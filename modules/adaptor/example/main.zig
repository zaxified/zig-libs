// SPDX-License-Identifier: MIT

//! What a PTLC (point-time-locked contract) leg does with `adaptor`: the
//! presigner produces a pre-signature bound to a public adaptor point `T`
//! without knowing its discrete log `t`, anyone can `preVerify` it, and once
//! `t` becomes known `adapt` completes it into an ordinary signature that a
//! plain BIP340 verifier accepts with zero awareness an adaptor scheme was
//! involved — and finally `extract` recovers `t` from the pre-signature and
//! the completed signature, the scheme's deliberate one-time key-leaking
//! property.
//!
//! ## External oracle: there isn't a runnable one, and SPEC.md says so
//!
//! `SPEC.md` ("Anchoring") is explicit: no BIP or formal spec exists for
//! Schnorr adaptor signatures, and "no schnorr adaptor vectors exist;
//! DLC's ECDSA-adaptor.json is a different scheme". `interop_vectors.zig`
//! inside the module does carry frozen bytes captured from a third-party
//! implementation (LLFourn/secp256kfun's `schnorr_fun::adaptor`, 0BSD), but
//! that is a byte fixture reachable only from INSIDE the module (`src/`,
//! not `deps`) — an example, which may only import the published module
//! surface, cannot call a Rust binary and has no independent adaptor-sig
//! implementation to run on this machine either.
//!
//! What SPEC.md names instead as "the STRONGEST available oracle for the
//! adapt/preVerify half, in the total absence of any official adaptor-sig
//! test vectors" is `bip340.verify` itself: `adapt`'s headline property is
//! that its 64-byte output is BYTE-IDENTICAL to what `bip340.sign` would
//! have produced outright, and `bip340` is byte-exact against all 19
//! official BIP340 test vectors. So this example's real external check is
//! that a plain `bip340.verify` call — a sibling module with its own
//! independent byte-exact anchor — accepts the adapted signature, plus the
//! algebraic round trip SPEC.md also names: `extract` on a pre-signature
//! and its adapted signature must return the EXACT original adaptor secret.
//!
//! `adaptor` allocates nothing and keeps no state (every value here is a
//! fixed-size array), so there is no DebugAllocator to wrap — same shape as
//! `modules/ct25519/example/main.zig` / `modules/l2disco/example/main.zig`.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const bip340 = @import("bip340");
const adaptor = @import("adaptor");

fn hexToBytes32(comptime hex: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// All secret material below is arbitrary and generated only for this
// example (`python3 -c "import secrets; print(secrets.token_hex(32))"`,
// run offline) — never a real key.
const sk_bytes = hexToBytes32("a92bcc87ae699844fd920ac9de424ea60113475ef7277aae6786354a2fbaf6c0");
const t_bytes = hexToBytes32("8b7498a7b05ba9b6dd8f330c75a68d93b369192252eaf7e696367a24fb077aee");
const wrong_t_bytes = hexToBytes32("98f4f7cfc0052f2e084af9b394c44208d27fe767a9cef15e0da9dc5871ade42b");
const aux_rand = hexToBytes32("1cde0c35e9ed6f4ab7f163cfb0a4741f5d86db6db45ac263adb0d8bfa112ffb1");
const msg = hexToBytes32("26d98dcaca1c286da9fa4c038c4d1d673460730780a32886764c1edabbdbec1e");

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const secret_key = try bip340.SecretKey.fromBytes(sk_bytes);
    const kp = try bip340.KeyPair.fromSecretKey(secret_key);

    // T = t*G — the public adaptor point the presigner binds to, without
    // ever learning t itself.
    const adaptor_point = try adaptor.AdaptorPoint.fromSecret(t_bytes);

    // ── PreSign: produce a pre-signature bound to T, no knowledge of t ────
    const presig = try adaptor.preSign(secret_key, &msg, aux_rand, adaptor_point, io);
    std.debug.print("preSign: pre-signature produced, needs_negation={}\n", .{presig.needs_negation});

    // ── PreVerify: anyone can check it, still without knowing t ──────────
    if (!adaptor.preVerify(kp.public, &msg, adaptor_point, presig)) return error.PreVerifyFailed;
    std.debug.print("preVerify: accepted\n", .{});

    // ── Adapt: whoever learns t completes it into a PLAIN BIP340 sig ─────
    const full_sig_bytes = try adaptor.adapt(presig, t_bytes);
    const full_sig = try bip340.Signature.fromBytes(full_sig_bytes);

    // External oracle: a completely ordinary bip340.verify call — the
    // sibling module's own byte-exact-anchored verifier, with zero
    // awareness an adaptor scheme produced this signature.
    if (!bip340.verify(kp.public, &msg, full_sig)) return error.AdaptedSignatureRejectedByBip340;
    std.debug.print("adapt -> bip340.verify: accepted (adapted sig is an ordinary BIP340 signature)\n", .{});

    // ── Extract: recover t from (presig, full_sig) — byte-exact ──────────
    const recovered = try adaptor.extract(presig, full_sig, adaptor_point);
    if (!std.mem.eql(u8, &recovered, &t_bytes)) return error.ExtractedWrongSecret;
    std.debug.print("extract: recovered the exact original adaptor secret\n", .{});

    // ── Negative case: extracting against the WRONG adaptor point must
    //    fail by NAME, not silently return a bogus scalar ────────────────
    const wrong_point = try adaptor.AdaptorPoint.fromSecret(wrong_t_bytes);
    if (adaptor.extract(presig, full_sig, wrong_point)) |_| {
        return error.UnexpectedExtractSuccess;
    } else |err| switch (err) {
        error.AdaptorSecretMismatch => std.debug.print("extract against the wrong adaptor point: AdaptorSecretMismatch (expected)\n", .{}),
        else => return err,
    }
}
