// SPDX-License-Identifier: MIT
//! RFC 9497 OPRF / VOPRF / POPRF, generic over the ciphersuite.
//!
//! `Protocol(G)` is the whole functional layer of RFC 9497 §2-§3 for one
//! group backend `G` (`groups.zig`). `root.zig` instantiates it once per §4
//! ciphersuite and re-exports the ristretto255-SHA512 instance at top level
//! (the module's original, source-compatible API). See `root.zig`'s module
//! doc comment for the security notes; every secret-scalar multiply here is
//! `G.mulSecret`/`G.mulBaseSecret`, every wire-scalar multiply
//! `G.mulPublic`/`G.mulBasePublic`.

const std = @import("std");
const burn = @import("burn.zig");

/// The three protocol variants (RFC 9497 §3.1 Table 1). The enum value
/// is the exact one-byte mode identifier used in `contextString`.
pub const Mode = enum(u8) {
    oprf = 0x00,
    voprf = 0x01,
    poprf = 0x02,
};

pub const InvalidInputError = error{InvalidInput};
pub const DeserializeElementError = error{InvalidElement};
pub const DeserializeScalarError = error{InvalidScalar};
/// RFC 9497 bounds every `input` and `info` at `2^16 - 1` bytes (they are
/// framed with a two-byte length); a longer slice is `error.InputTooLong`.
pub const max_input_length = 0xffff;
pub const InputTooLongError = error{InputTooLong};

fn checkLen(n: usize) InputTooLongError!void {
    if (n > max_input_length) return error.InputTooLong;
}

pub const DeriveKeyPairError = error{ DeriveKeyPairFailed, InputTooLong };
pub const GenerateProofError = error{ProofGenerationFailed};
pub const VerifyProofError = error{InvalidProof};
pub const BlindError = error{ InvalidInput, InputTooLong };
pub const FinalizeError = error{ InvalidBlind, InputTooLong };
pub const EvaluateError = error{ InvalidInput, InputTooLong };
pub const BlindEvaluateVerifiableError = error{
    ProofGenerationFailed,
    /// `blinded.len == 0`: an empty batch has no well-defined proof.
    EmptyBatch,
    /// `evaluated_out.len != blinded.len` (independent caller slices).
    MismatchedLengths,
};
pub const BlindEvaluateBatchError = error{MismatchedLengths};
pub const FinalizeVerifiableError = error{ InvalidBlind, InvalidProof, InputTooLong };
pub const FinalizeBatchError = error{ InvalidBlind, InvalidProof, EmptyBatch, MismatchedLengths, InputTooLong };
pub const PoprfEvaluateError = error{
    InverseError,
    InputTooLong,
    ProofGenerationFailed,
    EmptyBatch,
    MismatchedLengths,
};
pub const PoprfDirectEvaluateError = error{ InvalidInput, InverseError, InputTooLong };

const CompositesError = error{DegenerateComposite};

pub fn Protocol(comptime G: type) type {
    return struct {
        const Self = @This();

        /// The group backend (`groups.zig`).
        pub const Group = G;
        /// RFC 9497 §4's ciphersuite identifier string.
        pub const identifier = G.identifier;
        /// `Ne`: encoded length of a group `Element`.
        pub const Ne: usize = G.Ne;
        /// `Ns`: encoded length of a `Scalar`.
        pub const Ns: usize = G.Ns;
        /// `Nh`: output length of the ciphersuite hash.
        pub const Nh: usize = G.Nh;
        /// Bytes `scalarFromWideBytes` reduces (the suite's `HashToScalar`
        /// width: 64 for ristretto255/decaf448, `L` = 48/72/98 for P-256/
        /// P-384/P-521).
        pub const wide_length: usize = G.Lw;

        const wide_burn = burn.wide_burn * G.burn_scale;
        const derive_burn = burn.derive_burn * G.burn_scale;
        const mul_burn = burn.mul_burn * G.burn_scale;
        const proof_burn = burn.proof_burn * G.burn_scale;

        /// RFC 9497 §3.1 `CreateContextString(mode, identifier)`:
        /// `"OPRFV1-" || I2OSP(mode, 1) || "-" || identifier`.
        pub fn contextString(comptime mode: Mode) []const u8 {
            return "OPRFV1-" ++ [1]u8{@backingInt(mode)} ++ "-" ++ identifier;
        }

        // ── types ────────────────────────────────────────────────────

        /// A validated non-identity group element (RFC 9497 §2.1).
        pub const Element = struct {
            p: G.Point,

            pub const encoded_length = Ne;

            /// §2.1 `Generator()`.
            pub const generator = Element{ .p = G.base };

            /// §4 `DeserializeElement`: canonical decoding + identity rejection.
            pub fn fromBytes(bytes: [Ne]u8) DeserializeElementError!Element {
                return .{ .p = try G.decode(bytes) };
            }

            /// §4 `SerializeElement`.
            pub fn toBytes(e: Element) [Ne]u8 {
                return G.encode(e.p);
            }
        };

        /// §4 `DeserializeScalar`: canonical scalars only; returns the bytes.
        pub fn deserializeScalar(bytes: [Ns]u8) DeserializeScalarError![Ns]u8 {
            try G.sCanonical(bytes);
            return bytes;
        }

        /// RFC 9497 §4.7.2 random scalar from `wide_length` uniform bytes
        /// (reduced mod the group order). Secret in by pointer, secret out
        /// through `out`; stack burned.
        pub fn scalarFromWideBytes(wide: *const [G.Lw]u8, out: *[Ns]u8) void {
            burn.run(wide_burn, void, wideBody, .{ wide, out });
        }

        fn wideBody(wide: *const [G.Lw]u8, out: *[Ns]u8) void {
            out.* = G.reduceWide(wide);
        }

        /// A DLEQ proof (RFC 9497 §2.2): `c || s`.
        pub const Proof = struct {
            c: [Ns]u8,
            s: [Ns]u8,

            pub const encoded_length = 2 * Ns;

            pub fn toBytes(proof: Proof) [encoded_length]u8 {
                return proof.c ++ proof.s;
            }

            pub fn fromBytes(bytes: [encoded_length]u8) DeserializeScalarError!Proof {
                return .{
                    .c = try deserializeScalar(bytes[0..Ns].*),
                    .s = try deserializeScalar(bytes[Ns..].*),
                };
            }
        };

        /// A server key pair (RFC 9497 §3.2).
        pub const KeyPair = struct {
            sk: [Ns]u8,
            pk: Element,
        };

        // ── hash layer ───────────────────────────────────────────────

        /// RFC 9497 §4 `HashToGroup(x)` with `DST = "HashToGroup-" ||
        /// contextString`; an identity result is §3.3.1's InvalidInputError.
        pub fn hashToGroup(comptime mode: Mode, input: []const u8) InvalidInputError!Element {
            const p = G.hashToGroup(&.{input}, "HashToGroup-" ++ comptime contextString(mode));
            if (G.isIdentity(p)) return error.InvalidInput;
            return .{ .p = p };
        }

        /// RFC 9497 §4 `HashToScalar(x)` with `DST = "HashToScalar-" ||
        /// contextString`; `msg_parts` are concatenated in order.
        pub fn hashToScalar(comptime mode: Mode, msg_parts: []const []const u8) [Ns]u8 {
            return G.hashToScalar(msg_parts, "HashToScalar-" ++ comptime contextString(mode));
        }

        // ── key generation (§3.2.1) ──────────────────────────────────

        /// RFC 9497 §3.2.1 `DeriveKeyPair(seed, info)`. Output through `out`
        /// (written only on success); stack burned.
        pub fn deriveKeyPair(comptime mode: Mode, seed: *const [32]u8, info: []const u8, out: *KeyPair) DeriveKeyPairError!void {
            try checkLen(info.len);
            return burn.run(derive_burn, DeriveKeyPairError!void, DeriveBody(mode).f, .{ seed, info, out });
        }

        fn DeriveBody(comptime mode: Mode) type {
            return struct {
                fn f(seed: *const [32]u8, info: []const u8, out: *KeyPair) DeriveKeyPairError!void {
                    std.debug.assert(info.len <= 0xffff);
                    const dst = "DeriveKeyPair" ++ comptime contextString(mode);
                    var info_len: [2]u8 = undefined;
                    std.mem.writeInt(u16, &info_len, @intCast(info.len), .big);
                    var counter: u16 = 0;
                    while (counter <= 255) : (counter += 1) {
                        const counter_byte = [1]u8{@intCast(counter)};
                        const sk = G.hashToScalar(&.{ seed, &info_len, info, &counter_byte }, dst);
                        // The RFC's own loop condition, on a constant-time compare.
                        if (std.crypto.timing_safe.eql([Ns]u8, sk, @as([Ns]u8, @splat(0)))) continue;
                        out.* = .{ .sk = sk, .pk = .{ .p = G.mulBaseSecret(&sk) } };
                        return;
                    }
                    return error.DeriveKeyPairFailed;
                }
            };
        }

        // ── DLEQ proofs (§2.2) ───────────────────────────────────────

        const Composites = struct {
            m: Element,
            z: Element,
        };

        fn compositesSeed(comptime mode: Mode, b: Element) [Nh]u8 {
            const seed_dst = "Seed-" ++ comptime contextString(mode);
            const bm = b.toBytes();
            return G.hash(&.{ &.{ 0, Ne }, &bm, &.{ 0, seed_dst.len }, seed_dst });
        }

        fn compositeScalar(comptime mode: Mode, seed: *const [Nh]u8, i: u16, c_i: Element, d_i: Element) [Ns]u8 {
            var i_bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &i_bytes, i, .big);
            const ci = c_i.toBytes();
            const di = d_i.toBytes();
            return hashToScalar(mode, &.{
                &.{ 0, Nh }, seed,
                &i_bytes,    &.{ 0, Ne },
                &ci,         &.{ 0, Ne },
                &di,         "Composite",
            });
        }

        /// §2.2.1 `ComputeCompositesFast` (server, secret `k`).
        fn computeCompositesFast(
            comptime mode: Mode,
            k: [Ns]u8,
            b: Element,
            c_list: []const Element,
            d_list: []const Element,
        ) CompositesError!Composites {
            std.debug.assert(c_list.len >= 1 and c_list.len == d_list.len);
            const seed = compositesSeed(mode, b);
            var m_acc: G.Point = undefined;
            for (c_list, d_list, 0..) |c_i, d_i, i| {
                const d_scalar = compositeScalar(mode, &seed, @intCast(i), c_i, d_i);
                // `di` is a hash of wire elements: public.
                const term = G.mulPublic(c_i.p, d_scalar) catch return error.DegenerateComposite;
                m_acc = if (i == 0) term else G.add(m_acc, term);
            }
            const z = G.mulSecret(m_acc, &k); // SECRET k
            return .{ .m = .{ .p = m_acc }, .z = .{ .p = z } };
        }

        /// §2.2.2 `ComputeComposites` (verifier, public only).
        fn computeComposites(
            comptime mode: Mode,
            b: Element,
            c_list: []const Element,
            d_list: []const Element,
        ) CompositesError!Composites {
            std.debug.assert(c_list.len >= 1 and c_list.len == d_list.len);
            const seed = compositesSeed(mode, b);
            var m_acc: G.Point = undefined;
            var z_acc: G.Point = undefined;
            for (c_list, d_list, 0..) |c_i, d_i, i| {
                const d_scalar = compositeScalar(mode, &seed, @intCast(i), c_i, d_i);
                const m_term = G.mulPublic(c_i.p, d_scalar) catch return error.DegenerateComposite;
                const z_term = G.mulPublic(d_i.p, d_scalar) catch return error.DegenerateComposite;
                if (i == 0) {
                    m_acc = m_term;
                    z_acc = z_term;
                } else {
                    m_acc = G.add(m_acc, m_term);
                    z_acc = G.add(z_acc, z_term);
                }
            }
            return .{ .m = .{ .p = m_acc }, .z = .{ .p = z_acc } };
        }

        fn challengeScalar(comptime mode: Mode, b: Element, m: Element, z: Element, t2: Element, t3: Element) [Ns]u8 {
            const bm = b.toBytes();
            const a0 = m.toBytes();
            const a1 = z.toBytes();
            const a2 = t2.toBytes();
            const a3 = t3.toBytes();
            const len_prefix = [2]u8{ 0, Ne };
            return hashToScalar(mode, &.{
                &len_prefix, &bm,
                &len_prefix, &a0,
                &len_prefix, &a1,
                &len_prefix, &a2,
                &len_prefix, &a3,
                "Challenge",
            });
        }

        /// RFC 9497 §2.2.1 `GenerateProof(k, A, B, C, D)` with caller-supplied
        /// proof randomness `r` (fresh and uniformly random per proof).
        pub fn generateProof(
            comptime mode: Mode,
            k: *const [Ns]u8,
            a: Element,
            b: Element,
            c_list: []const Element,
            d_list: []const Element,
            r: *const [Ns]u8,
        ) GenerateProofError!Proof {
            return burn.run(proof_burn, GenerateProofError!Proof, GenerateProofBody(mode).f, .{ k, a, b, c_list, d_list, r });
        }

        fn GenerateProofBody(comptime mode: Mode) type {
            return struct {
                fn f(
                    k_ptr: *const [Ns]u8,
                    a: Element,
                    b: Element,
                    c_list: []const Element,
                    d_list: []const Element,
                    r_ptr: *const [Ns]u8,
                ) GenerateProofError!Proof {
                    if (c_list.len == 0 or c_list.len != d_list.len) return error.ProofGenerationFailed;
                    return generateProofImpl(mode, k_ptr.*, a, b, c_list, d_list, r_ptr.*);
                }
            };
        }

        fn generateProofImpl(
            comptime mode: Mode,
            k: [Ns]u8,
            a: Element,
            b: Element,
            c_list: []const Element,
            d_list: []const Element,
            r: [Ns]u8,
        ) GenerateProofError!Proof {
            const comp = computeCompositesFast(mode, k, b, c_list, d_list) catch
                return error.ProofGenerationFailed;
            // SECRET nonce: `s = r - c*k` reveals `k` to anyone who learns `r`.
            const t2 = G.mulSecret(a.p, &r);
            const t3 = G.mulSecret(comp.m.p, &r);
            const c = challengeScalar(mode, b, comp.m, comp.z, .{ .p = t2 }, .{ .p = t3 });
            const s = G.sSub(r, G.sMul(c, k));
            return .{ .c = c, .s = s };
        }

        /// RFC 9497 §2.2.2 `VerifyProof(A, B, C, D, proof)`. Fails closed.
        pub fn verifyProof(
            comptime mode: Mode,
            a: Element,
            b: Element,
            c_list: []const Element,
            d_list: []const Element,
            proof: Proof,
        ) VerifyProofError!void {
            if (c_list.len == 0 or c_list.len != d_list.len) return error.InvalidProof;
            _ = deserializeScalar(proof.c) catch return error.InvalidProof;
            _ = deserializeScalar(proof.s) catch return error.InvalidProof;
            const comp = computeComposites(mode, b, c_list, d_list) catch return error.InvalidProof;
            const s_a = G.mulPublic(a.p, proof.s) catch return error.InvalidProof;
            const c_b = G.mulPublic(b.p, proof.c) catch return error.InvalidProof;
            const t2 = G.add(s_a, c_b);
            const s_m = G.mulPublic(comp.m.p, proof.s) catch return error.InvalidProof;
            const c_z = G.mulPublic(comp.z.p, proof.c) catch return error.InvalidProof;
            const t3 = G.add(s_m, c_z);
            const expected_c = challengeScalar(mode, b, comp.m, comp.z, .{ .p = t2 }, .{ .p = t3 });
            if (!std.crypto.timing_safe.eql([Ns]u8, expected_c, proof.c)) return error.InvalidProof;
        }

        // ── shared Finalize hash (§3.3.1/§3.3.3) ─────────────────────

        fn finalizeHash(input: []const u8, info: ?[]const u8, unblinded: [Ne]u8) [Nh]u8 {
            std.debug.assert(input.len <= 0xffff);
            var input_len: [2]u8 = undefined;
            std.mem.writeInt(u16, &input_len, @intCast(input.len), .big);
            if (info) |inf| {
                std.debug.assert(inf.len <= 0xffff);
                var info_len: [2]u8 = undefined;
                std.mem.writeInt(u16, &info_len, @intCast(inf.len), .big);
                return G.hash(&.{ &input_len, input, &info_len, inf, &.{ 0, Ne }, &unblinded, "Finalize" });
            }
            return G.hash(&.{ &input_len, input, &.{ 0, Ne }, &unblinded, "Finalize" });
        }

        /// `ScalarInverse(blind) * evaluatedElement`; refuses a non-canonical
        /// or zero blind.
        fn unblind(blind_scalar: [Ns]u8, evaluated_element: Element) FinalizeError![Ne]u8 {
            _ = deserializeScalar(blind_scalar) catch return error.InvalidBlind;
            if (std.crypto.timing_safe.eql([Ns]u8, blind_scalar, @as([Ns]u8, @splat(0)))) return error.InvalidBlind;
            const inv = G.sInvert(blind_scalar);
            return G.encode(G.mulSecret(evaluated_element.p, &inv));
        }

        // ── OPRF mode (§3.3.1) ───────────────────────────────────────

        /// RFC 9497 §3.3.1 `Blind(input)` with caller-supplied blind scalar.
        pub fn blind(comptime mode: Mode, input: []const u8, blind_scalar: *const [Ns]u8) BlindError!Element {
            try checkLen(input.len);
            return burn.run(mul_burn, BlindError!Element, BlindBody(mode).f, .{ input, blind_scalar });
        }

        fn BlindBody(comptime mode: Mode) type {
            return struct {
                fn f(input: []const u8, blind_scalar: *const [Ns]u8) BlindError!Element {
                    const input_element = try hashToGroup(mode, input);
                    return .{ .p = G.mulSecret(input_element.p, blind_scalar) };
                }
            };
        }

        /// RFC 9497 §3.3.1 `BlindEvaluate(skS, blindedElement)`.
        pub fn blindEvaluate(sk: *const [Ns]u8, blinded_element: Element) Element {
            return burn.run(mul_burn, Element, blindEvaluateBody, .{ sk, blinded_element });
        }

        fn blindEvaluateBody(sk: *const [Ns]u8, blinded_element: Element) Element {
            return .{ .p = G.mulSecret(blinded_element.p, sk) };
        }

        /// Batched OPRF-mode `BlindEvaluate`: `evaluated_out[i] = skS *
        /// blinded[i]` (no proof in this mode). An empty batch is a no-op.
        pub fn blindEvaluateBatch(sk: *const [Ns]u8, blinded: []const Element, evaluated_out: []Element) BlindEvaluateBatchError!void {
            if (evaluated_out.len != blinded.len) return error.MismatchedLengths;
            return burn.run(mul_burn, void, blindEvaluateBatchBody, .{ sk, blinded, evaluated_out });
        }

        fn blindEvaluateBatchBody(sk: *const [Ns]u8, blinded: []const Element, evaluated_out: []Element) void {
            for (blinded, evaluated_out) |b, *o| o.* = blindEvaluateBody(sk, b);
        }

        /// RFC 9497 §3.3.1 `Finalize(input, blind, evaluatedElement)`.
        pub fn finalize(input: []const u8, blind_scalar: *const [Ns]u8, evaluated_element: Element, out: *[Nh]u8) FinalizeError!void {
            try checkLen(input.len);
            return burn.run(mul_burn, FinalizeError!void, finalizeBody, .{ input, blind_scalar, evaluated_element, out });
        }

        fn finalizeBody(input: []const u8, blind_scalar: *const [Ns]u8, evaluated_element: Element, out: *[Nh]u8) FinalizeError!void {
            const unblinded = try unblind(blind_scalar.*, evaluated_element);
            out.* = finalizeHash(input, null, unblinded);
        }

        /// RFC 9497 §3.3.1 `Evaluate(skS, input)` — the direct PRF.
        pub fn evaluate(comptime mode: Mode, sk: *const [Ns]u8, input: []const u8, out: *[Nh]u8) EvaluateError!void {
            try checkLen(input.len);
            return burn.run(mul_burn, EvaluateError!void, EvaluateBody(mode).f, .{ sk, input, out });
        }

        fn EvaluateBody(comptime mode: Mode) type {
            return struct {
                fn f(sk: *const [Ns]u8, input: []const u8, out: *[Nh]u8) EvaluateError!void {
                    const input_element = try hashToGroup(mode, input);
                    const evaluated = G.mulSecret(input_element.p, sk);
                    out.* = finalizeHash(input, null, G.encode(evaluated));
                }
            };
        }

        // ── VOPRF mode (§3.3.2) ──────────────────────────────────────

        pub const VerifiableEvaluation = struct {
            evaluated_element: Element,
            proof: Proof,
        };

        /// RFC 9497 §3.3.2 `BlindEvaluate(skS, pkS, blindedElement)`.
        pub fn blindEvaluateVerifiable(
            sk: *const [Ns]u8,
            pk: Element,
            blinded_element: Element,
            proof_r: *const [Ns]u8,
        ) BlindEvaluateVerifiableError!VerifiableEvaluation {
            var evaluated: [1]Element = undefined;
            const proof = try blindEvaluateVerifiableBatch(sk, pk, &.{blinded_element}, &evaluated, proof_r);
            return .{ .evaluated_element = evaluated[0], .proof = proof };
        }

        /// Batched §3.3.2 `BlindEvaluate`: one constant-size proof for the batch.
        pub fn blindEvaluateVerifiableBatch(
            sk: *const [Ns]u8,
            pk: Element,
            blinded: []const Element,
            evaluated_out: []Element,
            proof_r: *const [Ns]u8,
        ) BlindEvaluateVerifiableError!Proof {
            return burn.run(proof_burn, BlindEvaluateVerifiableError!Proof, blindEvaluateVerifiableBatchBody, .{ sk, pk, blinded, evaluated_out, proof_r });
        }

        fn blindEvaluateVerifiableBatchBody(
            sk: *const [Ns]u8,
            pk: Element,
            blinded: []const Element,
            evaluated_out: []Element,
            proof_r: *const [Ns]u8,
        ) BlindEvaluateVerifiableError!Proof {
            if (blinded.len == 0) return error.EmptyBatch;
            if (evaluated_out.len != blinded.len) return error.MismatchedLengths;
            for (blinded, evaluated_out) |blinded_element, *out| {
                out.* = blindEvaluateBody(sk, blinded_element);
            }
            return generateProofImpl(.voprf, sk.*, Element.generator, pk, blinded, evaluated_out, proof_r.*);
        }

        /// RFC 9497 §3.3.2 `Finalize(...)`: verifies the proof FIRST.
        pub fn finalizeVerifiable(
            input: []const u8,
            blind_scalar: *const [Ns]u8,
            evaluated_element: Element,
            blinded_element: Element,
            pk: Element,
            proof: Proof,
            out: *[Nh]u8,
        ) FinalizeVerifiableError!void {
            try checkLen(input.len);
            return burn.run(proof_burn, FinalizeVerifiableError!void, finalizeVerifiableBody, .{ input, blind_scalar, evaluated_element, blinded_element, pk, proof, out });
        }

        fn finalizeVerifiableBody(
            input: []const u8,
            blind_scalar: *const [Ns]u8,
            evaluated_element: Element,
            blinded_element: Element,
            pk: Element,
            proof: Proof,
            out: *[Nh]u8,
        ) FinalizeVerifiableError!void {
            try verifyProof(.voprf, Element.generator, pk, &.{blinded_element}, &.{evaluated_element}, proof);
            try finalizeBody(input, blind_scalar, evaluated_element, out);
        }

        /// Batched §3.3.2 `Finalize`: verifies the ONE batch proof, then
        /// unblinds and hashes every element into `outputs` (all slices the
        /// same non-zero length). Nothing is written unless the proof
        /// verifies; on a later `InvalidBlind` the outputs before it are
        /// written and the rest are left untouched.
        pub fn finalizeVerifiableBatch(
            inputs: []const []const u8,
            blinds: []const [Ns]u8,
            evaluated: []const Element,
            blinded: []const Element,
            pk: Element,
            proof: Proof,
            outputs: [][Nh]u8,
        ) FinalizeBatchError!void {
            for (inputs) |input| try checkLen(input.len);
            return burn.run(proof_burn, FinalizeBatchError!void, finalizeVerifiableBatchBody, .{ inputs, blinds, evaluated, blinded, pk, proof, outputs });
        }

        fn finalizeVerifiableBatchBody(
            inputs: []const []const u8,
            blinds: []const [Ns]u8,
            evaluated: []const Element,
            blinded: []const Element,
            pk: Element,
            proof: Proof,
            outputs: [][Nh]u8,
        ) FinalizeBatchError!void {
            try checkBatch(inputs.len, blinds.len, evaluated.len, blinded.len, outputs.len);
            try verifyProof(.voprf, Element.generator, pk, blinded, evaluated, proof);
            for (inputs, blinds, evaluated, outputs) |input, *b, e, *o| try finalizeBody(input, b, e, o);
        }

        fn checkBatch(a: usize, b: usize, c: usize, d: usize, e: usize) error{ EmptyBatch, MismatchedLengths }!void {
            if (a == 0) return error.EmptyBatch;
            if (b != a or c != a or d != a or e != a) return error.MismatchedLengths;
        }

        // ── POPRF mode (§3.3.3) ──────────────────────────────────────

        /// §3.3.3's framed-info scalar `m = HashToScalar("Info" ||
        /// I2OSP(len(info), 2) || info)` (public: a hash of public `info`).
        pub fn poprfInfoScalar(info: []const u8) InputTooLongError![Ns]u8 {
            try checkLen(info.len);
            return infoScalar(info);
        }

        /// `poprfInfoScalar` for a length the entry point already checked.
        fn infoScalar(info: []const u8) [Ns]u8 {
            std.debug.assert(info.len <= max_input_length);
            var info_len: [2]u8 = undefined;
            std.mem.writeInt(u16, &info_len, @intCast(info.len), .big);
            return hashToScalar(.poprf, &.{ "Info", &info_len, info });
        }

        pub const PoprfBlindResult = struct {
            blinded_element: Element,
            tweaked_key: Element,
        };

        /// RFC 9497 §3.3.3 `Blind(input, info, pkS)`.
        pub fn blindPoprf(
            input: []const u8,
            info: []const u8,
            pk: Element,
            blind_scalar: *const [Ns]u8,
        ) BlindError!PoprfBlindResult {
            try checkLen(input.len);
            try checkLen(info.len);
            return burn.run(mul_burn, BlindError!PoprfBlindResult, blindPoprfBody, .{ input, info, pk, blind_scalar });
        }

        fn blindPoprfBody(
            input: []const u8,
            info: []const u8,
            pk: Element,
            blind_scalar: *const [Ns]u8,
        ) BlindError!PoprfBlindResult {
            const m = infoScalar(info);
            const t_point = G.mulBasePublic(m) catch return error.InvalidInput;
            const tweaked = G.add(t_point, pk.p);
            if (G.isIdentity(tweaked)) return error.InvalidInput;
            const blinded = try BlindBody(.poprf).f(input, blind_scalar);
            return .{ .blinded_element = blinded, .tweaked_key = .{ .p = tweaked } };
        }

        /// Batched §3.3.3 `BlindEvaluate` (composite lists SWAPPED vs VOPRF).
        pub fn blindEvaluatePoprfBatch(
            sk: *const [Ns]u8,
            blinded: []const Element,
            info: []const u8,
            evaluated_out: []Element,
            proof_r: *const [Ns]u8,
        ) PoprfEvaluateError!Proof {
            try checkLen(info.len);
            return burn.run(proof_burn, PoprfEvaluateError!Proof, blindEvaluatePoprfBatchBody, .{ sk, blinded, info, evaluated_out, proof_r });
        }

        fn blindEvaluatePoprfBatchBody(
            sk: *const [Ns]u8,
            blinded: []const Element,
            info: []const u8,
            evaluated_out: []Element,
            proof_r: *const [Ns]u8,
        ) PoprfEvaluateError!Proof {
            if (blinded.len == 0) return error.EmptyBatch;
            if (evaluated_out.len != blinded.len) return error.MismatchedLengths;
            const m = infoScalar(info);
            const t = G.sAdd(sk.*, m);
            if (std.crypto.timing_safe.eql([Ns]u8, t, @as([Ns]u8, @splat(0)))) return error.InverseError;
            const t_inv = G.sInvert(t);
            for (blinded, evaluated_out) |blinded_element, *out| {
                out.* = .{ .p = G.mulSecret(blinded_element.p, &t_inv) };
            }
            const tweaked = G.mulBaseSecret(&t);
            return generateProofImpl(.poprf, t, Element.generator, .{ .p = tweaked }, evaluated_out, blinded, proof_r.*) catch
                return error.ProofGenerationFailed;
        }

        /// Single-element §3.3.3 `BlindEvaluate`.
        pub fn blindEvaluatePoprf(
            sk: *const [Ns]u8,
            blinded_element: Element,
            info: []const u8,
            proof_r: *const [Ns]u8,
        ) PoprfEvaluateError!VerifiableEvaluation {
            var evaluated: [1]Element = undefined;
            const proof = try blindEvaluatePoprfBatch(sk, &.{blinded_element}, info, &evaluated, proof_r);
            return .{ .evaluated_element = evaluated[0], .proof = proof };
        }

        /// RFC 9497 §3.3.3 `Finalize(...)`: verifies against `tweakedKey` first.
        pub fn finalizePoprf(
            input: []const u8,
            blind_scalar: *const [Ns]u8,
            evaluated_element: Element,
            blinded_element: Element,
            proof: Proof,
            info: []const u8,
            tweaked_key: Element,
            out: *[Nh]u8,
        ) FinalizeVerifiableError!void {
            try checkLen(input.len);
            try checkLen(info.len);
            return burn.run(proof_burn, FinalizeVerifiableError!void, finalizePoprfBody, .{ input, blind_scalar, evaluated_element, blinded_element, proof, info, tweaked_key, out });
        }

        fn finalizePoprfBody(
            input: []const u8,
            blind_scalar: *const [Ns]u8,
            evaluated_element: Element,
            blinded_element: Element,
            proof: Proof,
            info: []const u8,
            tweaked_key: Element,
            out: *[Nh]u8,
        ) FinalizeVerifiableError!void {
            try verifyProof(.poprf, Element.generator, tweaked_key, &.{evaluated_element}, &.{blinded_element}, proof);
            try finalizePoprfUnverifiedBody(input, blind_scalar, evaluated_element, info, out);
        }

        /// Batched §3.3.3 `Finalize`: one proof verification against
        /// `tweakedKey`, then unblind + hash per element (same contract as
        /// `finalizeVerifiableBatch`).
        pub fn finalizePoprfBatch(
            inputs: []const []const u8,
            blinds: []const [Ns]u8,
            evaluated: []const Element,
            blinded: []const Element,
            proof: Proof,
            info: []const u8,
            tweaked_key: Element,
            outputs: [][Nh]u8,
        ) FinalizeBatchError!void {
            for (inputs) |input| try checkLen(input.len);
            try checkLen(info.len);
            return burn.run(proof_burn, FinalizeBatchError!void, finalizePoprfBatchBody, .{ inputs, blinds, evaluated, blinded, proof, info, tweaked_key, outputs });
        }

        fn finalizePoprfBatchBody(
            inputs: []const []const u8,
            blinds: []const [Ns]u8,
            evaluated: []const Element,
            blinded: []const Element,
            proof: Proof,
            info: []const u8,
            tweaked_key: Element,
            outputs: [][Nh]u8,
        ) FinalizeBatchError!void {
            try checkBatch(inputs.len, blinds.len, evaluated.len, blinded.len, outputs.len);
            try verifyProof(.poprf, Element.generator, tweaked_key, evaluated, blinded, proof);
            for (inputs, blinds, evaluated, outputs) |input, *b, e, *o| try finalizePoprfUnverifiedBody(input, b, e, info, o);
        }

        /// POPRF Finalize WITHOUT proof verification — only after a
        /// `verifyProof` over the whole batch.
        pub fn finalizePoprfUnverified(
            input: []const u8,
            blind_scalar: *const [Ns]u8,
            evaluated_element: Element,
            info: []const u8,
            out: *[Nh]u8,
        ) FinalizeError!void {
            try checkLen(input.len);
            try checkLen(info.len);
            return burn.run(mul_burn, FinalizeError!void, finalizePoprfUnverifiedBody, .{ input, blind_scalar, evaluated_element, info, out });
        }

        fn finalizePoprfUnverifiedBody(
            input: []const u8,
            blind_scalar: *const [Ns]u8,
            evaluated_element: Element,
            info: []const u8,
            out: *[Nh]u8,
        ) FinalizeError!void {
            const unblinded = try unblind(blind_scalar.*, evaluated_element);
            out.* = finalizeHash(input, info, unblinded);
        }

        /// RFC 9497 §3.3.3 `Evaluate(skS, input, info)` — the direct POPRF.
        pub fn evaluatePoprf(sk: *const [Ns]u8, input: []const u8, info: []const u8, out: *[Nh]u8) PoprfDirectEvaluateError!void {
            try checkLen(input.len);
            try checkLen(info.len);
            return burn.run(mul_burn, PoprfDirectEvaluateError!void, evaluatePoprfBody, .{ sk, input, info, out });
        }

        fn evaluatePoprfBody(sk: *const [Ns]u8, input: []const u8, info: []const u8, out: *[Nh]u8) PoprfDirectEvaluateError!void {
            const input_element = try hashToGroup(.poprf, input);
            const m = infoScalar(info);
            const t = G.sAdd(sk.*, m);
            if (std.crypto.timing_safe.eql([Ns]u8, t, @as([Ns]u8, @splat(0)))) return error.InverseError;
            const t_inv = G.sInvert(t);
            const evaluated = G.mulSecret(input_element.p, &t_inv);
            out.* = finalizeHash(input, info, G.encode(evaluated));
        }

        // ── §3.2/§3.3 context objects (the facebook/voprf / CIRCL shape) ──
        //
        // Thin state holders over the functions above, one per role and
        // mode, as facebook/voprf's `OprfClient`/`VoprfServer`/... and
        // CIRCL's `Client`/`Server` types: the client object keeps its blind
        // and blinded element between `blind` and `finalize`, the server
        // object its key pair. They add no protocol logic. They hold
        // SECRETS by value (the blind, the key), so the owner calls `wipe`
        // when done; no randomness is drawn here (caller-supplied, as
        // everywhere in this module).

        /// OPRF-mode client state (§3.3.1).
        pub const OprfClient = struct {
            blind_scalar: [Ns]u8,
            blinded_element: Element,

            pub fn blind(input: []const u8, blind_scalar: *const [Ns]u8) BlindError!OprfClient {
                return .{ .blind_scalar = blind_scalar.*, .blinded_element = try Self.blind(.oprf, input, blind_scalar) };
            }
            pub fn finalize(c: *const OprfClient, input: []const u8, evaluated_element: Element, out: *[Nh]u8) FinalizeError!void {
                return Self.finalize(input, &c.blind_scalar, evaluated_element, out);
            }
            pub fn wipe(c: *OprfClient) void {
                std.crypto.secureZero(u8, &c.blind_scalar);
            }
        };

        /// VOPRF-mode client state (§3.3.2): `finalize` verifies the proof
        /// against `pk` before unblinding.
        pub const VoprfClient = struct {
            blind_scalar: [Ns]u8,
            blinded_element: Element,

            pub fn blind(input: []const u8, blind_scalar: *const [Ns]u8) BlindError!VoprfClient {
                return .{ .blind_scalar = blind_scalar.*, .blinded_element = try Self.blind(.voprf, input, blind_scalar) };
            }
            pub fn finalize(c: *const VoprfClient, input: []const u8, evaluated_element: Element, proof: Proof, pk: Element, out: *[Nh]u8) FinalizeVerifiableError!void {
                return Self.finalizeVerifiable(input, &c.blind_scalar, evaluated_element, c.blinded_element, pk, proof, out);
            }
            pub fn wipe(c: *VoprfClient) void {
                std.crypto.secureZero(u8, &c.blind_scalar);
            }
        };

        /// POPRF-mode client state (§3.3.3): also keeps the tweaked key
        /// derived from `pk` and `info` at blinding time.
        pub const PoprfClient = struct {
            blind_scalar: [Ns]u8,
            blinded_element: Element,
            tweaked_key: Element,

            pub fn blind(input: []const u8, info: []const u8, pk: Element, blind_scalar: *const [Ns]u8) BlindError!PoprfClient {
                const r = try Self.blindPoprf(input, info, pk, blind_scalar);
                return .{ .blind_scalar = blind_scalar.*, .blinded_element = r.blinded_element, .tweaked_key = r.tweaked_key };
            }
            pub fn finalize(c: *const PoprfClient, input: []const u8, evaluated_element: Element, proof: Proof, info: []const u8, out: *[Nh]u8) FinalizeVerifiableError!void {
                return Self.finalizePoprf(input, &c.blind_scalar, evaluated_element, c.blinded_element, proof, info, c.tweaked_key, out);
            }
            pub fn wipe(c: *PoprfClient) void {
                std.crypto.secureZero(u8, &c.blind_scalar);
            }
        };

        /// OPRF-mode server (§3.3.1): holds `skS`.
        pub const OprfServer = struct {
            sk: [Ns]u8,

            /// §3.2.1 `DeriveKeyPair` in OPRF mode.
            pub fn derive(seed: *const [32]u8, info: []const u8) DeriveKeyPairError!OprfServer {
                var kp: KeyPair = undefined;
                defer std.crypto.secureZero(u8, &kp.sk);
                try deriveKeyPair(.oprf, seed, info, &kp);
                return .{ .sk = kp.sk };
            }
            pub fn blindEvaluate(s: *const OprfServer, blinded_element: Element) Element {
                return Self.blindEvaluate(&s.sk, blinded_element);
            }
            pub fn blindEvaluateBatch(s: *const OprfServer, blinded: []const Element, evaluated_out: []Element) BlindEvaluateBatchError!void {
                return Self.blindEvaluateBatch(&s.sk, blinded, evaluated_out);
            }
            pub fn evaluate(s: *const OprfServer, input: []const u8, out: *[Nh]u8) EvaluateError!void {
                return Self.evaluate(.oprf, &s.sk, input, out);
            }
            pub fn wipe(s: *OprfServer) void {
                std.crypto.secureZero(u8, &s.sk);
            }
        };

        /// VOPRF-mode server (§3.3.2): holds the key pair; `publicKey` is
        /// what clients verify against.
        pub const VoprfServer = struct {
            key_pair: KeyPair,

            pub fn derive(seed: *const [32]u8, info: []const u8) DeriveKeyPairError!VoprfServer {
                var s: VoprfServer = undefined;
                try deriveKeyPair(.voprf, seed, info, &s.key_pair);
                return s;
            }
            pub fn publicKey(s: *const VoprfServer) Element {
                return s.key_pair.pk;
            }
            pub fn blindEvaluate(s: *const VoprfServer, blinded_element: Element, proof_r: *const [Ns]u8) BlindEvaluateVerifiableError!VerifiableEvaluation {
                return Self.blindEvaluateVerifiable(&s.key_pair.sk, s.key_pair.pk, blinded_element, proof_r);
            }
            pub fn blindEvaluateBatch(s: *const VoprfServer, blinded: []const Element, evaluated_out: []Element, proof_r: *const [Ns]u8) BlindEvaluateVerifiableError!Proof {
                return Self.blindEvaluateVerifiableBatch(&s.key_pair.sk, s.key_pair.pk, blinded, evaluated_out, proof_r);
            }
            pub fn evaluate(s: *const VoprfServer, input: []const u8, out: *[Nh]u8) EvaluateError!void {
                return Self.evaluate(.voprf, &s.key_pair.sk, input, out);
            }
            pub fn wipe(s: *VoprfServer) void {
                std.crypto.secureZero(u8, &s.key_pair.sk);
            }
        };

        /// POPRF-mode server (§3.3.3).
        pub const PoprfServer = struct {
            key_pair: KeyPair,

            pub fn derive(seed: *const [32]u8, info: []const u8) DeriveKeyPairError!PoprfServer {
                var s: PoprfServer = undefined;
                try deriveKeyPair(.poprf, seed, info, &s.key_pair);
                return s;
            }
            pub fn publicKey(s: *const PoprfServer) Element {
                return s.key_pair.pk;
            }
            pub fn blindEvaluate(s: *const PoprfServer, blinded_element: Element, info: []const u8, proof_r: *const [Ns]u8) PoprfEvaluateError!VerifiableEvaluation {
                return Self.blindEvaluatePoprf(&s.key_pair.sk, blinded_element, info, proof_r);
            }
            pub fn blindEvaluateBatch(s: *const PoprfServer, blinded: []const Element, info: []const u8, evaluated_out: []Element, proof_r: *const [Ns]u8) PoprfEvaluateError!Proof {
                return Self.blindEvaluatePoprfBatch(&s.key_pair.sk, blinded, info, evaluated_out, proof_r);
            }
            pub fn evaluate(s: *const PoprfServer, input: []const u8, info: []const u8, out: *[Nh]u8) PoprfDirectEvaluateError!void {
                return Self.evaluatePoprf(&s.key_pair.sk, input, info, out);
            }
            pub fn wipe(s: *PoprfServer) void {
                std.crypto.secureZero(u8, &s.key_pair.sk);
            }
        };
    };
}
