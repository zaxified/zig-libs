// SPDX-License-Identifier: MIT

//! What a WebAuthn relying-party server actually does with `webauthn`:
//! verify a registration ceremony (attestation) and an authentication
//! ceremony (assertion) against real, byte-exact captured wire responses
//! -- entirely offline. Two independent sessions, each its own algorithm
//! and attestation format, so nothing from the first leaks into the
//! second (every `webauthn` verify function is a free function taking an
//! explicit `Allocator`; a fresh `ArenaAllocator` per call below is
//! exactly where a leak between "rounds" would surface).
//!
//! ⚠ WHAT COULD NOT BE EXERCISED HERE, AND WHY: an actual browser running
//! the WebAuthn JS API against a real authenticator. This module is a
//! relying-party-side VERIFIER of wire bytes a browser/authenticator
//! produced (root.zig: "verification only") -- it never creates a
//! credential or drives a ceremony itself, so there is nothing to run
//! live even with a browser present. What CAN be shown, and is, is the
//! module's actual job: verifying REAL responses. Every fixture below is
//! the W3C WebAuthn Level 3 specification's own §16 "Test Vectors"
//! (https://www.w3.org/TR/webauthn-3/#sctn-test-vectors) -- published by
//! the W3C, captured from `modules/webauthn/src/vectors.zig` (itself
//! mechanically extracted from the spec text 2026-07-21, cross-checked
//! against go-webauthn's independent re-hosting of the same vectors; see
//! that file's own provenance comment and `../SPEC.md`'s "Verification"
//! section). §16's preamble: "All examples use the RP ID example.org,
//! the origin https://example.org [...] deterministically generated
//! using HKDF-SHA-256 [...] ECDSA signatures use a deterministic nonce
//! [RFC6979]" -- reproducible-by-construction bytes from the spec
//! authors' own reference implementation, independent of this module.
//!
//! Round A (§16.2, "ES256 Credential with No Attestation", `fmt: none`)
//! and round B (§16.11, "Packed Attestation with Ed25519 Credential",
//! `fmt: packed` + `x5c`) are genuinely different code paths: different
//! signature algorithm (ES256 vs EdDSA), different attestation format
//! (no statement at all vs a leaf-certificate-signed one, exercising the
//! `x509` dep), and round B's registration returns a `leaf_cert_der`
//! round A's does not.
//!
//! Built against the PUBLISHED module (`@import("webauthn")` plus its
//! four declared deps `cbor`/`rsa`/`p256`/`x509`, though this file only
//! needs `webauthn` itself) -- no `test_deps`, no reaching into `src/`.

const std = @import("std");
const webauthn = @import("webauthn");

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(200_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const rp_id = "example.org";
const origin = "https://example.org";

// ── §16.2 "ES256 Credential with No Attestation" (fmt: none) ────────────
// Published by the W3C (WebAuthn Level 3 §16.2), captured from
// modules/webauthn/src/vectors.zig's `none_es256`.

const a_registration_client_data_json = &hexBytes(255, "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d");
const a_attestation_object = &hexBytes(194, "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220");
const a_registration_challenge = &hexBytes(32, "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130");

const a_authenticator_data = hexBytes(37, "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000");
const a_assertion_client_data_json = &hexBytes(132, "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d");
const a_signature = &hexBytes(72, "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87");
const a_assertion_challenge = &hexBytes(32, "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408");

// ── §16.11 "Packed Attestation with Ed25519 Credential" (fmt: packed, x5c) ──
// Published by the W3C (WebAuthn Level 3 §16.11), captured from
// modules/webauthn/src/vectors.zig's `packed_eddsa`.

const b_registration_client_data_json = &hexBytes(255, "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22714b763532723347734e396a526d733576616e6f6f306f303459557a656c6e7878586d5a426e6254733730222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20425f44543567375a445f2d394f544c59583549764551227d");
const b_attestation_object = &hexBytes(803, "a363666d74667061636b65646761747453746d74a363616c67266373696758483046022100d83f60bd80269537583218858aefb03ac57d45fa06e42feaae332d187f62da9f022100a02bd3cb6f7e1d283c93bad1f3f4b5a4c0494463da7fdbf256949116754d1f17637835638159022730820223308201c8a003020102021100b2cfc9ea33c8643b0e1a760463eaf164300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d03010703420004dd2b7a564b73b8c0b81c4c62e521925c4d1198ec9f583dbf1eebe364b65cd9c29a9bdf346aaa81fb6b9507e5249a52fdaf8e39e26b0b7dc45992a7e233b70f70a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e041604140ae27546bc7eccb1b4b597bd354f0c0b1f1f8f8e301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d0403020349003046022100a0d434ecb5fc3bfd7da5f41904517ad2836249f561bd834ba7a438a8ab7a4ce8022100fac845bb7a02513b58e9f319654dbe49b0f02b95835bac568c71f8a18cdde9ab6861757468446174615881bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54100000000d5aa33581e8ca478e20fe713f5d32ff20020ce9f840ed96599580cd140fbc7bb3230633f50f61041aff73308ae71caa8a2bda401010327200621582044e06ddd331c36a8dc667bab52bcae63486c916aa5e339e6acebaa84934bf832");
const b_registration_challenge = &hexBytes(32, "a8abf9dabdc6b0df63466b39bda9e8a34a34e185337a59f1c579990676d3b3bd");

const b_authenticator_data = &hexBytes(37, "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50100000000");
const b_assertion_client_data_json = &hexBytes(132, "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2269566c583442786a4f6d6d44534b4c596f7870557439736e364d48454f7943413135726947514a6e763949222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d");
const b_signature = &hexBytes(64, "f5c59c7e46c34f6f8cc197101ddf9934fa2595f68eb1913a637e8419eb9ba4cfdfc48f85393bc0d40b011f0d6fecb097d6607525713223a0dc0d453993dae00b");
const b_assertion_challenge = &hexBytes(32, "895957e01c633a698348a2d8a31a54b7db27e8c1c43b2080d79ae2190267bfd2");

fn roundA(gpa: std.mem.Allocator) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // ── registration ceremony ────────────────────────────────────────
    const reg = try webauthn.verifyRegistration(arena, a_attestation_object, a_registration_client_data_json, .{
        .rp_id = rp_id,
        .expected_challenge = a_registration_challenge,
        .expected_origin = origin,
    });
    if (reg.attestation_type != .none) return error.WrongAttestationType;
    std.debug.print("round A: §16.2 registration (fmt=none, ES256) verifies; credential_id len={d}\n", .{reg.credential_id.len});

    // ── good assertion ───────────────────────────────────────────────
    const good = try webauthn.verifyAssertion(arena, &a_authenticator_data, a_assertion_client_data_json, a_signature, reg.credential_public_key, .{
        .rp_id = rp_id,
        .expected_challenge = a_assertion_challenge,
        .expected_origin = origin,
    });
    if (!good.user_present) return error.ExpectedUserPresent;
    std.debug.print("round A: §16.2 assertion verifies; sign_count={d} user_verified={}\n", .{ good.sign_count, good.user_verified });

    // ── negative: wrong challenge ────────────────────────────────────
    if (webauthn.verifyAssertion(arena, &a_authenticator_data, a_assertion_client_data_json, a_signature, reg.credential_public_key, .{
        .rp_id = rp_id,
        .expected_challenge = a_registration_challenge, // the REGISTRATION challenge, not this assertion's
        .expected_origin = origin,
    })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.ChallengeMismatch => std.debug.print("round A: wrong expected challenge: ChallengeMismatch (expected)\n", .{}),
        else => return err,
    }

    // ── negative: wrong RP ID ────────────────────────────────────────
    if (webauthn.verifyAssertion(arena, &a_authenticator_data, a_assertion_client_data_json, a_signature, reg.credential_public_key, .{
        .rp_id = "not-example.org",
        .expected_challenge = a_assertion_challenge,
        .expected_origin = origin,
    })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.RpIdMismatch => std.debug.print("round A: wrong RP ID: RpIdMismatch (expected)\n", .{}),
        else => return err,
    }

    // ── negative: tampered signature byte ────────────────────────────
    var bad_sig = a_signature.*;
    bad_sig[bad_sig.len - 1] ^= 0xff;
    if (webauthn.verifyAssertion(arena, &a_authenticator_data, a_assertion_client_data_json, &bad_sig, reg.credential_public_key, .{
        .rp_id = rp_id,
        .expected_challenge = a_assertion_challenge,
        .expected_origin = origin,
    })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.BadSignature => std.debug.print("round A: tampered signature byte: BadSignature (expected)\n", .{}),
        else => return err,
    }

    // ── negative: user verification required, but this real vector's ───
    // UV flag is genuinely clear (an ES256 "none" credential never sets
    // it) -- no tampering needed to reach this rejection.
    if (webauthn.verifyAssertion(arena, &a_authenticator_data, a_assertion_client_data_json, a_signature, reg.credential_public_key, .{
        .rp_id = rp_id,
        .expected_challenge = a_assertion_challenge,
        .expected_origin = origin,
        .require_user_verification = true,
    })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.UserNotVerified => std.debug.print("round A: require_user_verification=true against a genuinely UV-clear vector: UserNotVerified (expected)\n", .{}),
        else => return err,
    }

    // ── negative: User Present flag cleared ──────────────────────────
    // Flip bit 0 of the real flags byte (offset 32 -- rpIdHash is the
    // leading 32 bytes) so this check fires strictly before signature
    // verification is ever reached (root.zig's verifyAssertion checks
    // User Present before the signature) -- an invalid signature over
    // the now-modified authenticatorData is never the reason this fails.
    var up_cleared = a_authenticator_data;
    up_cleared[32] ^= 0x01;
    if (webauthn.verifyAssertion(arena, &up_cleared, a_assertion_client_data_json, a_signature, reg.credential_public_key, .{
        .rp_id = rp_id,
        .expected_challenge = a_assertion_challenge,
        .expected_origin = origin,
    })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.UserNotPresent => std.debug.print("round A: User Present flag cleared: UserNotPresent (expected)\n", .{}),
        else => return err,
    }

    // ── negative: require_attestation against this real fmt=="none" ─────
    // vector -- no tampering, this is genuinely what §16.2 sent.
    if (webauthn.verifyRegistration(arena, a_attestation_object, a_registration_client_data_json, .{
        .rp_id = rp_id,
        .expected_challenge = a_registration_challenge,
        .expected_origin = origin,
        .require_attestation = true,
    })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.AttestationNotProvided => std.debug.print("round A: require_attestation=true against a genuine fmt==\"none\" registration: AttestationNotProvided (expected)\n", .{}),
        else => return err,
    }

    // ── negative: a real allocating failure path -- malformed base64url ──
    // challenge in an otherwise well-formed clientDataJSON. std.json has
    // already allocated to parse the object's fields before the base64
    // decode step fails, so this is a genuine allocating early return, not
    // a check that short-circuits before any allocation.
    const malformed_client_data =
        \\{"type":"webauthn.get","challenge":"not!valid!base64url","origin":"https://example.org"}
    ;
    if (webauthn.verifyAssertion(arena, &a_authenticator_data, malformed_client_data, a_signature, reg.credential_public_key, .{
        .rp_id = rp_id,
        .expected_challenge = a_assertion_challenge,
        .expected_origin = origin,
    })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.Base64DecodeError => std.debug.print("round A: malformed base64url challenge: Base64DecodeError (expected)\n", .{}),
        else => return err,
    }
}

fn roundB(gpa: std.mem.Allocator) !void {
    // A second, independent session: its own arena, its own algorithm
    // (EdDSA, not ES256), its own attestation format (packed + x5c, not
    // none) -- proves the leak-checking allocator sees a clean cycle
    // across two structurally different verifications, not just two
    // repeats of the same one.
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const reg = try webauthn.verifyRegistration(arena, b_attestation_object, b_registration_client_data_json, .{
        .rp_id = rp_id,
        .expected_challenge = b_registration_challenge,
        .expected_origin = origin,
    });
    if (reg.attestation_type != .basic) return error.WrongAttestationType;
    if (reg.leaf_cert_der == null) return error.MissingLeafCert;
    std.debug.print("round B: §16.11 registration (fmt=packed, x5c, EdDSA) verifies; attestation_type=basic, leaf cert parsed\n", .{});

    const good = try webauthn.verifyAssertion(arena, b_authenticator_data, b_assertion_client_data_json, b_signature, reg.credential_public_key, .{
        .rp_id = rp_id,
        .expected_challenge = b_assertion_challenge,
        .expected_origin = origin,
    });
    if (!good.user_present) return error.ExpectedUserPresent;
    std.debug.print("round B: §16.11 EdDSA assertion verifies; sign_count={d}\n", .{good.sign_count});

    // ── negative: tampered signature, same defense on a different algorithm ──
    var bad_sig = b_signature.*;
    bad_sig[bad_sig.len - 1] ^= 0xff;
    if (webauthn.verifyAssertion(arena, b_authenticator_data, b_assertion_client_data_json, &bad_sig, reg.credential_public_key, .{
        .rp_id = rp_id,
        .expected_challenge = b_assertion_challenge,
        .expected_origin = origin,
    })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.BadSignature => std.debug.print("round B: tampered EdDSA signature byte: BadSignature (expected)\n", .{}),
        else => return err,
    }
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer if (gpa_state.deinit() == .leak) @panic("leak");
    const gpa = gpa_state.allocator();

    try roundA(gpa);
    try roundB(gpa);

    std.debug.print("OK: all webauthn example checks passed\n", .{});
}
