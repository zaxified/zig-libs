// SPDX-License-Identifier: MIT

//! What a CoAP client/server pair does with `oscore`: derive mirrored
//! client/server security contexts from one shared Master Secret, run TWO
//! full request/response exchanges (the module's own state — the Sender
//! Sequence Number and the Recipient's `ReplayWindow` — carries across
//! them, which a single-shot vector test can never exercise), reject a
//! replayed request by name, reject a tampered ciphertext by name without
//! leaking the buffer it allocated for the failed decrypt, and — after a
//! simulated reboot — show the RFC 8613 §7.5 hazard (a re-derived context
//! accepts the old request again) and Appendix B.1's recovery on both
//! sides (`resumeAfterRestart`, `resumeAtLowerLimit`).
//!
//! The RESPONSE side deliberately does NOT call `protect` — RFC 8613 §5.2
//! says a response "typically" reuses the ORIGINAL REQUEST's nonce and
//! omits its own Partial IV, and the module's own doc comment says a
//! caller in that (majority) case must call `computeNonce`/`buildAad`/the
//! AEAD directly instead. That hand-assembly, and the parallel hand-
//! assembly of `AadParams.request_piv` a caller needs to protect its OWN
//! request (before `protect` has returned anything to read the encoded
//! Partial IV back from), is exactly the consumer-path gap this example
//! exists to walk: this module ships `OscoreOption.encode`'s minimal-
//! length Partial IV rule internally but did not expose it, so every
//! caller building `AadParams.request_piv` had to reimplement RFC 8613
//! §6.1's non-trivial minimal-encoding rule by hand (the module's own
//! README usage sample did so with `&.{@intCast(seq)}`, which truncates —
//! and panics in Debug/ReleaseSafe — for any sequence number >= 256).
//! DEFECT FIXED (see CHANGELOG.md, 2026-08-23): `OscoreOption.
//! encodePartialIv` is now public, `encode()` itself now calls it instead
//! of duplicating the logic, and this example uses it on both the client
//! and server side below.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export).
//!
//! External judge — ACTUALLY RUN at authoring time: this scenario's
//! deterministic (fixed, non-random) key material means every printed hex
//! value below is reproducible. The Round-1 RESPONSE's key (`server_ctx.
//! sender.key`, hand-assembled via `computeNonce`/`buildAad` reusing the
//! request's nonce — the exact consumer path this example exists to
//! prove), nonce, AAD, and ciphertext-with-tag were fed to Python's
//! `cryptography.hazmat.primitives.ciphers.aead.AESCCM` (tag_length=8) —
//! an AES-CCM implementation wholly independent of this module's own
//! `std.crypto.aead.aes_ccm.Aes128Ccm8` call — which decrypted them back
//! to the exact same plaintext. That cross-checks the module's nonce/AAD/
//! ciphertext ASSEMBLY (the actual work this module supplies, per its own
//! doc comment) against a third-party AEAD, not merely against its own
//! `unprotect`. Tool output only; no `cryptography` source was read.
//!
//! CoAP itself is out of scope for `oscore` (see its module doc comment's
//! "Scope / non-goals") — the request/response "plaintext" bytes below are
//! a FABRICATED illustrative §5.3 shape (CoAP Code + payload marker +
//! payload), not a real `coap`-module encode, and not restated from any
//! published vector.

const std = @import("std");
const oscore = @import("oscore");

/// A check that survives EVERY optimize mode, unlike a debug-only assert:
/// `-Doptimize=ReleaseFast` compiles those out, and `scripts/test.sh` does not
/// merely BUILD the examples, it RUNS them in the lane's own optimize mode --
/// so in a release lane the check vanished and the example went on printing
/// that it had passed. See `scripts/checks/check-example-assert.py`.
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

/// A fabricated, non-secret 16-byte OSCORE Master Secret for this scenario
/// only — not a published vector, not a real key.
const master_secret = [16]u8{ 0x9e, 0x7c, 0xa9, 0x00, 0x35, 0x1a, 0x6c, 0x7d, 0x1b, 0x9e, 0x22, 0x64, 0xb1, 0xd8, 0xa9, 0x51 };
/// Empty Master Salt — RFC 8613 §3.2's own default when none is configured
/// (`deriveKey`'s doc comment: an empty slice already produces the
/// zero-padded HKDF salt this implies).
const master_salt = &[_]u8{};

const client_id = "c1";
const server_id = "s1";

fn printHex(label: []const u8, bytes: []const u8) void {
    std.debug.print("{s}: {x}\n", .{ label, bytes });
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── Setup: mirrored client/server security contexts from one shared
    // Master Secret (§3.2). Neither context retains an allocation of its
    // own — `SecurityContext`'s keys/IV are inline arrays — so nothing is
    // freed here.
    var client_ctx = try oscore.deriveContext(gpa, &master_secret, master_salt, null, client_id, server_id, .aes_ccm_16_64_128);
    var server_ctx = try oscore.deriveContext(gpa, &master_secret, master_salt, null, server_id, client_id, .aes_ccm_16_64_128);
    // Figure 4's mirroring: this endpoint's sender key is the peer's
    // recipient key, and vice versa.
    must(std.mem.eql(u8, &client_ctx.sender.key, &server_ctx.recipient.key), @src());
    must(std.mem.eql(u8, &client_ctx.recipient.key, &server_ctx.sender.key), @src());

    // ── Round 1: client GET request -> server response, reusing the
    // request's nonce (RFC 8613 §5.2's "typically" case) ───────────────

    // A fabricated §5.3 plaintext: CoAP Code 0x01 (GET), no Class E
    // options, payload marker 0xFF, payload "temp?".
    const request1_plaintext = "\x01" ++ "\xff" ++ "temp?";

    var piv_buf: [oscore.OscoreOption.max_partial_iv_bytes]u8 = undefined;
    const req1_piv_bytes = oscore.OscoreOption.encodePartialIv(client_ctx.sender.sequence_number, &piv_buf);
    const req1_aad = oscore.AadParams{ .request_kid = client_ctx.sender.id, .request_piv = req1_piv_bytes };

    const protected1 = try oscore.protect(gpa, &client_ctx, request1_plaintext, req1_aad, true, null);
    defer gpa.free(protected1.ciphertext);
    const option1_wire = try protected1.option.encode(gpa);
    defer gpa.free(option1_wire);
    must(client_ctx.sender.sequence_number == 1, @src()); // incremented by protect

    // "Over the wire": the server only ever sees encoded bytes.
    const decoded_option1 = try oscore.OscoreOption.decode(option1_wire);
    const aad1_server = oscore.AadParams{ .request_kid = decoded_option1.kid.?, .request_piv = req1_piv_bytes };
    const server_view1 = try oscore.unprotect(gpa, &server_ctx, decoded_option1, protected1.ciphertext, aad1_server, null, true);
    defer gpa.free(server_view1);
    must(std.mem.eql(u8, server_view1, request1_plaintext), @src());
    std.debug.print("round1 request: server recovered {s}\n", .{server_view1});

    // Server's response, hand-assembled per §5.2's majority case: reuse
    // the REQUEST's nonce, emit no Partial IV of its own. `protect` cannot
    // express this (it always consumes a FRESH sequence number), so this
    // is the module's own documented direct-call path — computeNonce +
    // buildAad + the AEAD itself.
    const response1_plaintext = "\x45" ++ "\xff" ++ "22.5C"; // 2.05 Content
    const nonce1_resp = try oscore.computeNonce(server_ctx.common.common_iv, server_ctx.recipient.id, decoded_option1.partial_iv.?);
    // §5.4: request_kid/request_piv are the ORIGINAL REQUEST's, even when
    // protecting the response.
    var aad_buf1: [oscore.max_aad_len]u8 = undefined;
    const full_aad1_resp = try oscore.buildAad(&aad_buf1, aad1_server);
    const ciphertext1_resp = try gpa.alloc(u8, response1_plaintext.len + oscore.tag_length);
    defer gpa.free(ciphertext1_resp);
    std.crypto.aead.aes_ccm.Aes128Ccm8.encrypt(
        ciphertext1_resp[0..response1_plaintext.len],
        ciphertext1_resp[response1_plaintext.len..][0..oscore.tag_length],
        response1_plaintext,
        full_aad1_resp,
        nonce1_resp,
        server_ctx.sender.key,
    );
    printHex("round1 response key (server sender = client recipient)", &server_ctx.sender.key);
    printHex("round1 response nonce", &nonce1_resp);
    printHex("round1 response aad", full_aad1_resp);
    printHex("round1 response ciphertext+tag", ciphertext1_resp);
    printHex("round1 response plaintext", response1_plaintext);

    // Response option carries neither Partial IV nor kid (majority case)
    // -> the truly-empty wire encoding (OscoreOption.encode's own doc
    // comment).
    const response1_option: oscore.OscoreOption = .{};
    const response1_option_wire = try response1_option.encode(gpa);
    defer gpa.free(response1_option_wire);
    must(response1_option_wire.len == 0, @src());

    // Client receives the response: no Partial IV in the option -> it
    // must supply the ORIGINAL REQUEST's (id, Partial IV) itself.
    const decoded_response1_option = try oscore.OscoreOption.decode(response1_option_wire);
    const request1_nonce_source = oscore.NonceSource{ .id = client_ctx.sender.id, .partial_iv = 0 };
    const client_view1 = try oscore.unprotect(gpa, &client_ctx, decoded_response1_option, ciphertext1_resp, req1_aad, request1_nonce_source, false);
    defer gpa.free(client_view1);
    must(std.mem.eql(u8, client_view1, response1_plaintext), @src());
    std.debug.print("round1 response: client recovered {s}\n", .{client_view1});

    // ── Round 2: a second full request/response exchange — proves the
    // Sender Sequence Number and ReplayWindow state genuinely carry
    // forward, not just that a single exchange works ────────────────────

    const request2_plaintext = "\x01" ++ "\xff" ++ "hum?";
    const req2_piv_bytes = oscore.OscoreOption.encodePartialIv(client_ctx.sender.sequence_number, &piv_buf);
    const req2_aad = oscore.AadParams{ .request_kid = client_ctx.sender.id, .request_piv = req2_piv_bytes };
    const protected2 = try oscore.protect(gpa, &client_ctx, request2_plaintext, req2_aad, true, null);
    defer gpa.free(protected2.ciphertext);
    must(client_ctx.sender.sequence_number == 2, @src());

    const option2_wire = try protected2.option.encode(gpa);
    defer gpa.free(option2_wire);
    const decoded_option2 = try oscore.OscoreOption.decode(option2_wire);

    const aad2_server = oscore.AadParams{ .request_kid = decoded_option2.kid.?, .request_piv = req2_piv_bytes };
    const server_view2 = try oscore.unprotect(gpa, &server_ctx, decoded_option2, protected2.ciphertext, aad2_server, null, true);
    defer gpa.free(server_view2);
    must(std.mem.eql(u8, server_view2, request2_plaintext), @src());
    std.debug.print("round2 request: server recovered {s}\n", .{server_view2});
    must(server_ctx.recipient.replay_window.highest_seen == 1, @src()); // seq numbers are 0-based; round2's piv is 1

    // ── Negative path 1: replaying round 1's exact wire bytes must be
    // rejected by NAME, not silently re-accepted (state carried from
    // round 1+2's `update` calls is what makes this a replay now) ────────
    {
        const result = oscore.unprotect(gpa, &server_ctx, decoded_option1, protected1.ciphertext, aad1_server, null, true);
        if (result) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.Replayed => std.debug.print("replayed round1 request: Replayed (expected)\n", .{}),
            else => return err,
        }
    }

    // ── Negative path 2: a tampered ciphertext must fail AEAD
    // verification by NAME, and the plaintext buffer `unprotect`
    // allocated before discovering the tag mismatch must not leak (its
    // `errdefer` frees it) — proven by running this whole example under
    // `DebugAllocator` with leak-checking `deinit` ──────────────────────
    const request3_plaintext = "\x01" ++ "\xff" ++ "press?";
    const req3_piv_bytes = oscore.OscoreOption.encodePartialIv(client_ctx.sender.sequence_number, &piv_buf);
    const req3_aad = oscore.AadParams{ .request_kid = client_ctx.sender.id, .request_piv = req3_piv_bytes };
    const protected3 = try oscore.protect(gpa, &client_ctx, request3_plaintext, req3_aad, true, null);
    defer gpa.free(protected3.ciphertext);
    must(client_ctx.sender.sequence_number == 3, @src());
    const option3_wire = try protected3.option.encode(gpa);
    defer gpa.free(option3_wire);
    const decoded_option3 = try oscore.OscoreOption.decode(option3_wire);
    const aad3_server = oscore.AadParams{ .request_kid = decoded_option3.kid.?, .request_piv = req3_piv_bytes };

    // A copy of the ciphertext with one flipped bit — protected3.ciphertext
    // itself is untouched, so the correct-message retry below still works.
    var tampered3 = try gpa.dupe(u8, protected3.ciphertext);
    defer gpa.free(tampered3);
    tampered3[0] ^= 0x01;

    {
        const result = oscore.unprotect(gpa, &server_ctx, decoded_option3, tampered3, aad3_server, null, true);
        if (result) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.AuthenticationFailed => std.debug.print("tampered round3 ciphertext: AuthenticationFailed (expected)\n", .{}),
            else => return err,
        }
    }

    // The failed forgery attempt must NOT have burned this sequence
    // number's replay-window slot (ReplayWindow.update's own doc comment:
    // only an INDEPENDENTLY VERIFIED sequence number may be recorded) —
    // the real message at the same Partial IV must still be accepted.
    const server_view3 = try oscore.unprotect(gpa, &server_ctx, decoded_option3, protected3.ciphertext, aad3_server, null, true);
    defer gpa.free(server_view3);
    must(std.mem.eql(u8, server_view3, request3_plaintext), @src());
    std.debug.print("round3 request (after rejected forgery, same seq#): server recovered {s}\n", .{server_view3});

    // ── Reboot: what RFC 8613 §7.5 / Appendix B.1 asks of the CALLER ────
    // The Sender Sequence Number and the ReplayWindow are RAM state. A
    // re-derived context restarts at Partial IV 0 — under the SAME keys as
    // round 1 — and its empty window accepts round 1's captured request
    // again. The module supplies the arithmetic (B.1.1 checkpoint/resume,
    // B.1.2 lower limit); this example plays the nonvolatile storage.
    const k: u64 = 2; // checkpoint every 2nd sequence number (tiny, to fire here)
    var nonvolatile_ssn: u64 = 0;
    // The client protected sequence numbers 0, 1, 2 above; B.1.1 stores the
    // value BEFORE the protect that consumes a multiple of K — replaying that
    // discipline over the three sends gives checkpoints at 0 and 2.
    var replayed_ssn: u64 = 0;
    while (replayed_ssn < client_ctx.sender.sequence_number) : (replayed_ssn += 1) {
        const probe = oscore.SenderContext{ .id = client_id, .key = client_ctx.sender.key, .sequence_number = replayed_ssn };
        if (probe.needsCheckpoint(k)) nonvolatile_ssn = replayed_ssn;
    }
    must(nonvolatile_ssn == 2, @src());

    var client_after = try oscore.deriveContext(gpa, &master_secret, master_salt, null, client_id, server_id, .aes_ccm_16_64_128);
    var server_after = try oscore.deriveContext(gpa, &master_secret, master_salt, null, server_id, client_id, .aes_ccm_16_64_128);
    must(client_after.sender.sequence_number == 0, @src()); // the hazard, as derived
    must(std.mem.eql(u8, &client_after.sender.key, &client_ctx.sender.key), @src()); // same keys

    // B.1.1 on the client: SSN2 = SSN1 + K + F = 2 + 2 + 1 = 5, strictly above
    // every number (0..2) the pre-reboot process used.
    try client_after.sender.resumeAfterRestart(nonvolatile_ssn, k, 1);
    must(client_after.sender.sequence_number == 5, @src());
    must(client_after.sender.sequence_number > protected3.option.partial_iv.?, @src());

    // B.1.2 on the server: the first request after the reboot is verified
    // FRESH by the CoAP layer (Echo option, RFC 9175 — not modelled here);
    // its Partial IV becomes the window's lower limit.
    // Own Partial IV buffers from here on: `aad1_server.request_piv` still
    // points into `piv_buf`, and round 1's AAD is replayed below.
    var piv_buf4: [oscore.OscoreOption.max_partial_iv_bytes]u8 = undefined;
    var piv_buf5: [oscore.OscoreOption.max_partial_iv_bytes]u8 = undefined;
    const request4_plaintext = "\x01" ++ "\xff" ++ "after?";
    const req4_piv_bytes = oscore.OscoreOption.encodePartialIv(client_after.sender.sequence_number, &piv_buf4);
    const req4_aad = oscore.AadParams{ .request_kid = client_after.sender.id, .request_piv = req4_piv_bytes };
    const protected4 = try oscore.protect(gpa, &client_after, request4_plaintext, req4_aad, true, null);
    defer gpa.free(protected4.ciphertext);
    server_after.recipient.replay_window.resumeAtLowerLimit(protected4.option.partial_iv.?);

    // Round 1's captured request — accepted by a NAIVELY re-derived server,
    // rejected by name once the lower limit is set. Its AAD is rebuilt with
    // round 1's own Partial IV (0): `piv_buf` was reused by rounds 2 and 3
    // above, so `aad1_server.request_piv` no longer reads 0x00 — the earlier
    // replay check never noticed because `Replayed` fires before the AAD is
    // ever compared, while the naive server below gets as far as the AEAD.
    var piv_buf1_again: [oscore.OscoreOption.max_partial_iv_bytes]u8 = undefined;
    const aad1_again = oscore.AadParams{ .request_kid = decoded_option1.kid.?, .request_piv = oscore.OscoreOption.encodePartialIv(0, &piv_buf1_again) };
    {
        var naive_server = try oscore.deriveContext(gpa, &master_secret, master_salt, null, server_id, client_id, .aes_ccm_16_64_128);
        const accepted = try oscore.unprotect(gpa, &naive_server, decoded_option1, protected1.ciphertext, aad1_again, null, true);
        gpa.free(accepted);
        std.debug.print("reboot WITHOUT B.1.2: round1 request replayed and ACCEPTED (the hazard)\n", .{});

        const result = oscore.unprotect(gpa, &server_after, decoded_option1, protected1.ciphertext, aad1_again, null, true);
        if (result) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.Replayed => std.debug.print("reboot WITH B.1.2 lower limit: round1 request Replayed (expected)\n", .{}),
            else => return err,
        }
    }
    // The next genuine request after the fresh one is accepted.
    const request5_plaintext = "\x01" ++ "\xff" ++ "next?";
    const req5_piv_bytes = oscore.OscoreOption.encodePartialIv(client_after.sender.sequence_number, &piv_buf5);
    const req5_aad = oscore.AadParams{ .request_kid = client_after.sender.id, .request_piv = req5_piv_bytes };
    const protected5 = try oscore.protect(gpa, &client_after, request5_plaintext, req5_aad, true, null);
    defer gpa.free(protected5.ciphertext);
    const server_view5 = try oscore.unprotect(gpa, &server_after, protected5.option, protected5.ciphertext, req5_aad, null, true);
    defer gpa.free(server_view5);
    must(std.mem.eql(u8, server_view5, request5_plaintext), @src());
    std.debug.print("after reboot: resumed client sealed at piv={d}, server recovered {s}\n", .{ protected5.option.partial_iv.?, server_view5 });

    std.debug.print("oscore example: OK\n", .{});
}
