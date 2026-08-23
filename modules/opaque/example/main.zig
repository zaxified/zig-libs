// SPDX-License-Identifier: MIT

//! What a real deployment does with `opaque`: registration once, then TWO
//! independent logins (fresh ephemeral randomness each time — session 2
//! must not silently reuse anything session 1 left behind), driving BOTH
//! roles (client and server) through every round, plus every named failure
//! this protocol can hand a caller: a wrong password (client-side
//! `error.EnvelopeRecovery`), a tampered server MAC (client-side
//! `error.ServerAuthentication`), a tampered client MAC (server-side
//! `error.ClientAuthentication`), and a malformed peer public key
//! (`error.InvalidPublicKey`).
//!
//! `opaque` IS a Zig keyword — `const opaque = @import("opaque");` does
//! not parse. Every other module's example imports its own module under
//! its own name; this one cannot, and is aliased to `opq` instead.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export).
//!
//! No `std.heap.DebugAllocator`: `opaque`'s own module doc comment/`meta`
//! say it outright ("`.role = .util, // pure computation — no I/O, no
//! allocation, no RNG`") — every wire structure and every function here
//! operates on fixed-size stack arrays, so there is nothing for a leak
//! detector to watch. The module also takes NO internal randomness at
//! all: every nonce/blind/keyshare-seed below is caller-supplied, which is
//! why this file has to manufacture its own (via label hashes — a real
//! deployment draws these from a CSPRNG instead).
//!
//! `modules/opaque/src/kat_test.zig` already drives RFC 9807 Appendix
//! C.1's official OPAQUE-3DH "Real" test vectors (both without and with
//! application identities) through this module, byte-exact including
//! every published intermediate — this file does NOT restate that table.
//! Every secret/nonce/seed below is FRESH.
//!
//! External oracle: NONE was run. No maintained, license-clear Python or
//! OpenSSL implementation of RFC 9807 OPAQUE (ristretto255-SHA-512, 3DH)
//! was found — OPAQUE is new enough (RFC published 2025) that library
//! support is thin, and the one candidate considered (a `.NET`/`libopaque`
//! C binding surfaced by a general search) could not be verified MIT or
//! run without native compilation in this sandbox, so per this repo's
//! "verify a license BEFORE reading" rule it was left unused. RFC 9807
//! Appendix C.1's official vectors remain the real external judge for
//! byte-exact correctness, already exercised at the module level; this
//! file instead exercises the protocol-sequencing and state-carrying
//! properties a vector test cannot (see the task this file was written
//! for): both roles, two full login sessions, and the fail-closed
//! rejections along the way.

const std = @import("std");
const opq = @import("opaque"); // `opaque` is a keyword — see file doc comment.

fn bytes32(label: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &out, .{});
    return out;
}

fn bytes64(label: []const u8) [64]u8 {
    var out: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(label, &out, .{});
    return out;
}

/// A fresh OPRF blind scalar from a label — real callers draw this from a
/// CSPRNG via `opq.scalarFromWideBytes` over genuine random bytes.
fn blindFromLabel(label: []const u8) [opq.Ns]u8 {
    return opq.scalarFromWideBytes(bytes64(label));
}

pub fn main() !void {
    const password = "correct horse battery staple (alice's real password)";
    const credential_identifier = "alice@example.com";
    const identities: opq.Identities = .{}; // default: both sides fall back to public keys; both registration and every login below use this SAME value, which they must.
    const context = "zig-libs opaque example v1";

    // ── server setup (once, long-term) ────────────────────────────────
    const server_kp = try opq.deriveAkeKeyPair(bytes32("server ake seed"));
    const oprf_seed = bytes64("server oprf seed (per-deployment, covers all credential_identifiers)");

    // ── registration ────────────────────────────────────────────────
    const reg_blind = blindFromLabel("alice registration blind");
    const reg_request = try opq.createRegistrationRequest(password, reg_blind);
    const reg_response = try opq.createRegistrationResponse(
        reg_request,
        server_kp.public_key,
        credential_identifier,
        oprf_seed,
    );
    const reg_finalized = try opq.finalizeRegistrationRequest(
        password,
        reg_blind,
        reg_response,
        identities,
        bytes32("alice envelope nonce"),
    );
    // What the server stores, per client — server never saw the password.
    const db_record = reg_finalized.record;
    const export_key_registration = reg_finalized.export_key;
    std.debug.print("registration complete, record stored server-side\n", .{});

    // ── login session 1 ─────────────────────────────────────────────
    const ke1_res_1 = try opq.generateKE1(
        password,
        blindFromLabel("alice login-1 blind"),
        bytes32("alice login-1 client nonce"),
        bytes32("alice login-1 client keyshare seed"),
    );
    const ke2_res_1 = try opq.generateKE2(
        server_kp.private_key,
        server_kp.public_key,
        db_record,
        credential_identifier,
        oprf_seed,
        ke1_res_1.ke1,
        identities,
        context,
        bytes32("server login-1 masking nonce"),
        bytes32("server login-1 server nonce"),
        bytes32("server login-1 keyshare seed"),
    );
    const ke3_res_1 = try opq.generateKE3(ke1_res_1.state, identities, context, ke2_res_1.ke2);
    // The export_key is a client-only value, re-derived (not transmitted)
    // — it must match what registration produced, every successful login.
    std.debug.assert(std.mem.eql(u8, &export_key_registration, &ke3_res_1.export_key));
    const session_key_server_1 = try opq.serverFinish(ke2_res_1.state, ke3_res_1.ke3);
    std.debug.assert(std.mem.eql(u8, &ke3_res_1.session_key, &session_key_server_1));
    std.debug.print("login 1: client and server agree on session_key and export_key\n", .{});

    // ── login session 2: fresh ephemeral randomness throughout ────────
    // Nothing above may leak into this session — `ClientLoginState`/
    // `ServerLoginState` are plain caller-held values, never module-global
    // state, but the actual behavioural check is that two independent
    // sessions produce independent keys.
    const ke1_res_2 = try opq.generateKE1(
        password,
        blindFromLabel("alice login-2 blind"),
        bytes32("alice login-2 client nonce"),
        bytes32("alice login-2 client keyshare seed"),
    );
    const ke2_res_2 = try opq.generateKE2(
        server_kp.private_key,
        server_kp.public_key,
        db_record,
        credential_identifier,
        oprf_seed,
        ke1_res_2.ke1,
        identities,
        context,
        bytes32("server login-2 masking nonce"),
        bytes32("server login-2 server nonce"),
        bytes32("server login-2 keyshare seed"),
    );
    const ke3_res_2 = try opq.generateKE3(ke1_res_2.state, identities, context, ke2_res_2.ke2);
    std.debug.assert(std.mem.eql(u8, &export_key_registration, &ke3_res_2.export_key));
    const session_key_server_2 = try opq.serverFinish(ke2_res_2.state, ke3_res_2.ke3);
    std.debug.assert(std.mem.eql(u8, &ke3_res_2.session_key, &session_key_server_2));
    // Two independent sessions must not share a session_key.
    std.debug.assert(!std.mem.eql(u8, &ke3_res_1.session_key, &ke3_res_2.session_key));
    std.debug.print("login 2: independent session_key from login 1, both sides still agree\n", .{});

    // ── failure path 1: wrong password (named error, client-side) ─────
    // The server has no way to know the password is wrong — it runs
    // GenerateKE2 exactly as normal against the real record. Only the
    // client's own envelope recovery catches it, BEFORE any DH result is
    // trusted (module doc comment's Security notes).
    const wrong_password = "definitely not alice's password";
    const ke1_res_w = try opq.generateKE1(
        wrong_password,
        blindFromLabel("alice wrong-password login blind"),
        bytes32("alice wrong-password client nonce"),
        bytes32("alice wrong-password client keyshare seed"),
    );
    const ke2_res_w = try opq.generateKE2(
        server_kp.private_key,
        server_kp.public_key,
        db_record,
        credential_identifier,
        oprf_seed,
        ke1_res_w.ke1,
        identities,
        context,
        bytes32("server wrong-password masking nonce"),
        bytes32("server wrong-password server nonce"),
        bytes32("server wrong-password keyshare seed"),
    );
    if (opq.generateKE3(ke1_res_w.state, identities, context, ke2_res_w.ke2)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.EnvelopeRecovery => std.debug.print("wrong password: EnvelopeRecovery (expected)\n", .{}),
        else => return err,
    }

    // ── failure path 2: tampered server_mac (named error, client-side) ─
    const ke1_res_3 = try opq.generateKE1(
        password,
        blindFromLabel("alice login-3 blind"),
        bytes32("alice login-3 client nonce"),
        bytes32("alice login-3 client keyshare seed"),
    );
    var ke2_res_3 = try opq.generateKE2(
        server_kp.private_key,
        server_kp.public_key,
        db_record,
        credential_identifier,
        oprf_seed,
        ke1_res_3.ke1,
        identities,
        context,
        bytes32("server login-3 masking nonce"),
        bytes32("server login-3 server nonce"),
        bytes32("server login-3 keyshare seed"),
    );
    ke2_res_3.ke2.auth_response.server_mac[0] ^= 0x01;
    if (opq.generateKE3(ke1_res_3.state, identities, context, ke2_res_3.ke2)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.ServerAuthentication => std.debug.print("tampered server_mac: ServerAuthentication (expected)\n", .{}),
        else => return err,
    }

    // ── failure path 3: tampered client_mac (named error, server-side) ─
    const ke1_res_4 = try opq.generateKE1(
        password,
        blindFromLabel("alice login-4 blind"),
        bytes32("alice login-4 client nonce"),
        bytes32("alice login-4 client keyshare seed"),
    );
    const ke2_res_4 = try opq.generateKE2(
        server_kp.private_key,
        server_kp.public_key,
        db_record,
        credential_identifier,
        oprf_seed,
        ke1_res_4.ke1,
        identities,
        context,
        bytes32("server login-4 masking nonce"),
        bytes32("server login-4 server nonce"),
        bytes32("server login-4 keyshare seed"),
    );
    var ke3_res_4 = try opq.generateKE3(ke1_res_4.state, identities, context, ke2_res_4.ke2);
    ke3_res_4.ke3.client_mac[0] ^= 0x01;
    if (opq.serverFinish(ke2_res_4.state, ke3_res_4.ke3)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.ClientAuthentication => std.debug.print("tampered client_mac: ClientAuthentication (expected)\n", .{}),
    }

    // ── failure path 4: malformed peer public key (named error) ───────
    // The client's ephemeral keyshare bytes, corrupted to a non-canonical
    // ristretto255 encoding — the real untrusted-wire shape a server's
    // KE1 decoder meets. `error.InvalidPublicKey` fires before any DH
    // computation, at `voprf.Element.fromBytes`'s canonical-decode check.
    var ke1_bad = ke1_res_2.ke1;
    ke1_bad.auth_request.client_public_keyshare = [_]u8{0xff} ** opq.Npk;
    if (opq.generateKE2(
        server_kp.private_key,
        server_kp.public_key,
        db_record,
        credential_identifier,
        oprf_seed,
        ke1_bad,
        identities,
        context,
        bytes32("server bad-pubkey masking nonce"),
        bytes32("server bad-pubkey server nonce"),
        bytes32("server bad-pubkey keyshare seed"),
    )) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidPublicKey => std.debug.print("non-canonical client keyshare: InvalidPublicKey (expected)\n", .{}),
        else => return err,
    }
}
