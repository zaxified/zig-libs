// SPDX-License-Identifier: MIT

//! What a consumer does with `acme`'s protocol layer on its own, without
//! dialing a CA: mint an account key, prove control of a challenge token
//! (RFC 8555 §8.1 key authorization), and sign/verify the JOSE envelope
//! every ACME request rides in — the same `jws.sign`/`jws.verifyFlattened`
//! pair the module's own mock-CA integration test uses to check the real
//! `Client`. That mock CA is exactly the shape a consumer writing their
//! OWN ACME-adjacent tooling (a staging CA stand-in, a conformance check)
//! would want to reuse — `verifyFlattened` is public for that reason.
//!
//! Also exercises `needsRenewal`, the one fully offline top-level helper:
//! its documented failure mode is "unparseable input renews", not a panic.
//!
//! Everything stays in memory: no `http.Client`, no `router`, no `io`. The
//! account key is deterministic (`generateDeterministic`, a fixed seed) —
//! not `jws.generateKeyPair`, which pulls entropy through `io` and would
//! make this example do a real syscall for no reason.
//!
//! Built against the PUBLISHED module (`@import("acme")`) only — no
//! `test_deps`.

const std = @import("std");
const acme = @import("acme");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // The account key IS the account identity (see the module README) —
    // deterministic here only so the example is reproducible byte-for-byte.
    const account_key = try acme.jws.Es256.KeyPair.generateDeterministic(@splat(0x42));

    // ── prove control: RFC 8555 §8.1 key authorization ─────────────────
    // The CA hands out `token`; the client answers with `token + "." +
    // thumbprint(account_key)`, served back at the HTTP-01 well-known URL.
    const token = "L0FfB3tPY0kR8sM4jH2vQ9wZxK7nD1cE";
    var ka_buf: [acme.jws.max_key_authorization_len]u8 = undefined;
    const key_auth = try acme.jws.keyAuthorization(&ka_buf, token, account_key.public_key);
    std.debug.print("key authorization: {s}\n", .{key_auth});

    // ── client side: sign a POST-as-GET the way `Client` would ─────────
    // `kid = null` embeds the account's `jwk` — the shape `newAccount`
    // uses before the CA has assigned an account URL.
    const request = try acme.jws.sign(gpa, account_key, "", .{
        .nonce = "server-issued-nonce-abc123",
        .url = "https://ca.example.org/acme/new-account",
    });
    defer gpa.free(request);

    // ── server side: what a CA (or a consumer's own mock CA) does ──────
    // `expected_key = null` means "trust whatever jwk is embedded" — the
    // only correct posture for `newAccount`, where the CA has not seen
    // this key before.
    var verified = try acme.jws.verifyFlattened(gpa, request, null);
    defer verified.deinit();
    std.debug.print("verified request: url={s} nonce={s}\n", .{ verified.url, verified.nonce });

    // ── reject: a request claiming to be from a DIFFERENT account ──────
    // Once an account exists, later requests carry `kid` instead of a raw
    // `jwk`, and the CA checks the signature against the key it already
    // has on file for that `kid`. A signature that verifies under the
    // embedded key must NOT also verify under some other account's key —
    // that would let one account forge requests for another.
    const other_key = try acme.jws.Es256.KeyPair.generateDeterministic(@splat(0x99));
    _ = acme.jws.verifyFlattened(gpa, request, other_key.public_key) catch |err| switch (err) {
        error.BadSignature => {
            std.debug.print("rejected: BadSignature (signed by a different account key)\n", .{});
        },
        else => return err,
    };

    // ── needsRenewal: fails toward renewal on anything it can't parse ──
    // A cert store returning a corrupt/truncated PEM is a real production
    // shape (partial write, wrong file); the renewal loop must treat that
    // as "renew now", never crash the loop.
    if (!acme.needsRenewal("not a certificate", 0, 30)) return error.ExpectedFailSafeRenewal;
    std.debug.print("rejected: unparseable cert PEM -> needsRenewal=true (fail toward renewal)\n", .{});
}
