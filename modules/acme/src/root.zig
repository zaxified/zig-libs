// SPDX-License-Identifier: MIT

//! acme — ACME v2 (RFC 8555) client: automated certificate issuance +
//! renewal over HTTP with the HTTP-01 challenge (Let's Encrypt et al.).
//!
//! The pieces: `Client` drives the protocol (directory → nonce → account →
//! order → HTTP-01 → CSR finalize → PEM chain download) over the sibling
//! `http.Client`; `Client.Responder` is the `router` middleware that serves
//! `/.well-known/acme-challenge/<token>`; `jws` is the ES256/JWK/thumbprint
//! layer; `x509` covers the PKCS#10 CSR (minimal DER), PEM and key/cert
//! (de)serialization; `needsRenewal` is the renewal-loop predicate.
//!
//! **Defaults to the Let's Encrypt STAGING directory** — staging issues
//! untrusted test certificates but has friendly rate limits. Production is
//! a deliberate opt-in: `.directory_url = acme.letsencrypt_production`.
//!
//! ```zig
//! const acme = @import("acme");
//!
//! var transport = http.Client.init(io, gpa, .{});
//! const account_key = acme.jws.KeyPair.generate(io); // persist via x509.ecPrivateKeyToPem
//! var client = acme.Client.init(io, gpa, &transport, account_key, .{});
//!
//! // Serve the challenge (the CA dials port 80 of the ordered domains):
//! try app_router.use(client.challengeResponder().middleware());
//!
//! var cert = try client.obtain(&.{"example.org"});
//! defer cert.deinit(gpa);
//! // cert.chain_pem + cert.key_pem → feed the TLS server; later:
//! if (acme.needsRenewal(cert.chain_pem, now_unix, 30)) { ... }
//! ```

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .client,
    // The Responder is fully thread-safe (server threads read while the
    // order flow writes); client-internal caches are synchronized, but
    // drive register/obtain from one thread at a time.
    .concurrency = .threadsafe,
    .model_after = "golang.org/x/crypto/acme + certbot flow semantics; RFC 8555/7515/7638 wire",
    .deps = .{ "http", "router", "std.crypto (ecdsa P-256, Certificate)", "std.json" },
};

/// The ACME protocol client — see `Client.init` / `Client.obtain`.
pub const Client = @import("Client.zig");

/// HTTP-01 challenge responder (`router` middleware) — usually reached via
/// `Client.challengeResponder`.
pub const Responder = Client.Responder;

/// An issued certificate (PEM chain + leaf key PEM + notAfter).
pub const Certificate = Client.Certificate;

/// JOSE layer: base64url, ES256 JWS, JWK thumbprint, key authorization.
pub const jws = @import("jws.zig");

/// X.509 layer: PKCS#10 CSR, PEM, EC key (de)serialization, cert notAfter.
pub const x509 = @import("x509.zig");

/// Let's Encrypt staging directory (untrusted test certs) — the default.
pub const letsencrypt_staging = Client.letsencrypt_staging;
/// Let's Encrypt production directory — explicit opt-in.
pub const letsencrypt_production = Client.letsencrypt_production;

/// True when the first certificate of `cert_pem` expires within
/// `within_days` of `now_unix` (or already has, or cannot be parsed —
/// failing toward renewal is the safe direction). Boundary: exactly
/// `within_days` left ⇒ renew. Allocation-free (16 KiB stack scratch; a
/// PEM bigger than that also answers "renew").
pub fn needsRenewal(cert_pem: []const u8, now_unix: i64, within_days: u32) bool {
    var scratch: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const not_after = x509.certNotAfter(fba.allocator(), cert_pem) catch return true;
    const na: i128 = not_after;
    const remaining = na - now_unix;
    return remaining <= @as(i128, within_days) * std.time.s_per_day;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test {
    _ = jws;
    _ = x509;
    _ = Client;
}

test "needsRenewal: boundary at exactly within_days, expiry, malformed input" {
    const pem = x509.test_cert_pem;
    const na: i64 = @intCast(x509.test_cert_not_after);
    const day = std.time.s_per_day;

    // 30-day window: exactly 30 days left ⇒ renew; one second more ⇒ not yet.
    try testing.expect(needsRenewal(pem, na - 30 * day, 30));
    try testing.expect(!needsRenewal(pem, na - 30 * day - 1, 30));
    // Zero window: renew only at/after expiry.
    try testing.expect(needsRenewal(pem, na, 0));
    try testing.expect(!needsRenewal(pem, na - 1, 0));
    // Expired certificates always renew.
    try testing.expect(needsRenewal(pem, na + 1, 0));
    try testing.expect(needsRenewal(pem, na + 100 * day, 30));
    // Fresh certificate, far from the window.
    try testing.expect(!needsRenewal(pem, na - 365 * day, 30));

    // Chain: the leaf (first block) decides, not the longer-lived root.
    const chain = x509.test_cert_pem ++ x509.test_root_cert_pem;
    try testing.expect(needsRenewal(chain, na - 30 * day, 30));
    try testing.expect(!needsRenewal(chain, na - 31 * day, 30));

    // Unparseable input fails toward renewal — never panics.
    try testing.expect(needsRenewal("", 0, 30));
    try testing.expect(needsRenewal("garbage", 0, 30));
    try testing.expect(needsRenewal(
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        0,
        30,
    ));
}

test "meta block sanity" {
    try testing.expectEqual(.client, meta.role);
}
