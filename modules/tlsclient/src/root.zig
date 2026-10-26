// SPDX-License-Identifier: MIT

//! std's TLS client, with the server's certificate chain judged by RFC 5280.
//!
//! `Client` is Zig 0.16.0's `std.crypto.tls.Client`, copied (MIT, see
//! ../NOTICE) with one change, in the handler of the server's Certificate
//! message: every certificate is proven well-formed by `x509.safe` before
//! std's parser sees it, and the chain is decided by `x509.verifyChain`
//! against the caller's bundle -- basicConstraints, keyUsage, pathLen,
//! nameConstraints, and extKeyUsage serverAuth on the leaf (`verify.zig`).
//!
//! Why: std checks none of those (ziglang/zig #35877). Anyone holding one
//! valid certificate can sign a leaf for any other name with its key and
//! prepend it to its own chain; std's client accepts it. `interop_test.zig`
//! reproduces that against `openssl s_server` and keeps a tripwire test that
//! goes red the day std refuses the forged chain -- then this module retires.
//!
//! The API is std's: `Client.init(reader, writer, options)` with std's
//! `Options` fields, so a consumer switches by changing one import. Since the
//! S2 work (2026-10-13) the defaults are Go `crypto/tls`'s client's and the
//! options cover Go's: version bounds, group preferences, HelloRetryRequest,
//! ALPN, client certificates (TLS 1.3 and 1.2, ECDSA/Ed25519/RSA, a selection
//! callback), a session view with a verification hook, OCSP/SCT, the
//! keying-material exporter, TLS 1.3 resumption. std's ClientHello stays
//! reachable (`Client.std_groups`). SPEC.md lists them and what is deferred.

const std = @import("std");

pub const Client = @import("Client.zig");
pub const verify = @import("verify.zig");

comptime {
    // The copy is std 0.16.0's file; another Zig means re-copying it and
    // re-applying the change (SPEC.md "Updating the copy").
    const v = @import("builtin").zig_version;
    if (v.major != 0 or (v.minor != 16 and v.minor != 17)) @compileError("tlsclient: Client.zig is std 0.16's (ported to 0.17); re-copy it for this Zig (SPEC.md)");
}

pub const meta = .{
    // The module catalog's one-line entry -- README.md's table is rendered
    // from this by `zig build gen-catalog`.
    .doc = "std's TLS 1.3/1.2 client with the server chain verified by RFC 5280 (x509.verifyChain) — closes ziglang/zig #35877 — grown to Go crypto/tls client parity: Go's defaults (2 key shares + HelloRetryRequest, OCSP/SCT, EMS), client certificates incl. RSA and TLS 1.2, session view + verification hook, exporter, TLS 1.3 resumption.",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .client,
    // A `Client` is one connection's state, owned by one caller, like std's.
    .concurrency = .single_owner,
    .model_after = "Zig 0.16.0 std.crypto.tls.Client (copied, MIT) + RFC 5280 §6.1 path validation via x509; options and defaults after Go crypto/tls (go1.26 client)",
    .deps = .{ "x509", "p256", "p384", "p521", "rsa", "tlsresume", "ct25519" }, // ct25519: the X25519 key share (comb public key, MULX/ADX ladder); tlsresume: the TLS 1.3 PSK binder, PSK derivation and NewSessionTicket codec for resumption; p521: the P-521 key share (std has no P-521); p384: the P-384 key share, ECDHE, client-cert signing and server-signature verify; p256 + rsa: the server CertificateVerify / ServerKeyExchange signature
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────

test {
    _ = verify;
    _ = @import("interop_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
    _ = @import("keygen.zig");
    _ = @import("hello.zig");
    _ = @import("session.zig");
    // The handshake path: analysed in full, so a patch that does not
    // compile cannot hide behind laziness.
    std.testing.refAllDecls(Client);
}
