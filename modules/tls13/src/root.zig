// SPDX-License-Identifier: MIT

//! tls13 — the TLS 1.3 handshake building blocks shared by the collection's
//! TLS-family engines: the RFC 8446 §7.1 key schedule, instantiated for
//! TLS 1.3 (`"tls13 "` labels) and DTLS 1.3 (`"dtls13"`, RFC 9147 §5.9); the
//! RFC 8446 §4.4.3 CertificateVerify sign/verify; the (EC)DHE key exchange
//! (x25519, secp256r1, X25519MLKEM768); and the transcript hash, generic over
//! SHA-256 / SHA-384.
//! Pure functions over caller bytes: no I/O, no allocation, no key storage.
//!
//! It is the shared core of `dtls` (which reaches all four under its old
//! names) and of the planned `tlsserver`; more pieces move here as
//! that module needs them (SPEC.md, *Backlog / deferred*). Not an engine:
//! nothing here sends, parses or decides anything about a handshake (which
//! groups to offer is the engine's policy; `kex` only computes).

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "TLS 1.3 handshake building blocks shared by the TLS-family engines: the RFC 8446 §7.1 key schedule for TLS 1.3 and DTLS 1.3 labels (resumption, exporter and KeyUpdate steps included), CertificateVerify sign/verify (ECDSA P-256/P-384, Ed25519, RSA-PSS), the (EC)DHE key exchange (x25519, secp256r1, X25519MLKEM768) and a SHA-256/SHA-384 transcript hash",
    // Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any (pure computation)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "RFC 8446 §7 / RFC 9147 §5.9 (rustls `tls13::key_schedule` for the API split)",
    .deps = .{"rsa"}, // rsa: certverify's RSASSA-PSS (rsa_pss_rsae_sha{256,384,512})
};

/// The RFC 8446 §7.1 key schedule: `keyschedule.tls13` and
/// `keyschedule.dtls13` (one `Schedule(prefix)` per protocol).
pub const keyschedule = @import("keyschedule.zig");

/// RFC 8446 §4.4.3 CertificateVerify: the signed-content construction and
/// sign/verify for ECDSA P-256/P-384, Ed25519 and RSA-PSS over a
/// caller-supplied transcript hash.
pub const certverify = @import("certverify.zig");

/// The (EC)DHE key exchange: x25519, secp256r1 and X25519MLKEM768 shares,
/// shared secrets and the server's one-step answer.
pub const kex = @import("kex.zig");

/// The running handshake transcript hash, generic over the suite hash
/// (`Transcript(Sha256)`, `Transcript(Sha384)`), with the PSK-binder
/// truncation and the HelloRetryRequest message_hash rewrite.
pub const transcript = @import("transcript.zig");

/// `certverify`'s known-answer vectors (fixture keys, fixed transcript
/// hashes, the signed content and signatures) — exported because `dtls`'s
/// tests sign and frame with them too.
pub const certverify_kat_vectors = @import("certverify_kat_vectors.zig");

test {
    _ = keyschedule;
    _ = certverify;
    _ = kex;
    _ = transcript;
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
}
