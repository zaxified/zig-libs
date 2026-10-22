// SPDX-License-Identifier: MIT

//! tlsserver.server — the sans-I/O TLS 1.3 server: a full (EC)DHE handshake
//! with a certificate (RFC 8446 §2, Figure 1), then application data.
//!
//! The caller owns the I/O. It hands received octets to `feed`, which says
//! how many it is done with and what happened; whatever the server wants to
//! send accumulates in `pendingOutput` until the caller writes it out and
//! `discardOutput`s it. Two buffers come from the caller: the handshake
//! joiner (`inbound.Joiner.bufferLen`) and the output buffer, which must
//! hold the server's whole first flight (`minOutputLen`).
//!
//! Negotiation follows rustls 0.23 (the scope reference):
//!
//! - **version** TLS 1.3 only — no `supported_versions` with 0x0304, or a
//!   `legacy_version` below 0x0301, is `protocol_version`, checked before
//!   anything else;
//! - **certificate** fixed, or chosen by a callback from the SNI and the
//!   ClientHello (none chosen: `access_denied`); the signature scheme is
//!   the key's first candidate (or `CertifiedKey.signature_schemes` entry)
//!   the client offers and the key can produce
//!   (`certverify.canSign`: a 1024-bit RSA key has no `rsa_pss_rsae_sha512`;
//!   `handshake_failure` if none, or no `signature_algorithms` at all);
//! - **cipher suite** the client's first that the server enables
//!   (`Config.server_order`: the server's first that the client offers);
//! - **group** the client's first `supported_groups` entry the server
//!   enables (`Config.server_order`: the server's first the client
//!   supports; no `supported_groups` or no `key_share` at all is
//!   `missing_extension`, RFC 8446 §9.2); without a share for it the
//!   server sends a HelloRetryRequest naming it (no cookie, RFC 8446
//!   §4.1.4); a key_share entry for a group the client does not list, or
//!   for an obsolete one (RFC 8446 §4.2.7), is `illegal_parameter`;
//! - **second ClientHello** (after a HelloRetryRequest) must carry a share
//!   for the group asked for, still offer the suite named, the same SNI and
//!   no `early_data` (`illegal_parameter` otherwise; rustls re-chooses suite
//!   and group, RFC 8446 §4.1.4/§4.2.8 bind them); the transcript starts
//!   with `message_hash` (RFC 8446 §4.4.1). A ClientHello that triggers the
//!   retry must end its record flight (`unexpected_message`);
//! - **ALPN** the server's first protocol the client offers; none in
//!   common while the server has some is `no_application_protocol`;
//! - a compatibility `change_cipher_spec` follows the first ServerHello
//!   or HelloRetryRequest (one per connection, as rustls); the
//!   EncryptedExtensions acknowledge a DNS-name SNI with an empty
//!   `server_name` and carry the ALPN choice; an OCSP response is stapled
//!   to the leaf if the client asked for one.
//!
//!
//! With `Config.tickets` set, the server resumes sessions (RFC 8446 §2.2),
//! as rustls:
//!
//! - **tickets** `Tickets.count` NewSessionTickets follow the client's
//!   Finished in one record (none if the client does not offer
//!   `psk_dhe_ke`), each with a GREASE extension (RFC 8701); each is a
//!   `tlsresume.select.SessionState` sealed by the `Ticketer`, with this
//!   server's fields behind it (SNI, ALPN, suite);
//! - **resumption** the first offered identity that opens, has the
//!   negotiated suite and the same SNI and is younger than
//!   `Tickets.lifetime_s` is the PSK (`tlsresume.select.selectPsk`); its
//!   binder not verifying is `decrypt_error` (RFC 8446 §4.2.11). Only
//!   `psk_dhe_ke`: a fresh (EC)DHE runs on every resumption. The reported
//!   ticket age is not checked (no early data is taken). A resumed handshake
//!   sends no Certificate or CertificateVerify and no SNI acknowledgement.
//!
//! After the handshake (RFC 8446 §4.6.3) a client KeyUpdate turns the receive
//! key over; `update_requested` is answered with the server's own KeyUpdate
//! (one, however many requests arrive before it goes out — rustls). At most
//! `max_key_updates` KeyUpdates may come between two application-data
//! records (rustls, BoringSSL `kMaxKeyUpdates`). The server turns its send
//! key over by itself at `max_records_per_key`, asking the client to do the
//! same (rustls `refresh_traffic_keys`), or when the caller asks
//! (`keyUpdate`).
//!
//! With `Config.client_auth` set, a full handshake asks for a client
//! certificate (RFC 8446 §4.3.2), as rustls:
//!
//! - **request** a CertificateRequest follows the EncryptedExtensions, with
//!   an empty context, `ClientAuth.schemes` and the CA names given; none on
//!   a resumption;
//! - **chain** an empty one is `certificate_required` when the
//!   certificate is mandatory, otherwise the client goes on unauthenticated;
//!   a non-empty one's leaf must have a key the server verifies and, if it
//!   has a `keyUsage`, `digitalSignature` (BoringSSL; `unsupported_certificate`),
//!   then the chain goes to the `ClientCertVerifier` (its refusal is its
//!   alert), then the CertificateVerify over the transcript through it must
//!   use a scheme of `ClientAuth.schemes` that TLS 1.3 allows (no RSA PKCS#1
//!   v1.5, RFC 8446 §4.4.3) and suits the leaf's key (`illegal_parameter`
//!   otherwise) and verify (`decrypt_error`);
//! - **identity** the leaf is `peerCertificate` once its CertificateVerify
//!   verified; tickets carry it, so a resumption is as authenticated as
//!   the handshake that issued the ticket (rustls keeps the whole chain;
//!   here only the leaf is kept). With a mandatory certificate, a ticket
//!   without one is not resumed (stricter than rustls, which resumes it).
//!
//! With `Config.early_data` set (and tickets), a resumption takes 0-RTT
//! early data (RFC 8446 §2.3, §4.2.10), as BoringSSL decides it
//! (`EarlyDataReason`): the first identity offered, resumed with the
//! ticket's ALPN protocol, a ticket issued with `max_early_data_size`, a
//! reported age within `EarlyData.max_age_skew_s`, no HelloRetryRequest —
//! and then the `ReplayGuard` admitting the ticket (single use, RFC 8446
//! §8.1). The EncryptedExtensions acknowledge it; `early_data` events carry
//! up to the ticket's `max_early_data_size` octets until the client's
//! EndOfEarlyData, and the server may write half-RTT data meanwhile
//! (`canWrite`). Early data not taken is skipped
//! (`inbound.Inbound.skip_early`, 2^14 octets or `max_size`).

const std = @import("std");
const tls13 = @import("tls13");
const record = @import("record.zig");
const alert = @import("alert.zig");
const inbound = @import("inbound.zig");
const outbound = @import("outbound.zig");
const hello = @import("hello.zig");
const messages = @import("messages.zig");
const burn = @import("burn.zig");
const zeroize = @import("zeroize.zig").zeroize;
const clientauth = @import("clientauth.zig");
const tlsresume = @import("tlsresume");

const certverify = tls13.certverify;
const kex = tls13.kex;
const ks = tls13.keyschedule.tls13;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;

/// A certificate chain (DER, leaf first) and the leaf's signing key.
/// RFC 7250 `CertificateType` values (IANA TLS Certificate Types).
pub const cert_type_x509: u8 = 0;
pub const cert_type_raw_public_key: u8 = 2;

pub const CertifiedKey = struct {
    /// The X.509 chain, leaf first — or, with `raw_public_key`, one entry:
    /// the DER SubjectPublicKeyInfo of `key`.
    chain: []const []const u8,
    /// RFC 7250: the server authenticates with the bare public key
    /// (`chain[0]`), not a certificate (rustls `only_raw_public_keys`). Only
    /// a client that offers RawPublicKey in `server_certificate_type` is
    /// taken (others get `handshake_failure`); no OCSP staple or SCT list
    /// is sent.
    raw_public_key: bool = false,
    /// Borrowed (`certverify.SecretKey` holds pointers): must outlive the
    /// connections that use it. Null exactly when `offload` is set.
    key: ?certverify.SecretKey,
    /// The key lives elsewhere — an HSM, a KMS, a signing service, another
    /// thread (BoringSSL `SSL_PRIVATE_KEY_METHOD`, s2n async pkey, picotls
    /// async sign; rustls signs synchronously in the handshake): `feed`
    /// stops with `signature_needed` after queueing the Certificate, the
    /// caller signs `Server.signatureRequest` and hands the signature to
    /// `Server.provideSignature`, and the handshake goes on.
    offload: ?Offload = null,
    /// A DER OCSPResponse to staple on the leaf when the client asks
    /// (RFC 8446 §4.4.2.1). Empty counts as none (rustls). The module does
    /// not parse it: refreshing it before it expires is the caller's job.
    ocsp_response: ?[]const u8 = null,
    /// A `SignedCertificateTimestampList` (RFC 6962 §3.3, with its 2-octet
    /// length) to send on the leaf when the client asks (§3.3.1). Empty
    /// counts as none.
    sct_list: ?[]const u8 = null,
    /// The CertificateVerify schemes this key may sign with, most
    /// preferred first (BoringSSL `SSL_CREDENTIAL_set1_signing_algorithm_prefs`,
    /// rustls `SigningKey::choose_scheme`); null: every scheme the key can
    /// produce, in `certverify.candidateSchemes` order. Schemes the key
    /// cannot produce and the ones TLS 1.3 forbids (RSA PKCS#1 v1.5,
    /// SHA-1) are skipped.
    signature_schemes: ?[]const u16 = null,
    /// The Certificate message compressed ahead of time (RFC 8879), in the
    /// server's order of preference: the first one whose algorithm the
    /// client's `compress_certificate` offers and whose staples are the ones
    /// this handshake sends goes as a CompressedCertificate; with none, the
    /// Certificate goes uncompressed. Each is `uncompressedCertificate`'s
    /// output for its `staples`, compressed by the caller (rustls compresses
    /// per handshake behind a cache; here no compressor runs in the
    /// handshake). Replacing the chain, the OCSP staple or the SCT list
    /// means compressing again: give each entry its `digest` and `check`
    /// refuses one that no longer matches. Without it `check` sees only a
    /// length that changed, so a same-length replacement (a refreshed
    /// staple usually is one) left uncompressed would reach compressing
    /// clients stale.
    compressed_certificates: []const CompressedCertificate = &.{},

    /// What the leaf carries in a Certificate message: the OCSP staple and
    /// the SCT list go only to a client that asked for them.
    pub const Staples = struct {
        ocsp: bool = false,
        sct: bool = false,
    };

    pub const Offload = struct {
        /// The CertificateVerify schemes the key behind the signer can make,
        /// most preferred first; those of `certverify.SignatureScheme` only
        /// (others are skipped). It replaces `signature_schemes`.
        schemes: []const u16,
        /// Check every signature against the leaf's public key before it
        /// goes out (s2n `S2N_ASYNC_PKEY_VALIDATION_STRICT`): a signer that
        /// answers for the wrong key or garbles the signature fails the
        /// handshake here with `internal_error`, not at the client as
        /// `decrypt_error`. A verification costs about as much as a
        /// signature for ECDSA, a few percent of one for RSA.
        verify: bool = true,

        /// The longest signature of `schemes` (0: none known).
        fn maxSignatureLen(self: Offload) usize {
            var n: usize = 0;
            for (self.schemes) |s| n = @max(n, certverify.maxSignatureLen(@fromBackingInt(s)));
            return n;
        }
    };

    pub const CompressedCertificate = struct {
        /// `CertificateCompressionAlgorithm` (zlib 1, brotli 2, zstd 3).
        algorithm: u16,
        /// The staples in the compressed message (a staple the key does not
        /// hold cannot be in it).
        staples: Staples = .{},
        /// `uncompressedCertificate(…, staples).len`.
        uncompressed_len: u24,
        /// SHA-256 of `uncompressedCertificate(…, staples)` (or
        /// `certificateDigest(staples)`), compared by `check`; null: only
        /// the length is.
        digest: ?[32]u8 = null,
        /// `opaque compressed_certificate_message<1..2^24-1>`.
        data: []const u8,
    };

    pub const CheckError = error{
        /// No certificate, or more than `max_chain_len`.
        ChainLength,
        /// An empty certificate or one over 2^24-1 octets.
        CertificateLength,
        /// The Certificate message over its 2^24-1 octets.
        ChainTooLong,
        /// Not a well-formed `SignedCertificateTimestampList`: a length
        /// that does not add up, an empty list or an empty SCT.
        InvalidSctList,
        /// The leaf's OCSP staple and SCT list together overflow its
        /// `extensions<0..2^16-1>`.
        LeafExtensionsTooLong,
        /// `raw_public_key`, and `chain[0]` is not a DER
        /// SubjectPublicKeyInfo (or there is more than one entry:
        /// `ChainLength`).
        InvalidRawPublicKey,
        /// A compressed certificate that is empty or longer than a
        /// CompressedCertificate's 2^24-1 octets hold, or under the
        /// reserved algorithm 0.
        CompressedLength,
        /// Neither `key` nor `offload`, or both; or `offload` with no
        /// scheme `certverify` knows.
        SigningKey,
        /// A compressed certificate whose `uncompressed_len` (or `digest`)
        /// is not the message it stands for (compressed before the chain
        /// or the staples changed), or with a staple the key does not hold.
        CompressedStale,
    };

    pub const max_chain_len = 16;

    /// What the handshake would refuse with `internal_error`, reported
    /// up front: call it when loading the certificate (a `select`
    /// callback's keys are checked again at every handshake).
    pub fn check(self: *const CertifiedKey) CheckError!void {
        if (self.chain.len == 0 or self.chain.len > max_chain_len) return error.ChainLength;
        if ((self.key == null) == (self.offload == null)) return error.SigningKey;
        if (self.offload) |o| if (o.maxSignatureLen() == 0) return error.SigningKey;
        if (self.raw_public_key) {
            if (self.chain.len != 1) return error.ChainLength;
            _ = x509.parseSpki(self.chain[0]) catch return error.InvalidRawPublicKey;
        }
        // `certificate_request_context` (1) ‖ `certificate_list<0..2^24-1>`.
        var body: usize = 1 + 3;
        for (self.chain) |c| {
            if (c.len == 0 or c.len > std.math.maxInt(u24)) return error.CertificateLength;
            body += 3 + c.len + 2;
        }
        var exts: usize = 0;
        if (self.ocspStaple()) |o| exts += 4 + 1 + 3 + o.len;
        if (self.sctList()) |l| {
            if (!validSctList(l)) return error.InvalidSctList;
            exts += 4 + l.len;
        }
        if (exts > std.math.maxInt(u16)) return error.LeafExtensionsTooLong;
        if (body + exts > std.math.maxInt(u24)) return error.ChainTooLong;
        for (self.compressed_certificates) |c| {
            if (c.algorithm == 0 or c.data.len == 0 or c.data.len > std.math.maxInt(u24) - (2 + 3 + 3)) return error.CompressedLength;
            const len = self.certificateBodyLen(c.staples) orelse return error.CompressedStale;
            if (c.uncompressed_len != len) return error.CompressedStale;
            if (c.digest) |d| if (!std.mem.eql(u8, &d, &self.certificateDigest(c.staples).?)) return error.CompressedStale;
        }
    }

    /// SHA-256 of `uncompressedCertificate(…, staples)` without the buffer:
    /// for `CompressedCertificate.digest`. Null: a staple the key does not
    /// hold. Call `check` first (it bounds the lengths).
    pub fn certificateDigest(self: *const CertifiedKey, staples: Staples) ?[32]u8 {
        const body = self.certificateBodyLen(staples) orelse return null;
        var h: Sha256 = .init(.{});
        var be: [4]u8 = undefined;
        h.update(&.{0}); // certificate_request_context: empty
        std.mem.writeInt(u24, be[0..3], @intCast(body - 1 - 3), .big);
        h.update(be[0..3]);
        for (self.chain, 0..) |der, i| {
            std.mem.writeInt(u24, be[0..3], @intCast(der.len), .big);
            h.update(be[0..3]);
            h.update(der);
            const ocsp = if (i == 0 and staples.ocsp) self.ocspStaple().? else null;
            const sct = if (i == 0 and staples.sct) self.sctList().? else null;
            var exts: usize = 0;
            if (ocsp) |o| exts += 4 + 1 + 3 + o.len;
            if (sct) |l| exts += 4 + l.len;
            std.mem.writeInt(u16, be[0..2], @intCast(exts), .big);
            h.update(be[0..2]);
            if (ocsp) |o| {
                std.mem.writeInt(u16, be[0..2], 5, .big); // status_request
                h.update(be[0..2]);
                std.mem.writeInt(u16, be[0..2], @intCast(1 + 3 + o.len), .big);
                h.update(be[0..2]);
                h.update(&.{1}); // ocsp
                std.mem.writeInt(u24, be[0..3], @intCast(o.len), .big);
                h.update(be[0..3]);
                h.update(o);
            }
            if (sct) |l| {
                std.mem.writeInt(u16, be[0..2], 18, .big); // signed_certificate_timestamp
                h.update(be[0..2]);
                std.mem.writeInt(u16, be[0..2], @intCast(l.len), .big);
                h.update(be[0..2]);
                h.update(l);
            }
        }
        return h.finalResult();
    }

    /// The length of the Certificate message body with `staples` (null: a
    /// staple the key does not hold). `check` bounded it.
    fn certificateBodyLen(self: *const CertifiedKey, staples: Staples) ?usize {
        var body: usize = 1 + 3;
        for (self.chain) |c| body += 3 + c.len + 2;
        if (staples.ocsp) body += 4 + 1 + 3 + (self.ocspStaple() orelse return null).len;
        if (staples.sct) body += 4 + (self.sctList() orelse return null).len;
        return body;
    }

    /// The Certificate message body (without its 4-octet header) the
    /// handshake sends with `staples`: what RFC 8879 compresses, for
    /// `compressed_certificates`. Call `check` first.
    /// `InvalidChain`: what `check` refuses about the chain.
    pub fn uncompressedCertificate(self: *const CertifiedKey, out: []u8, staples: Staples) error{ BufferTooSmall, InvalidStaples, InvalidChain }![]u8 {
        if (out.len < 4) return error.BufferTooSmall;
        var entries: [max_chain_len]messages.CertificateEntry = undefined;
        const m = self.certificateMessage(out, &entries, staples) catch |err| return switch (err) {
            error.BufferTooSmall => error.BufferTooSmall,
            error.InvalidStaples => error.InvalidStaples,
            error.FieldTooLong => error.InvalidChain,
        };
        return m[4..];
    }

    /// The Certificate message (header ‖ body) with `staples`.
    fn certificateMessage(self: *const CertifiedKey, out: []u8, entries: *[max_chain_len]messages.CertificateEntry, staples: Staples) (messages.Error || error{InvalidStaples})![]u8 {
        if (self.chain.len == 0 or self.chain.len > max_chain_len) return error.FieldTooLong;
        for (self.chain, 0..) |der, i| entries[i] = .{ .cert_data = der };
        if (staples.ocsp) entries[0].ocsp_response = self.ocspStaple() orelse return error.InvalidStaples;
        if (staples.sct) entries[0].sct_list = self.sctList() orelse return error.InvalidStaples;
        return messages.certificate(out, "", entries[0..self.chain.len]);
    }

    /// The staples a ClientHello gets: the ones it asks for that the key
    /// holds.
    fn staplesFor(self: *const CertifiedKey, ch: *const hello.ClientHello) Staples {
        // RFC 7250 §4.2: certificate status is not for a raw public key.
        if (self.raw_public_key) return .{};
        return .{
            .ocsp = ch.ocsp_requested and self.ocspStaple() != null,
            .sct = ch.sct_requested and self.sctList() != null,
        };
    }

    /// The first compressed certificate for these staples in an algorithm
    /// the client offers.
    fn compressedFor(self: *const CertifiedKey, ch: *const hello.ClientHello, staples: Staples) ?*const CompressedCertificate {
        const offered = ch.compressCertificate() orelse return null;
        for (self.compressed_certificates) |*c| {
            if (c.staples.ocsp == staples.ocsp and c.staples.sct == staples.sct and offered.contains(c.algorithm)) return c;
        }
        return null;
    }

    fn ocspStaple(self: *const CertifiedKey) ?[]const u8 {
        const o = self.ocsp_response orelse return null;
        return if (o.len == 0) null else o;
    }

    fn sctList(self: *const CertifiedKey) ?[]const u8 {
        const l = self.sct_list orelse return null;
        return if (l.len == 0) null else l;
    }
};

/// `SerializedSCT sct_list<1..2^16-1>`, each `opaque SerializedSCT<1..2^16-1>`.
fn validSctList(l: []const u8) bool {
    if (l.len < 2 or std.mem.readInt(u16, l[0..2], .big) != l.len - 2 or l.len == 2) return false;
    var i: usize = 2;
    while (i < l.len) {
        if (l.len - i < 2) return false;
        const n = std.mem.readInt(u16, l[i..][0..2], .big);
        if (n == 0 or n > l.len - i - 2) return false;
        i += 2 + n;
    }
    return true;
}

/// Chooses the certificate for a ClientHello. `sni` is the requested DNS
/// name (null when the client sent none or an IP literal); `ch` is valid
/// only during the call. Null refuses the connection (`access_denied`).
pub const CertificateSelector = struct {
    ctx: ?*anyopaque = null,
    select: *const fn (ctx: ?*anyopaque, sni: ?[]const u8, ch: *const hello.ClientHello) ?*const CertifiedKey,
};

/// For a `CertificateSelector` serving several keys (RSA, ECDSA, Ed25519)
/// under one name: the first of `keys`, in the server's order, that can
/// sign a CertificateVerify in a scheme the client offers (BoringSSL's
/// credential list). None can: `keys[0]`, so the handshake refuses with
/// `handshake_failure` as for a single key; null only for an empty list.
pub fn firstUsableKey(keys: []const CertifiedKey, ch: *const hello.ClientHello) ?*const CertifiedKey {
    if (keys.len == 0) return null;
    const offered = ch.signatureAlgorithms() orelse return &keys[0];
    for (keys) |*k| if (Server.chooseScheme(k, &offered) != null) return k;
    return &keys[0];
}

pub const Config = struct {
    certificate: union(enum) {
        fixed: *const CertifiedKey,
        select: CertificateSelector,
    },
    /// The suites the server enables (the client's order decides, unless
    /// `server_order`).
    cipher_suites: []const record.CipherSuite = &default_cipher_suites,
    /// The groups the server enables, any of `supported_groups` (the
    /// client's order decides, unless `server_order`).
    groups: []const u16 = &default_groups,
    /// Choose the cipher suite and the group in the order of
    /// `cipher_suites` and `groups` instead of the client's (BoringSSL
    /// `SSL_OP_CIPHER_SERVER_PREFERENCE`, which covers both; rustls
    /// `ignore_client_order`, suites only). A preferred group the client
    /// supports without a share costs a HelloRetryRequest.
    server_order: bool = false,
    /// The largest record content sent, in [`outbound.min_fragment`, 2^14]
    /// (rustls `max_fragment_size`, BoringSSL `SSL_set_max_send_fragment`);
    /// out of range is clamped. Records received may still be 2^14.
    max_fragment_len: u16 = record.max_plaintext_len,
    /// In the server's order of preference.
    alpn_protocols: []const []const u8 = &.{},
    /// MUST be a cryptographically secure source: it draws the server
    /// random, the ephemeral key-exchange secret and signing randomness.
    random: std.Random,
    /// Session tickets and resumption with them; null: neither (a
    /// `pre_shared_key` offer gets a full handshake).
    tickets: ?*const Tickets = null,
    /// Client certificates; null: none is asked for.
    client_auth: ?*const ClientAuth = null,
    /// 0-RTT early data on resumptions (with `tickets`); null: none is
    /// taken, and what a client sends is skipped.
    early_data: ?*const EarlyData = null,
    /// `Server.extractSecrets` may hand the record keys out (rustls
    /// `enable_secret_extraction`, for kTLS); false refuses it.
    enable_secret_extraction: bool = false,
    /// QUIC (RFC 9001; rustls `quic::ServerConnection`, Go `QUICServer`):
    /// no record layer — handshake messages go in and out per encryption
    /// level (`quicFeed`, `quicOutput`) and the QUIC stack takes each
    /// level's traffic secret (`quicSecret`) to protect its packets
    /// (zig-libs `quic-crypto`). Null: TLS over a byte stream.
    quic: ?*const Quic = null,
};

/// QUIC encryption levels (RFC 9001 §4.1.4): which packet space handshake
/// data travels in, and which keys protect it.
pub const QuicLevel = enum(u2) { initial = 0, early = 1, handshake = 2, application = 3 };

pub const Quic = struct {
    /// This server's transport parameters (RFC 9000 §18, encoded by the
    /// QUIC stack), sent as `quic_transport_parameters` in its
    /// EncryptedExtensions. The client must send its own, and an ALPN
    /// protocol must be agreed (RFC 9001 §8.1-8.2).
    transport_parameters: []const u8,
    /// 0-RTT on a resumption only if this accepts the resumption data the
    /// ticket carries (`Server.setQuicResumptionData` at issue; RFC 9001
    /// §4.6.2: the transport parameters remembered must still allow what
    /// the client may send early). Null: the ticket's data is not checked.
    /// Asked before `EarlyData.replay`.
    accept_early: ?EarlyCheck = null,

    pub const EarlyCheck = struct {
        ctx: ?*anyopaque = null,
        accept: *const fn (ctx: ?*anyopaque, resumption_data: []const u8) bool,
    };
};

/// Client authentication (RFC 8446 §4.3.2, §4.4.2; rustls
/// `ClientCertVerifier`).
pub const ClientAuth = struct {
    verifier: clientauth.ClientCertVerifier,
    /// A client without a certificate is refused (`certificate_required`);
    /// false lets it on unauthenticated (rustls `allow_unauthenticated`).
    mandatory: bool = true,
    /// The CertificateRequest's `signature_algorithms`, most preferred
    /// first: for the client's CertificateVerify and its chain. Must name
    /// at least one TLS 1.3 CertificateVerify scheme (an empty list is
    /// `InternalError` at the first handshake; RSA PKCS#1 v1.5 alone leaves
    /// a client nothing to sign with).
    schemes: []const u16 = &default_client_auth_schemes,
    /// DER DistinguishedNames sent as `certificate_authorities` (rustls
    /// `root_hint_subjects`); empty: not sent.
    authorities: []const []const u8 = &.{},
    /// The verifier's time.
    clock: Clock,
    /// The longest client leaf taken (`bad_certificate` past it). Each
    /// `Server` keeps the leaf in a buffer of `peerBufferLen(max_leaf_len)`
    /// octets its caller gives it (`Server.setPeerBuffer`; a smaller one, or
    /// none, is `InternalError` at the ClientHello), so a larger cap costs
    /// only the connections of this configuration. ML-DSA-65/87 leaves are
    /// 5.5-7.5 KB. Past about 64 KB less 0.6 KB the tickets no longer fit
    /// their 16-bit length: none is issued.
    max_leaf_len: u16 = clientauth.default_max_leaf_len,
    /// RFC 7250: the client authenticates with a raw public key, judged by
    /// this verifier instead of `verifier` (rustls's verifier with
    /// `requires_raw_public_keys`); only a client that offers RawPublicKey
    /// in `client_certificate_type` is taken. `peerCertificate` is then the
    /// key's DER SubjectPublicKeyInfo (`peerRawPublicKey` true).
    raw_public_keys: ?clientauth.RawKeyVerifier = null,
};

/// rustls's (ring provider) `supported_verify_schemes`: ECDSA P-384 and
/// P-256, Ed25519, RSA-PSS, then RSA PKCS#1 v1.5 — for certificates only,
/// never a TLS 1.3 CertificateVerify.
/// P-521 (0x0603) and ML-DSA (0x0904-0x0906) client keys verify too, but
/// only when listed in `ClientAuth.schemes` (rustls's default leaves them
/// out as well; an ML-DSA-65/87 leaf also needs a larger `max_leaf_len`).
pub const default_client_auth_schemes = [_]u16{ 0x0503, 0x0403, 0x0807, 0x0806, 0x0805, 0x0804, 0x0601, 0x0501, 0x0401 };

/// Session tickets (RFC 8446 §4.6.1).
pub const Tickets = struct {
    ticketer: Ticketer,
    clock: Clock,
    /// NewSessionTickets after each handshake (rustls `send_tls13_tickets`).
    count: u8 = 2,
    /// The `ticket_lifetime` advertised, in seconds (at most 7 days, RFC
    /// 8446 §4.6.1); an older ticket is not resumed. rustls: 12 hours. 0
    /// issues no tickets (a lifetime of 0 tells the client to discard it).
    lifetime_s: u32 = 12 * 3600,
};

/// 0-RTT early data (RFC 8446 §2.3, §4.2.10), taken on a resumption with
/// `Config.tickets` (rustls `max_early_data_size`, BoringSSL
/// `SSL_set_early_data_enabled`). Early data is not replay-protected by
/// TLS: the server answers it before the client's Finished, so a ClientHello
/// recorded on the wire can be sent again. `replay` stops the same ticket
/// from carrying early data twice (RFC 8446 §8.1), and the reported ticket
/// age bounds how long a recording stays usable (§8.3); what early data may
/// do is still the application's call (RFC 8470 for HTTP). The identity a
/// resumed ticket carries (`Server.peerCertificate`) is not proved before
/// the client's Finished: authorize nothing in early data by it.
pub const EarlyData = struct {
    /// The `max_early_data_size` advertised in each NewSessionTicket and the
    /// most early plaintext taken (more is `unexpected_message`, rustls
    /// `TooMuchEarlyDataReceived`). BoringSSL: 14336. 0 takes none.
    max_size: u32 = 14336,
    /// Asked last, once every other condition holds: true lets this ticket
    /// carry early data, false refuses it (the handshake goes on in 1-RTT).
    replay: ReplayGuard,
    /// The largest gap, in whole seconds, between the client's idea of the
    /// ticket's age and the server's (`Server.ticketAgeSkew`) for which
    /// early data is taken (BoringSSL `kMaxTicketAgeSkewSeconds`, rustls
    /// `MAX_FRESHNESS_SKEW_MS`: 60). A recorded ClientHello stays within it
    /// for up to twice this long after it was sent.
    max_age_skew_s: u32 = 60,
};

/// Single use for the tickets that carry early data (RFC 8446 §8.1).
pub const ReplayGuard = struct {
    ctx: ?*anyopaque = null,
    /// True the first time `ticket` (the PSK identity, the ticket blob as
    /// sent; valid during the call) asks for early data; false for a ticket
    /// seen before, or when the guard cannot tell (fail closed). `now_ms`
    /// is `Tickets.clock`'s reading. It must remember a ticket for at least
    /// twice `EarlyData.max_age_skew_s` plus one second (ages are compared
    /// in whole seconds; a recording replayed later is refused by its age).
    /// Its memory is its scope: a guard per process lets a recording through
    /// on another instance, or after a restart within that window; a clock
    /// stepped back re-arms what it forgot.
    admit: *const fn (ctx: ?*anyopaque, ticket: []const u8, now_ms: i64) bool,
};

/// A `ReplayGuard` over a `tlsresume.replay.StrikeRegister` (its window at
/// least twice `EarlyData.max_age_skew_s` plus one second; full or out of
/// memory refuses).
/// The register is not locked: servers on several threads sharing it need
/// a guard of their own that takes a lock around `checkAndMark`.
pub fn strikeRegisterGuard(register: *tlsresume.replay.StrikeRegister) ReplayGuard {
    return .{ .ctx = register, .admit = StrikeRegisterAdmit.admit };
}

const StrikeRegisterAdmit = struct {
    fn admit(ctx: ?*anyopaque, ticket: []const u8, now_ms: i64) bool {
        const register: *tlsresume.replay.StrikeRegister = @ptrCast(@alignCast(ctx.?));
        return register.checkAndMark(ticket, now_ms) catch false;
    }
};

/// Why early data was or was not taken (BoringSSL `ssl_early_data_reason_t`,
/// whose names `name` gives).
pub const EarlyDataReason = enum {
    /// `Config.early_data` is null (or takes none), or there are no tickets.
    disabled,
    accepted,
    /// The client offered no early data.
    peer_declined,
    /// The client offered no ticket.
    no_session_offered,
    /// The client's tickets were not resumed.
    session_not_resumed,
    /// The ticket resumed was issued without early data.
    unsupported_for_session,
    /// A HelloRetryRequest was sent (RFC 8446 §4.2.10).
    hello_retry_request,
    /// The protocol negotiated is not the ticket's (RFC 8446 §4.2.10).
    alpn_mismatch,
    /// The reported ticket age is off by more than `max_age_skew_s`.
    ticket_age_skew,
    /// The ticket resumed is not the first one offered (RFC 8446 §4.2.10).
    not_first_identity,
    /// `ReplayGuard.admit` refused the ticket.
    replayed,
    /// QUIC: `Quic.accept_early` refused the ticket's resumption data
    /// (RFC 9001 §4.6.2; BoringSSL's name).
    quic_parameter_mismatch,

    /// BoringSSL's `SSL_early_data_reason_string` (this module's own two
    /// reasons have names of their own).
    pub fn name(r: EarlyDataReason) []const u8 {
        return switch (r) {
            .accepted => "accept",
            else => @tagName(r),
        };
    }
};

/// The wall clock, milliseconds since the Unix epoch.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    now_ms: *const fn (ctx: ?*anyopaque) i64,
};

/// Seals and opens session tickets (rustls `ProducesTickets`): the blob
/// format and the key rotation are its own. `StekTicketer` wraps a
/// `tlsresume.StekRing`.
pub const Ticketer = struct {
    ctx: *const anyopaque,
    /// Seal `plaintext` (secret: it holds the resumption master secret)
    /// into `out` under the AEAD nonce `nonce`; null if it cannot (no key,
    /// no room).
    seal: *const fn (ctx: *const anyopaque, plaintext: []const u8, nonce: [12]u8, out: []u8) ?[]u8,
    /// Open a blob this server sealed under a key still accepted at `now_s`
    /// into `out`, returning a prefix of `out` (the server wipes the secret
    /// there by its position); null for anything else.
    open: *const fn (ctx: *const anyopaque, blob: []const u8, now_s: i64, out: []u8) ?[]u8,
};

/// A `Ticketer` over a `tlsresume.StekRing(depth)`: AES-256-GCM, the key id
/// as AAD, keys past `policy.lifetime_s` refused. The ring is read, never
/// changed: its owner rotates it (`maybeRotate`) — sealing does not look at
/// the policy, so an overdue active key issues tickets nothing will open —
/// and must keep connections on other threads from reading it meanwhile.
/// One ring is one trust domain: a ticket names only SNI and suite, so
/// servers sharing a ring resume each other's sessions (rustls likewise).
pub fn StekTicketer(comptime Ring: type) type {
    return struct {
        const Self = @This();

        ring: *const Ring,
        policy: tlsresume.RotationPolicy = .{},

        /// The `Ticketer` points at `self` (and `self` at the ring): both
        /// must outlive every `Server` whose `Config.tickets` holds it —
        /// never call this on a temporary.
        pub fn ticketer(self: *const Self) Ticketer {
            return .{ .ctx = self, .seal = seal, .open = open };
        }

        fn seal(ctx: *const anyopaque, plaintext: []const u8, nonce: [12]u8, out: []u8) ?[]u8 {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            return self.ring.seal(plaintext, nonce, out) catch null;
        }

        fn open(ctx: *const anyopaque, blob: []const u8, now_s: i64, out: []u8) ?[]u8 {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            return self.ring.openAt(blob, now_s, self.policy, out) catch null;
        }
    };
}

/// The identity a `CacheTicketer` issues: random octets naming the session
/// kept server-side (rustls `ServerSessionMemoryCache`, 32 as rustls).
pub const cache_id_len = 32;

/// The longest ticket plaintext under a `ClientAuth.max_leaf_len` of
/// `max_leaf_len` (0 without client authentication): the state a
/// `CacheTicketer`'s cache keeps per session.
pub fn ticketStateLen(max_leaf_len: u16) usize {
    return ticket_head_len + @as(usize, max_leaf_len) + TicketFields.tail_len;
}

/// The cache a `CacheTicketer` keeps the sessions of a configuration with
/// that `max_leaf_len` in: entries of `ticketStateLen(max_leaf_len)`
/// octets each, allocated at `init` (with its capacity and timeout).
pub fn SessionCache(comptime max_leaf_len: u16) type {
    return tlsresume.SessionCache(cache_id_len, ticketStateLen(max_leaf_len));
}

/// A stateful `Ticketer` (rustls's default server `session_storage`, RFC
/// 8446 §2.2's "database lookup"): the session stays in `cache` and the
/// client gets a random id for it. Opening a ticket takes it out of the
/// cache, so each resumes at most once (rustls `take`), whether its binder,
/// SNI or suite then match or not — so anyone who saw a ClientHello (the
/// id is sent in the clear) can spend its ticket with a bad binder, and the
/// client's next connection is a full handshake (rustls likewise; a
/// `StekTicketer` has no such effect). A session evicted (oldest first: a
/// flood of full handshakes pushes out real ones) or past the cache's
/// timeout gets a full handshake too.
/// Sizing: `Cache` is `SessionCache(m)` with `m` the configuration's
/// `ClientAuth.max_leaf_len` (0 without client authentication; a smaller
/// one issues no ticket to a client with a longer leaf), each entry costs
/// `ticketStateLen(m)` octets whether used or not, and every lookup scans
/// all of them, up to 32 times per ClientHello (one per identity offered):
/// keep the capacity modest. Set the cache's timeout to at least
/// `Tickets.lifetime_s`, and `clock` to `Tickets.clock` (the cache dates its
/// entries by `clock`, the server opens them by `Tickets.clock`).
/// Unlike a `StekTicketer`, a ticket is good only where its cache is: one
/// cache per process means no resumption on another instance or after a
/// restart.
/// The cache is not locked: servers on several threads sharing it need a
/// `Ticketer` of their own that takes a lock around `seal` and `open`.
pub fn CacheTicketer(comptime Cache: type) type {
    return struct {
        const Self = @This();

        cache: *Cache,
        /// The time a session is stored at (`seal` is not given one).
        clock: Clock,
        /// The ids' source: a CSPRNG, as `Config.random`. The id is no
        /// secret (it crosses the wire in the clear); it must not be
        /// guessable, or a guessed id resumes nothing but spends another
        /// client's ticket, and two equal ids overwrite a session.
        random: std.Random,

        /// A `ReplayGuard` for `EarlyData.replay` alongside `self.ticketer()`:
        /// a ticket is taken from the cache when it is opened, so a recorded
        /// ClientHello sent again finds no session and resumes nothing —
        /// the guard need not remember anything (rustls takes 0-RTT only
        /// from a stateful cache, for this reason). With any other
        /// `Tickets.ticketer` (a `StekTicketer`, or a wrapper whose `open`
        /// does not take) it lets every replay through: never mix them.
        pub fn replayGuard(self: *const Self) ReplayGuard {
            return .{ .ctx = @constCast(self), .admit = admitTaken };
        }

        /// The `Ticketer` points at `self` (and `self` at the cache): both
        /// must outlive every `Server` whose `Config.tickets` holds it —
        /// never call this on a temporary.
        pub fn ticketer(self: *const Self) Ticketer {
            return .{ .ctx = self, .seal = seal, .open = open };
        }

        fn seal(ctx: *const anyopaque, plaintext: []const u8, _: [12]u8, out: []u8) ?[]u8 {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            if (out.len < cache_id_len) return null;
            const id = out[0..cache_id_len];
            self.random.bytes(id);
            const now_s = @divFloor(self.clock.now_ms(self.clock.ctx), 1000);
            self.cache.put(id, plaintext, now_s) catch return null;
            return id;
        }

        fn open(ctx: *const anyopaque, blob: []const u8, now_s: i64, out: []u8) ?[]u8 {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            if (blob.len != cache_id_len) return null;
            return self.cache.take(blob, now_s, out);
        }

        fn admitTaken(_: ?*anyopaque, _: []const u8, _: i64) bool {
            return true;
        }
    };
}

/// A ticket's plaintext is built around the client's leaf where it lies in
/// the peer buffer (`Server.setPeerBuffer`), and opened there: the
/// `SessionState` prefix (a SHA-384 secret, a 1-octet nonce) and the
/// `TicketFields` before the leaf end at `ticket_head_len`, the fields after
/// it follow it.
const ticket_head_len = tlsresume.select.SessionState(48).wireLen(1) + TicketFields.head_max;

/// Room after the leaf: the ticket's last fields, and `x509.safe`'s
/// zero padding behind the copy `clientauth.checkLeafKeyUsage` reads.
const leaf_tail_room = @max(TicketFields.tail_len, x509_parse_slack);
const x509 = @import("x509");
const x509_parse_slack = x509.safe.parse_slack;

/// What a `Ticketer` may add to the plaintext (a `StekRing` adds 29).
const ticket_seal_overhead = 128;

/// The peer buffer a `Server` needs under a `ClientAuth.max_leaf_len` of
/// `max_leaf_len` (`Server.setPeerBuffer`).
pub fn peerBufferLen(max_leaf_len: u16) usize {
    return ticket_head_len + @as(usize, max_leaf_len) + leaf_tail_room;
}

/// The longest ticket blob this configuration issues.
fn maxTicketLen(cfg: *const Config) usize {
    const leaf: usize = if (cfg.client_auth) |ca| ca.max_leaf_len else 0;
    return @min(ticket_head_len + leaf + TicketFields.tail_len + ticket_seal_overhead, std.math.maxInt(u16));
}

/// PSK identities looked at in one ClientHello; later ones are ignored.
const max_psk_identities = 32;

/// The ticket `choosePsk` resumed, for the early-data decision.
const PskTaken = struct {
    /// Its place among the offered identities.
    index: u16 = 0,
    /// The identity as sent (a slice of the ClientHello).
    identity: []const u8 = "",
    /// The ALPN protocol it was issued under.
    alpn_buf: [255]u8 = undefined,
    alpn_len: ?u8 = null,
    /// A QUIC ticket's resumption data (copied out: the ticket's scratch is
    /// wiped).
    app_buf: [255]u8 = undefined,
    app_len: ?u8 = null,
    /// Its `max_early_data_size` (0: it allows no early data).
    max_early_data: u32 = 0,

    fn alpn(t: *const PskTaken) ?[]const u8 {
        return if (t.alpn_len) |n| t.alpn_buf[0..n] else null;
    }

    fn app(t: *const PskTaken) []const u8 {
        return if (t.app_len) |n| t.app_buf[0..n] else "";
    }
};

/// What this server appends to the `SessionState` in a ticket. The suite is
/// last, so it is read from the same place whichever hash length the prefix
/// was parsed with: a ticket of the other hash never matches the suite.
const TicketFields = struct {
    sni: ?[]const u8,
    alpn: ?[]const u8,
    /// The client's certificate (DER leaf), if it authenticated, and the
    /// scheme of its CertificateVerify (0 without one).
    peer: ?[]const u8,
    /// `peer` is an RFC 7250 raw public key (written as format
    /// `format_raw`, so tickets from before stay readable).
    peer_raw: bool = false,
    peer_scheme: u16 = 0,
    /// When the client proved that certificate (the full handshake's time,
    /// carried across resumptions), ms since the epoch.
    peer_auth_ms: i64 = 0,
    /// The `max_early_data_size` the ticket was issued with (0: none).
    max_early_data: u32 = 0,
    suite: u16,
    /// Issued over QUIC (formats `format_quic`/`format_quic_raw`): resumed
    /// over QUIC only, and with `app`, the QUIC stack's resumption data
    /// (`Server.setQuicResumptionData`, at most 255 octets).
    quic: bool = false,
    app: ?[]const u8 = null,

    const format: u8 = 3;
    const format_raw: u8 = 4;
    const format_quic: u8 = 5;
    const format_quic_raw: u8 = 6;
    /// The longest run before the leaf, and the run after it.
    const head_max = 1 + 1 + 255 + 1 + 255 + 1 + 255 + 2;
    const tail_len = 2 + 8 + 4 + 2;

    /// Writes the fields around a leaf that is already at `buf[leaf_at..]`
    /// (`f.peer`, if any, is that very slice): the run before it ends at
    /// `leaf_at` (which must leave `head_max` octets), the run after it
    /// follows it. Returns the fields' extent in `buf`.
    fn writeAround(f: TicketFields, buf: []u8, leaf_at: usize) []u8 {
        const p = f.peer orelse "";
        if (f.peer) |leaf| std.debug.assert(leaf.ptr == buf[leaf_at..].ptr);
        const sni = f.sni orelse "";
        const alpn = f.alpn orelse "";
        const app = f.app orelse "";
        std.debug.assert(f.quic or app.len == 0);
        const app_field: usize = if (f.quic) 1 + app.len else 0;
        const start = leaf_at - (1 + 1 + sni.len + 1 + alpn.len + app_field + 2);
        var n = start;
        const raw = f.peer_raw and f.peer != null;
        buf[n] = if (f.quic) (if (raw) format_quic_raw else format_quic) else if (raw) format_raw else format;
        n += 1;
        for ([_][]const u8{ sni, alpn, app }, 0..) |b, i| {
            if (i == 2 and !f.quic) break;
            buf[n] = @intCast(b.len);
            @memcpy(buf[n + 1 ..][0..b.len], b);
            n += 1 + b.len;
        }
        std.mem.writeInt(u16, buf[n..][0..2], @intCast(p.len), .big);
        n += 2 + p.len;
        std.mem.writeInt(u16, buf[n..][0..2], f.peer_scheme, .big);
        std.mem.writeInt(i64, buf[n + 2 ..][0..8], f.peer_auth_ms, .big);
        std.mem.writeInt(u32, buf[n + 10 ..][0..4], f.max_early_data, .big);
        std.mem.writeInt(u16, buf[n + 14 ..][0..2], f.suite, .big);
        return buf[start .. n + tail_len];
    }

    /// Null for anything this server did not write (another format), or
    /// with a leaf over `max_peer` octets.
    fn parse(tail: []const u8, max_peer: usize) ?TicketFields {
        if (tail.len < 7 or tail[0] < format or tail[0] > format_quic_raw) return null;
        const quic = tail[0] >= format_quic;
        const raw = tail[0] == format_raw or tail[0] == format_quic_raw;
        var at: usize = 1;
        var v: [3]?[]const u8 = @splat(null);
        for (v[0..if (quic) 3 else 2]) |*x| {
            if (at >= tail.len) return null;
            const n: usize = tail[at]; // not u8: `1 + n` overflows at 255
            if (tail.len - at - 1 < n) return null;
            x.* = if (n == 0) null else tail[at + 1 ..][0..n];
            at += 1 + n;
        }
        if (tail.len - at < 2) return null;
        const n: usize = std.mem.readInt(u16, tail[at..][0..2], .big);
        at += 2;
        if (tail.len - at < n or n > max_peer) return null;
        const peer: ?[]const u8 = if (n == 0) null else tail[at..][0..n];
        at += n;
        if (tail.len - at != tail_len) return null;
        if (raw and peer == null) return null;
        return .{
            .sni = v[0],
            .alpn = v[1],
            .quic = quic,
            .app = v[2],
            .peer = peer,
            .peer_raw = raw,
            .peer_scheme = std.mem.readInt(u16, tail[at..][0..2], .big),
            .peer_auth_ms = std.mem.readInt(i64, tail[at + 2 ..][0..8], .big),
            .max_early_data = std.mem.readInt(u32, tail[at + 10 ..][0..4], .big),
            .suite = std.mem.readInt(u16, tail[at + 14 ..][0..2], .big),
        };
    }
};

/// Which of this server's tickets a ClientHello may resume (rustls
/// `can_resume`: the suite negotiated, the same SNI; younger than the
/// configured lifetime; with a mandatory client certificate, one the ticket
/// carries). A client certificate is good for the lifetime from the full
/// handshake that proved it, however many resumptions re-issued it
/// (stricter than rustls, whose re-issued tickets keep a certificate alive
/// indefinitely — past its expiry or revocation).
const Resumable = struct {
    suite: u16,
    sni: ?[]const u8,
    lifetime_ms: i64,
    now_ms: i64 = 0,
    need_peer: bool = false,
    /// A client certificate in the ticket must be of this type (a raw
    /// public key or X.509), the one negotiated for this hello.
    peer_raw: bool = false,
    /// This connection runs over QUIC: only a QUIC ticket resumes (and a
    /// TLS one only over TLS).
    quic: bool = false,
    /// Out: the QUIC ticket's resumption data (a slice of the scratch).
    app: ?[]const u8 = null,
    /// The longest leaf a ticket may carry (this connection's cap; 0
    /// without client authentication).
    max_peer: usize = 0,
    /// Out: the client certificate of the last ticket accepted (the one
    /// `selectPsk` took, if it took one), a slice of its scratch, and the
    /// scheme it signed with.
    peer: ?[]const u8 = null,
    peer_scheme: u16 = 0,
    peer_auth_ms: i64 = 0,
    /// Out: that ticket's ALPN protocol, a slice of the scratch too, and
    /// its `max_early_data_size`.
    alpn: ?[]const u8 = null,
    max_early_data: u32 = 0,

    fn accepts(w: *Resumable, tail: []const u8, age_ms: i64) bool {
        const f = TicketFields.parse(tail, w.max_peer) orelse return false;
        if (f.suite != w.suite or !Server.optEql(f.sni, w.sni) or age_ms > w.lifetime_ms) return false;
        if (w.need_peer and f.peer == null) return false;
        if (f.peer != null and f.peer_raw != w.peer_raw) return false;
        if (f.quic != w.quic) return false;
        if (f.peer != null and (f.peer_auth_ms > w.now_ms or w.now_ms - f.peer_auth_ms > w.lifetime_ms)) return false;
        w.peer = f.peer;
        w.peer_scheme = f.peer_scheme;
        w.peer_auth_ms = f.peer_auth_ms;
        w.alpn = f.alpn;
        w.app = f.app;
        w.max_early_data = f.max_early_data;
        return true;
    }

    /// `tlsresume.select.Filter.accept`.
    fn accept(ctx: ?*anyopaque, tail: []const u8, age_ms: i64) bool {
        const w: *Resumable = @ptrCast(@alignCast(ctx.?));
        return w.accepts(tail, age_ms);
    }
};

/// `selectPsk`'s ring: the configured `Ticketer`.
const TicketerRing = struct {
    t: Ticketer,

    pub fn openAt(self: *const TicketerRing, blob: []const u8, now_s: i64, _: tlsresume.RotationPolicy, out: []u8) tlsresume.stek.OpenError![]u8 {
        return self.t.open(self.t.ctx, blob, now_s, out) orelse error.DecryptionFailed;
    }
};

/// Records sealed under one send key before the server turns it over with
/// a KeyUpdate (RFC 8446 §5.5: AES-GCM's limit is 2^24.5 full records; qap
/// rekeys at 2^23).
pub const max_records_per_key: u64 = 1 << 23;

/// KeyUpdates accepted between two application-data records (rustls
/// `INITIAL_KEY_UPDATE_REQUESTS`, BoringSSL `kMaxKeyUpdates`).
pub const max_key_updates: u8 = 32;

/// `KeyUpdate.request_update` (RFC 8446 §4.6.3).
pub const KeyUpdateRequest = enum(u8) {
    update_not_requested = 0,
    update_requested = 1,
};

/// RFC 8446 §4.6.1: a ticket lives at most 7 days.
pub const max_ticket_lifetime_s: u32 = 604_800;

/// `psk_key_exchange_modes`: PSK with (EC)DHE, the only mode served.
const psk_dhe_ke: u8 = 1;

pub const default_cipher_suites = [_]record.CipherSuite{ .aes_256_gcm_sha384, .aes_128_gcm_sha256, .chacha20_poly1305_sha256 };
pub const default_groups = [_]u16{ kex.x25519_mlkem768_group, kex.x25519_group, kex.secp256r1_group, kex.secp384r1_group };
/// Every group `Config.groups` may enable: the defaults and standalone
/// ML-KEM-1024 (draft-ietf-tls-mlkem; rustls and BoringSSL leave it out of
/// their defaults too — its shares are 1568 octets each way).
pub const supported_groups = default_groups ++ [_]u16{kex.mlkem1024_group};

pub const Error = inbound.Error || clientauth.VerifyError || error{
    /// A mandatory client certificate was not sent.
    CertificateRequired,
    /// A client certificate entry with an extension.
    UnsupportedExtension,
    HandshakeFailure,
    ProtocolVersion,
    MissingExtension,
    DecryptError,
    AccessDenied,
    NoApplicationProtocol,
    /// A certificate or signature the server cannot encode or produce (a
    /// configuration problem), or a signing fault.
    InternalError,
    /// The output buffer cannot take the records: drain it, or size it
    /// with `minOutputLen`.
    OutputFull,
    /// The connection failed or was closed; nothing more can be done.
    Closed,
    /// Application data before the handshake completed.
    NotConnected,
    /// More early data than `EarlyData.max_size` (`unexpected_message`,
    /// rustls `TooMuchEarlyDataReceived`).
    TooMuchEarlyData,
    /// More than `max_key_updates` KeyUpdates without application data
    /// between them (`unexpected_message`, as BoringSSL; rustls closes
    /// without an alert).
    TooManyKeyUpdates,
    /// A record-layer call (`feed`, `write`, `keyUpdate`, `close`…) on a
    /// QUIC connection, or a `quic…` call on a TLS one.
    WrongTransport,
    /// `provideSignature` while no offloaded signature is awaited.
    NoSignatureRequested,
};

/// The alert a failure sends (null: none — the peer aborted, or the
/// output is the problem).
pub fn alertFor(err: Error) ?alert.Description {
    return switch (err) {
        error.HandshakeFailure => .handshake_failure,
        error.ProtocolVersion => .protocol_version,
        error.MissingExtension => .missing_extension,
        error.DecryptError => .decrypt_error,
        error.AccessDenied => .access_denied,
        error.NoApplicationProtocol => .no_application_protocol,
        error.InternalError => .internal_error,
        error.OutputFull, error.Closed, error.NotConnected, error.WrongTransport, error.NoSignatureRequested => null,
        error.TooManyKeyUpdates, error.TooMuchEarlyData => .unexpected_message,
        error.CertificateRequired => .certificate_required,
        error.UnsupportedExtension => .unsupported_extension,
        error.BadCertificate => .bad_certificate,
        error.UnsupportedCertificate => .unsupported_certificate,
        error.CertificateRevoked => .certificate_revoked,
        error.CertificateExpired => .certificate_expired,
        error.UnknownCa => .unknown_ca,
        error.CertificateUnknown => .certificate_unknown,
        else => |e| inbound.alertFor(@errorCast(e)),
    };
}

/// An output that takes a full 2^14 application data record when empty
/// (with the alert reserve): below it `write` sends shorter records.
pub const full_record_output_len = record.max_record_len + outbound.alert_reserve;

/// An output buffer that holds the first flight for `ck` under `cfg`:
/// ServerHello (with the largest share), CCS, EncryptedExtensions (ALPN), a
/// CertificateRequest, the chain with an OCSP staple, CertificateVerify,
/// Finished, each record's overhead, plus one alert — and a
/// HelloRetryRequest with its CCS, should the caller not drain the output
/// between the two ClientHellos. It also holds the NewSessionTickets after
/// the client's Finished (with the longest client leaf they may carry).
/// secret-api-ok: reads the chain's lengths and the key's tag (its signature schemes), never the key bytes.
pub fn minOutputLen(cfg: *const Config, ck: *const CertifiedKey) usize {
    var request: usize = 0;
    if (cfg.client_auth) |ca| {
        request = 4 + 1 + 2 + 6 + 2 * ca.schemes.len + 6;
        for (ca.authorities) |dn| request += 2 + dn.len;
    }
    // A client's `record_size_limit` may bring records down to 63 octets.
    const frag: usize = @min(fragmentLen(cfg), min_record_size_limit - 1);
    var tickets: usize = 0;
    if (cfg.tickets) |tk| {
        const one = 4 + 4 + 4 + 1 + 1 + 2 + maxTicketLen(cfg) + 2 + 4 + @as(usize, if (cfg.early_data != null) 8 else 0);
        tickets = tk.count * one;
        tickets += (tickets / frag + 1) * (record.header_len + 1 + record.tag_len);
    }
    // The request may add a record when fragments are small.
    request += (request / frag + 1) * (record.header_len + 1 + record.tag_len);
    return @max(firstFlightLen(ck, frag) + request, tickets + outbound.alert_reserve + 64);
}

/// RFC 8449 §4: the smallest `record_size_limit` a client may send.
pub const min_record_size_limit = 64;

/// `Config.max_fragment_len`, clamped.
fn fragmentLen(cfg: *const Config) u16 {
    return std.math.clamp(cfg.max_fragment_len, outbound.min_fragment, record.max_plaintext_len);
}

fn firstFlightLen(ck: *const CertifiedKey, frag: usize) usize {
    var chain: usize = 3;
    for (ck.chain) |c| chain += 3 + c.len + 2;
    if (ck.ocspStaple()) |o| chain += 4 + 4 + o.len;
    if (ck.sctList()) |l| chain += 4 + l.len;
    // A compressed one may be the longer: algorithm, two lengths and the
    // data, against the context octet and `chain` counted below.
    for (ck.compressed_certificates) |c| chain = @max(chain, 2 + 3 + 3 + c.data.len - 1);
    const sig = if (ck.key) |k| for (certverify.candidateSchemes(k)) |s| {
        break certverify.maxSignatureLen(s);
    } else 0 else if (ck.offload) |o| o.maxSignatureLen() else 0;
    const hrr = record.header_len + (4 + 2 + 32 + 33 + 3 + 2 + 6 + 6) + 6;
    const flight = hrr + (4 + 2 + 32 + 33 + 3 + 2 + 8 + kex.max_server_share_len + 6) + // ServerHello
        6 + // CCS
        (4 + 2 + 4 + 2 + 1 + 255 + 4 + 4 + 6) + // EncryptedExtensions
        (4 + 1 + chain) + (4 + 4 + sig) + (4 + 48);
    // Each message may end a record of its own: one more than the content
    // needs per message (HRR, SH, CCS ×2, EE, Certificate, CV, Finished).
    const records = flight / frag + 8;
    return flight + records * (record.header_len + 1 + record.tag_len) + outbound.alert_reserve + 64;
}

pub const Event = union(enum) {
    /// Everything buffered was used: read more and feed again.
    need_more,
    /// The client's Finished verified: the connection is up.
    handshake_done,
    /// The ClientHello's early data is taken (`Config.early_data`): the
    /// server's flight is queued, `early_data` events follow until the
    /// client's EndOfEarlyData, then `handshake_done`. The server may write
    /// from here on (half-RTT data, before the client is authenticated).
    early_data_accepted,
    /// 0-RTT application data, which a recorded ClientHello can replay (RFC
    /// 8446 §8): a slice as for `app_data`.
    early_data: []u8,
    /// Application data, a slice of the buffer given to `feed` (inside
    /// `consumed`: use it before discarding those octets).
    app_data: []u8,
    /// The client sent close_notify. It may still be written to.
    peer_closed,
    /// The certificate's key is offloaded (`CertifiedKey.offload`): the
    /// flight up to the Certificate is queued (send it now), and the
    /// handshake waits for `provideSignature` over `signatureRequest`.
    /// `feed` takes nothing until then and says this again.
    signature_needed,
};

pub const Result = struct {
    event: Event,
    consumed: usize,
};

const State = enum { client_hello, client_hello_retry, server_signature, early_data, client_certificate, client_certificate_verify, client_finished, connected, failed };

/// What an offloaded key signs (`Server.signatureRequest`).
pub const SignatureRequest = struct {
    /// A `certverify.SignatureScheme` of `CertifiedKey.Offload.schemes`.
    scheme: u16,
    /// RFC 8446 §4.4.3's content — 64 spaces, the server's context string,
    /// a zero octet, the transcript hash — to sign as the scheme says (the
    /// signer hashes it: it is not a digest). Valid until
    /// `provideSignature` or `deinit`.
    message: []const u8,
};

/// A signer for an offloaded key that answers at once (`Connection`'s):
/// the signature of `message` under `scheme`, in `out`
/// (`certverify.max_signature_len` octets).
pub const Signer = struct {
    ctx: ?*anyopaque = null,
    sign: *const fn (ctx: ?*anyopaque, scheme: u16, message: []const u8, out: []u8) error{SigningFailed}![]const u8,
};

const Transcript = union(enum) {
    sha256: tls13.transcript.Transcript(Sha256),
    sha384: tls13.transcript.Transcript(Sha384),
};

fn HashSuite(comptime H: type, comptime M: type) type {
    return struct {
        const Hash = H;
        const Hmac = M;
        const Hkdf = std.crypto.kdf.hkdf.Hkdf(M);
        const len = H.digest_length;

        fn transcript(t: *Transcript) *tls13.transcript.Transcript(H) {
            return if (H == Sha256) &t.sha256 else &t.sha384;
        }
    };
}
const S256 = HashSuite(Sha256, HmacSha256);
const S384 = HashSuite(Sha384, HmacSha384);

pub const Server = struct {
    config: *const Config,
    inbound: inbound.Inbound,
    out: outbound.Outbound,
    state: State = .client_hello,
    suite: record.CipherSuite = undefined,
    /// `suite` has been chosen (the ClientHello got that far).
    has_suite: bool = false,
    /// close_notify sent: no more writes, reading goes on.
    write_closed: bool = false,
    transcript: Transcript = undefined,
    /// Secrets of the schedule, `suite.hashLen()` octets each. The
    /// handshake ones are wiped once the client's Finished is verified.
    handshake_secret: [48]u8 = @splat(0),
    client_handshake_secret: [48]u8 = @splat(0),
    master_secret: [48]u8 = @splat(0),
    client_application_secret: [48]u8 = @splat(0),
    server_application_secret: [48]u8 = @splat(0),
    /// RFC 8446 §7.5's base, kept for the connection's life
    /// (`exportKeyingMaterial`).
    exporter_master_secret: [48]u8 = @splat(0),
    /// The negotiated ALPN protocol (one of `config.alpn_protocols`).
    alpn: ?[]const u8 = null,
    /// The negotiated key-exchange group (0: not chosen yet).
    group: u16 = 0,
    sni_buf: [253]u8 = undefined,
    sni_len: ?u8 = null,
    peer_closed: bool = false,
    /// KeyUpdates the client may still send before its next application
    /// data.
    key_updates_left: u8 = max_key_updates,
    /// The server's own KeyUpdate, due but not yet in the output (it had no
    /// room): it goes out before any further record.
    tx_update: ?KeyUpdateRequest = null,
    /// NewSessionTickets to send after the client's Finished.
    tickets_due: u8 = 0,
    /// The output octets the last `writeSlot` gave, [start, end), until
    /// `commitWrite` or `abandonWrite` (end 0: none open). `deinit` wipes
    /// them even if never committed.
    write_slot_start: usize = 0,
    write_slot_end: usize = 0,
    /// The handshake resumed a session (a ticket's PSK was accepted).
    resumed: bool = false,
    /// A HelloRetryRequest was sent.
    retried: bool = false,
    /// On a resumption: the client's reported ticket age less the server's,
    /// in whole seconds (BoringSSL `SSL_get_ticket_age_skew`).
    age_skew_s: i64 = 0,
    /// The caller's (`setPeerBuffer`): the client's certificate (DER leaf),
    /// `peer_len` octets at `ticket_head_len`, from its Certificate or the
    /// ticket resumed; the tickets are sealed and opened around it.
    peer_buf: []u8 = &.{},
    peer_len: u16 = 0,
    /// The client proved it holds the key of the leaf (its
    /// CertificateVerify verified, or the ticket was issued after one).
    peer_authenticated: bool = false,
    /// The scheme of the client's CertificateVerify (0: none), from the
    /// ticket on a resumption.
    peer_scheme: u16 = 0,
    /// When the client proved the leaf (`TicketFields.peer_auth_ms`).
    peer_auth_ms: i64 = 0,
    /// RFC 7250 at the last ClientHello: the `server_certificate_type` and
    /// `client_certificate_type` chosen (null: the client sent none).
    server_cert_type: ?u8 = null,
    client_cert_type: ?u8 = null,
    /// The client's leaf is a raw public key (a SubjectPublicKeyInfo).
    peer_raw: bool = false,
    /// QUIC: the server's handshake traffic secret and the client's early
    /// one (the record layer keeps neither: the QUIC stack takes them from
    /// `quicSecret`); wiped with the other handshake secrets.
    quic_server_hs: [48]u8 = @splat(0),
    quic_client_early: [48]u8 = @splat(0),
    /// QUIC: the client's 0-RTT is taken.
    quic_early: bool = false,
    /// QUIC: the alert a failure calls for, for the QUIC stack to send as
    /// CRYPTO_ERROR 0x100 + the description (RFC 9001 §4.8).
    quic_alert: ?alert.Description = null,
    /// QUIC: the last ClientHello's transport parameters (in the joiner).
    quic_peer_params: ?[]const u8 = null,
    /// QUIC: what the tickets issued carry (`setQuicResumptionData`), and
    /// what the resumed one carried (null: not resumed).
    quic_resumption_data: []const u8 = "",
    quic_received: [255]u8 = undefined,
    quic_received_len: ?u8 = null,
    /// What became of the client's early data (set at the last ClientHello).
    early_reason: EarlyDataReason = .disabled,
    /// The first ClientHello offered early data, and a HelloRetryRequest
    /// answered it.
    early_hrr: bool = false,
    /// Early plaintext the client may still send (`EarlyData.max_size`).
    early_left: u32 = 0,
    /// An offloaded signature awaited (`server_signature`): the content to
    /// sign, its scheme, the key it is for, the server's handshake traffic
    /// secret the Finished is made with (wiped with the other handshake
    /// secrets), and the state the client's flight then starts in.
    sign_content: [certverify.max_signed_content_len]u8 = undefined,
    sign_len: u8 = 0,
    sign_scheme: u16 = 0,
    sign_key: ?*const CertifiedKey = null,
    sign_server_hs: [48]u8 = @splat(0),
    after_signature: State = .failed,
    /// RFC 8449: the client's `record_size_limit` (null: none sent).
    peer_record_limit: ?u16 = null,

    /// secret-api-ok: returns the initial state; every secret field is zero until `feed` runs a handshake step (under `burn.handshake_burn`).
    pub fn init(config: *const Config, joiner_buf: []u8, output_buf: []u8) Server {
        var out: outbound.Outbound = .init(output_buf);
        out.max_fragment = fragmentLen(config);
        out.quic = config.quic != null;
        var in: inbound.Inbound = .init(joiner_buf);
        in.quic = config.quic != null;
        return .{
            .config = config,
            .inbound = in,
            .out = out,
        };
    }

    /// With `Config.client_auth`: the buffer the client's leaf is kept in,
    /// at least `peerBufferLen(ClientAuth.max_leaf_len)` octets, owned by the
    /// caller until `deinit` (like the joiner's). Set before the first
    /// `feed`. Tickets are sealed and opened in it; their secrets are wiped
    /// as soon as that is done, the leaf (not a secret) stays — also after
    /// `deinit`: a pooled buffer holds the last client's certificate.
    pub fn setPeerBuffer(self: *Server, buf: []u8) void {
        std.debug.assert(self.state == .client_hello);
        self.peer_buf = buf;
    }

    fn peerLeaf(self: *const Server) []u8 {
        return self.peer_buf[ticket_head_len..][0..self.peer_len];
    }

    /// Wipe every secret and both buffers.
    pub fn deinit(self: *Server) void {
        self.out.touch(self.write_slot_end);
        self.inbound.wipe();
        self.out.wipe();
        self.wipeHandshakeSecrets();
        std.crypto.secureZero(u8, &self.master_secret);
        std.crypto.secureZero(u8, &self.client_application_secret);
        std.crypto.secureZero(u8, &self.server_application_secret);
        std.crypto.secureZero(u8, &self.exporter_master_secret);
        self.state = .failed;
    }

    fn wipeHandshakeSecrets(self: *Server) void {
        std.crypto.secureZero(u8, &self.handshake_secret);
        std.crypto.secureZero(u8, &self.client_handshake_secret);
        std.crypto.secureZero(u8, &self.quic_server_hs);
        std.crypto.secureZero(u8, &self.quic_client_early);
        std.crypto.secureZero(u8, &self.sign_server_hs);
    }

    pub fn isConnected(self: *const Server) bool {
        return self.state == .connected;
    }

    /// The DNS name the client asked for, if any (valid while `self` is).
    pub fn serverName(self: *const Server) ?[]const u8 {
        return if (self.sni_len) |n| self.sni_buf[0..n] else null;
    }

    pub fn cipherSuite(self: *const Server) ?record.CipherSuite {
        return if (self.has_suite) self.suite else null;
    }

    /// The key-exchange group of the handshake (IANA code point), once the
    /// ClientHello was accepted.
    pub fn negotiatedGroup(self: *const Server) ?u16 {
        return if (self.group != 0) self.group else null;
    }

    /// The ALPN protocol chosen (one of `Config.alpn_protocols`), if any.
    pub fn alpnProtocol(self: *const Server) ?[]const u8 {
        return self.alpn;
    }

    /// The handshake resumed a session from a ticket (no certificate was
    /// sent).
    pub fn isResumed(self: *const Server) bool {
        return self.resumed;
    }

    /// The server sent a HelloRetryRequest (BoringSSL
    /// `SSL_used_hello_retry_request`).
    pub fn usedHelloRetryRequest(self: *const Server) bool {
        return self.retried;
    }

    /// The client's RFC 8449 `record_size_limit`, if it sent one: the
    /// server's protected records stay within it (`write` included).
    pub fn peerRecordSizeLimit(self: *const Server) ?u16 {
        return self.peer_record_limit;
    }

    /// On a resumption, how far the client's idea of the ticket's age is
    /// ahead of the server's (negative: behind), in seconds — each age
    /// truncated to whole seconds first, as BoringSSL
    /// `SSL_get_ticket_age_skew`. Null without a resumption. It decides
    /// only whether early data is taken (`EarlyData.max_age_skew_s`): a
    /// resumption without early data gains a replayer nothing (RFC 8446 §8).
    pub fn ticketAgeSkew(self: *const Server) ?i64 {
        return if (self.resumed) self.age_skew_s else null;
    }

    /// The client's certificate (DER, the leaf of the chain the
    /// `ClientCertVerifier` accepted), once the client proved it holds its
    /// key; null without client authentication. On a resumption, the one
    /// of the handshake that issued the ticket. Valid while `self` is.
    /// While `inEarlyData()` (and until the client's Finished) that identity
    /// is only claimed: a replayed ClientHello carries the same ticket, so
    /// early data attributed to it may come from a replayer (RFC 8446 §8).
    pub fn peerCertificate(self: *const Server) ?[]const u8 {
        return if (self.peer_authenticated) self.peerLeaf() else null;
    }

    /// `peerCertificate` is an RFC 7250 raw public key: a DER
    /// SubjectPublicKeyInfo, not a certificate (`ClientAuth.raw_public_keys`).
    /// Check it before parsing `peerCertificate` as X.509 (`x509.parseSpki`
    /// for the key, `x509.spkiOf` for a certificate).
    pub fn peerRawPublicKey(self: *const Server) bool {
        return self.peer_authenticated and self.peer_raw;
    }

    /// The signature scheme of the client's CertificateVerify (null: no
    /// client certificate). On a resumption, the one of the handshake that
    /// issued the ticket (BoringSSL `SSL_get_peer_signature_algorithm`).
    pub fn peerSignatureScheme(self: *const Server) ?u16 {
        return if (self.peer_authenticated and self.peer_scheme != 0) self.peer_scheme else null;
    }

    /// The client's early data was taken (BoringSSL `SSL_early_data_accepted`).
    pub fn earlyDataAccepted(self: *const Server) bool {
        return self.early_reason == .accepted;
    }

    /// Why the client's early data was or was not taken (BoringSSL
    /// `SSL_get_early_data_reason`); meaningful once the ClientHello was
    /// accepted.
    pub fn earlyDataReason(self: *const Server) EarlyDataReason {
        return self.early_reason;
    }

    /// Early data was taken and the client's EndOfEarlyData has not come
    /// yet: application data received now is 0-RTT (BoringSSL
    /// `SSL_in_early_data`).
    pub fn inEarlyData(self: *const Server) bool {
        return self.state == .early_data;
    }

    /// Application data may be written: the handshake completed, or the
    /// server's flight is out after taking early data (half-RTT).
    pub fn canWrite(self: *const Server) bool {
        return switch (self.state) {
            .connected => true,
            .early_data, .client_finished => self.early_reason == .accepted,
            else => false,
        };
    }

    /// The signature an offloaded key owes (`signature_needed`), or null.
    pub fn signatureRequest(self: *const Server) ?SignatureRequest {
        if (self.state != .server_signature) return null;
        return .{ .scheme = self.sign_scheme, .message = self.sign_content[0..self.sign_len] };
    }

    /// The offloaded key's signature over `signatureRequest().message`: the
    /// CertificateVerify and the Finished are queued, and `feed` goes on.
    /// With `Offload.verify` a signature that does not verify under the
    /// leaf's key fails the handshake (`InternalError`). Not awaiting one:
    /// `error.NoSignatureRequested`, and nothing changes.
    pub fn provideSignature(self: *Server, signature: []const u8) Error!void {
        if (self.state != .server_signature) return if (self.state == .failed) error.Closed else error.NoSignatureRequested;
        burn.run(burn.handshake_burn, Error!void, completeSignature, .{ self, signature }) catch |err| return self.fail(err);
    }

    /// The signer could not sign: the handshake fails with `internal_error`
    /// (queued for the caller to send).
    pub fn signatureFailed(self: *Server) void {
        if (self.state != .server_signature) return;
        std.debug.assert(self.fail(error.InternalError) == error.InternalError);
    }

    fn completeSignature(self: *Server, signature: []const u8) Error!void {
        const ck = self.sign_key.?;
        const scheme: certverify.SignatureScheme = @fromBackingInt(self.sign_scheme);
        if (signature.len == 0 or signature.len > certverify.maxSignatureLen(scheme)) return error.InternalError;
        if (ck.offload.?.verify) {
            const leaf = ck.chain[0];
            const public = (if (ck.raw_public_key) clientauth.rawPublicKey(leaf) else clientauth.leafPublicKey(leaf)) catch return error.InternalError;
            const L = self.suite.hashLen().?;
            const th = self.sign_content[self.sign_len - L .. self.sign_len];
            certverify.verify(scheme, public, .server, th, signature) catch return error.InternalError;
        }
        switch (self.suite) {
            .aes_256_gcm_sha384 => try self.sendSignature(S384, signature),
            else => try self.sendSignature(S256, signature),
        }
        std.crypto.secureZero(u8, &self.sign_server_hs);
        self.sign_key = null;
        self.state = self.after_signature;
    }

    fn sendSignature(self: *Server, comptime H: type, signature: []const u8) Error!void {
        try self.send(H, try encoded(messages.certificateVerify(self.out.slot(), self.sign_scheme, signature)));
        try self.finishFlight(H, self.sign_server_hs[0..H.len]);
    }

    pub const ExportError = error{
        /// Neither complete nor writing half-RTT data (`canWrite`).
        HandshakeNotComplete,
        /// Over `max_exporter_label_len` octets.
        LabelTooLong,
        /// Over `maxExporterLen` octets for the suite's hash.
        OutputTooLong,
    };

    /// The longest exporter label (RFC 8446 §7.1 `HkdfLabel`).
    pub const max_exporter_label_len = ks.max_exporter_label_len;

    /// The longest exporter output under `suite`: 255 HKDF blocks (8160
    /// octets with SHA-256, 12240 with SHA-384).
    pub fn maxExporterLen(suite: record.CipherSuite) usize {
        return switch (suite) {
            .aes_256_gcm_sha384 => ks.maxExporterLen(S384.Hkdf),
            else => ks.maxExporterLen(S256.Hkdf),
        };
    }

    /// One direction's record protection as a record layer outside this
    /// module needs it (kTLS `tls12_crypto_info_*`, which TLS 1.3 uses
    /// too): key, static IV and the next record's sequence number.
    pub const ExtractedDirection = struct {
        key: [32]u8,
        /// 16 (AES-128-GCM) or 32.
        key_len: u8,
        iv: [record.nonce_len]u8,
        seq: u64,
    };

    /// rustls `ExtractedSecrets`. Holds secrets: `wipe` it once installed.
    pub const ExtractedSecrets = struct {
        suite: record.CipherSuite,
        /// Server to client.
        tx: ExtractedDirection,
        /// Client to server.
        rx: ExtractedDirection,

        pub fn wipe(self: *ExtractedSecrets) void {
            std.crypto.secureZero(u8, std.mem.asBytes(self));
        }
    };

    pub const ExtractError = error{
        /// `Config.enable_secret_extraction` is off.
        SecretExtractionDisabled,
        /// The handshake is not complete (early data included), or the
        /// connection failed or was closed.
        NotConnected,
        /// Records are still queued (`pendingOutput`), a KeyUpdate is due
        /// or the send key is at its record limit (`keyUpdate`, send it,
        /// then hand over), a write slot is open, or a handshake message is
        /// half received.
        NotQuiescent,
        /// A QUIC connection: its keys are `quicSecret`'s.
        WrongTransport,
    };

    /// Hand the record protection over (rustls `dangerous_extract_secrets`):
    /// both directions' keys, IVs and sequence numbers, after which this
    /// server is finished — every secret wiped (the exporter's included),
    /// every call `Closed`, and `peerCertificate`/`peerSignatureScheme`
    /// null: read the identity, ALPN, SNI and exported keying material
    /// first. The caller must have sent `pendingOutput` and fed every
    /// octet received so far, and must hold none unconsumed after the last
    /// `feed` (the server cannot see a partial record in the caller's
    /// buffer; under `Connection`, its reader's buffer must be empty); what
    /// arrives next is the new record layer's. As in rustls, the result has
    /// no traffic secrets: a KeyUpdate after the hand-over cannot be
    /// followed.
    pub fn extractSecrets(self: *Server, out: *ExtractedSecrets) ExtractError!void {
        if (self.config.quic != null) return error.WrongTransport;
        if (!self.config.enable_secret_extraction) return error.SecretExtractionDisabled;
        if (self.state != .connected or self.write_closed or self.peer_closed) return error.NotConnected;
        if (self.pendingOutput().len != 0 or self.tx_update != null or !self.inbound.joiner.isEmpty() or self.write_slot_end != 0)
            return error.NotQuiescent;
        if (self.out.tx.seq >= max_records_per_key) return error.NotQuiescent;
        const L = self.suite.hashLen().?;
        out.* = std.mem.zeroes(ExtractedSecrets);
        out.suite = self.suite;
        out.tx.key_len = @intCast(record.Protection.trafficKeyIv(self.suite, self.server_application_secret[0..L], &out.tx.key, &out.tx.iv) catch unreachable);
        out.tx.seq = self.out.tx.seq;
        out.rx.key_len = @intCast(record.Protection.trafficKeyIv(self.suite, self.client_application_secret[0..L], &out.rx.key, &out.rx.iv) catch unreachable);
        out.rx.seq = self.inbound.rx.seq;
        // `fail`'s wipe, without an alert (`Closed` calls for none).
        const e = self.fail(error.Closed);
        std.debug.assert(e == error.Closed);
    }

    pub const QuicResult = struct {
        /// `handshake_done` (the client's Finished verified) or
        /// `early_data_accepted` (its 0-RTT is taken: `quicSecret(.read,
        /// .early)`); null: nothing to report.
        event: ?Event = null,
        /// The client's transport parameters, when this call took its
        /// ClientHello (the second one after a HelloRetryRequest): opaque
        /// RFC 9000 §18 octets, valid until the next `quicFeed`.
        transport_parameters: ?[]const u8 = null,
    };

    /// QUIC: handshake octets the client sent in CRYPTO frames at `level`,
    /// in order (RFC 9001 §4.1.3). Data at a level the handshake is not at
    /// (Initial for the ClientHello, Handshake for the client's flight; 0-RTT
    /// packets carry none), or data past a message that changes the level,
    /// is `unexpected_message`. After each call: send `quicOutput`, and
    /// install every `quicSecret` that became available. On an error the
    /// handshake is dead: close with CRYPTO_ERROR for `quicAlert`.
    pub fn quicFeed(self: *Server, level: QuicLevel, data: []const u8) Error!QuicResult {
        if (self.config.quic == null) return error.WrongTransport;
        if (self.state == .failed) return error.Closed;
        var res: QuicResult = .{};
        var at: usize = 0;
        while (at < data.len) {
            if (level != self.quicReadLevel()) return self.fail(error.UnexpectedMessage);
            const n = @min(data.len - at, record.max_plaintext_len);
            self.inbound.joiner.push(data[at..][0..n]) catch |err| return self.fail(err);
            at += n;
            while (self.inbound.joiner.next() catch |err| return self.fail(err)) |m| {
                const is_hello = m.msg_type == @backingInt(messages.HandshakeType.client_hello);
                if (self.onHandshake(m) catch |err| return self.fail(err)) |e| res.event = e;
                if (is_hello) res.transport_parameters = self.quic_peer_params;
            }
            // A message that moved the level ended this level's data: what
            // is left in the joiner `installRx` refused, the next chunk the
            // level check above refuses.
        }
        return res;
    }

    /// The level the client's next CRYPTO data must come at.
    fn quicReadLevel(self: *const Server) QuicLevel {
        return switch (self.state) {
            .client_hello, .client_hello_retry => .initial,
            .connected, .failed => .application,
            else => .handshake,
        };
    }

    /// QUIC: the handshake octets to send next, at their level (lowest
    /// level first); `discardOutput` what went into CRYPTO frames.
    pub fn quicOutput(self: *const Server) ?struct { level: QuicLevel, data: []const u8 } {
        // After a failure a flight may be cut short: nothing goes out (the
        // QUIC stack closes with `quicAlert`).
        if (self.state == .failed) return null;
        const p = self.out.quicPending() orelse return null;
        return .{ .level = @fromBackingInt(@intCast(p.level)), .data = p.data };
    }

    pub const QuicDirection = enum { read, write };

    /// QUIC: the traffic secret protecting `level` in `direction` (the QUIC
    /// stack derives its packet keys with `quic-crypto`, the hash being
    /// `cipherSuite()`'s), or null while there is none — Initial keys come
    /// from the connection ID (`quic-crypto` `deriveInitialSecrets`). The
    /// handshake (and early) secrets are wiped once the client's Finished
    /// is verified, the application ones at `deinit`: take them after the
    /// `quicFeed` that made them available.
    /// secret-api-ok: returns a slice of the server's own secret fields; nothing is derived or copied in this frame.
    pub fn quicSecret(self: *const Server, direction: QuicDirection, level: QuicLevel) ?[]const u8 {
        if (self.config.quic == null or !self.has_suite) return null;
        const L = self.suite.hashLen().?;
        const handshaking = switch (self.state) {
            .server_signature, .client_certificate, .client_certificate_verify, .client_finished => true,
            else => false,
        };
        return switch (direction) {
            .write => switch (level) {
                .handshake => if (handshaking) self.quic_server_hs[0..L] else null,
                .application => if (self.out.quic_level == 3 and self.state != .failed) self.server_application_secret[0..L] else null,
                .initial, .early => null,
            },
            .read => switch (level) {
                .early => if (self.quic_early and handshaking) self.quic_client_early[0..L] else null,
                .handshake => if (handshaking) self.client_handshake_secret[0..L] else null,
                .application => if (self.state == .connected) self.client_application_secret[0..L] else null,
                .initial => null,
            },
        };
    }

    /// QUIC: the data each NewSessionTicket carries for the QUIC stack (at
    /// most 255 octets; rustls `set_resumption_data`), typically the
    /// transport parameters 0-RTT must be checked against. Set before the
    /// client's Finished (the tickets are issued then); borrowed until.
    pub fn setQuicResumptionData(self: *Server, data: []const u8) void {
        std.debug.assert(data.len <= 255);
        self.quic_resumption_data = data;
    }

    /// QUIC: the resumption data of the ticket this connection resumed
    /// (rustls `received_resumption_data`); null on a full handshake.
    pub fn quicResumptionData(self: *const Server) ?[]const u8 {
        return if (self.quic_received_len) |n| self.quic_received[0..n] else null;
    }

    /// QUIC: the alert behind the last failure, for CRYPTO_ERROR 0x100 +
    /// its code (RFC 9001 §4.8); null: none to send (the peer aborted, or a
    /// misuse such as `WrongTransport`) — close with INTERNAL_ERROR.
    pub fn quicAlert(self: *const Server) ?alert.Description {
        return self.quic_alert;
    }

    /// RFC 8446 §7.5 (RFC 5705's interface): `out.len` octets of keying
    /// material for `label` and `context` from the exporter master secret.
    /// No context and an empty one give the same value in TLS 1.3, so
    /// there is no "no context" form. Available once `canWrite()` holds:
    /// the handshake completed, or early data was taken and the server is
    /// writing half-RTT data (BoringSSL; the client's Finished, and its
    /// certificate, are then still to come). Not the early exporter
    /// (`early_exporter_master_secret`). The secret lives until `deinit`
    /// or a failure.
    pub fn exportKeyingMaterial(self: *const Server, out: []u8, label: []const u8, context: []const u8) ExportError!void {
        if (!self.canWrite()) return error.HandshakeNotComplete;
        if (label.len > max_exporter_label_len) return error.LabelTooLong;
        if (out.len > maxExporterLen(self.suite)) return error.OutputTooLong;
        switch (self.suite) {
            .aes_256_gcm_sha384 => ks.exportKeyingMaterial(S384.Hash, S384.Hkdf, out, &self.exporter_master_secret, label, context),
            else => ks.exportKeyingMaterial(S256.Hash, S256.Hkdf, out, self.exporter_master_secret[0..32], label, context),
        }
    }

    pub fn pendingOutput(self: *const Server) []const u8 {
        // QUIC: one level at a time (`quicOutput` names it); the levels'
        // octets must never go out together.
        if (self.config.quic != null) return if (self.quicOutput()) |o| o.data else "";
        return self.out.pending();
    }

    pub fn discardOutput(self: *Server, n: usize) void {
        self.out.discard(n);
    }

    /// Process received octets (`buf`: everything received and not yet
    /// consumed) up to the next event. On an error the connection is dead:
    /// the alert it calls for (if any) is already in `pendingOutput` —
    /// send it, then close.
    pub fn feed(self: *Server, buf: []u8) Error!Result {
        if (self.config.quic != null) return error.WrongTransport;
        if (self.state == .failed) return error.Closed;
        if (self.state == .server_signature) return .{ .event = .signature_needed, .consumed = 0 };
        self.flushKeyUpdate() catch |err| return self.fail(err);
        var at: usize = 0;
        while (true) {
            const r = self.inbound.next(buf[at..]) catch |err| return self.fail(err);
            at += r.consumed;
            switch (r.event) {
                .need_more => return .{ .event = .need_more, .consumed = at },
                .app_data => |d| {
                    if (self.state == .early_data) {
                        // RFC 8446 §4.2.10: no more than max_early_data_size.
                        if (d.len > self.early_left) return self.fail(error.TooMuchEarlyData);
                        self.early_left -= @intCast(d.len);
                        return .{ .event = .{ .early_data = d }, .consumed = at };
                    }
                    // Only a record that carries data refills the KeyUpdate
                    // budget (BoringSSL `kMaxKeyUpdates`): empty records
                    // between KeyUpdates would make the cap moot.
                    if (d.len != 0) self.key_updates_left = max_key_updates;
                    return .{ .event = .{ .app_data = d }, .consumed = at };
                },
                .peer_closed => {
                    self.peer_closed = true;
                    return .{ .event = .peer_closed, .consumed = at };
                },
                .handshake => |m| {
                    const ev = self.onHandshake(m) catch |err| return self.fail(err);
                    if (ev) |e| return .{ .event = e, .consumed = at };
                },
            }
        }
    }

    /// Seal application data into the output, as much as fits (at least
    /// one octet unless the output is full). Returns how much was taken.
    /// A record is not cut short to fit behind output still pending: send
    /// that first (`error.OutputFull` when nothing was taken). An output
    /// smaller than `full_record_output_len` cuts records to what it holds.
    pub fn write(self: *Server, data: []const u8) Error!usize {
        if (self.config.quic != null) return error.WrongTransport;
        try self.checkWritable();
        var done: usize = 0;
        while (done < data.len) {
            const s = try self.writeSlot();
            // A record cut short only because earlier records still wait
            // in the buffer goes out whole after the caller sends them
            // (record boundaries follow the data, not the buffer's fill).
            const want = @min(data.len - done, self.out.max_fragment);
            if (s.len == 0 or (s.len < want and self.out.len != 0)) break;
            const n = @min(s.len, want);
            @memcpy(s[0..n], data[done..][0..n]);
            try self.commitWrite(n);
            done += n;
        }
        if (done == 0 and data.len != 0) return error.OutputFull;
        return done;
    }

    /// Where application data can be written in place, inside the record
    /// it will be sealed in (no copy): at most one record's content
    /// (`Config.max_fragment_len`), less when output still pending leaves
    /// less room. Write up to its length, then `commitWrite` — with no other
    /// call on the server in between (each may queue records over it). Empty:
    /// send the pending output first. A KeyUpdate that is due goes out
    /// before the slot is given.
    pub fn writeSlot(self: *Server) Error![]u8 {
        if (self.config.quic != null) return error.WrongTransport;
        try self.checkWritable();
        // RFC 8446 §5.5: retire the key well before its usage limit.
        if (self.out.tx.seq >= max_records_per_key and self.tx_update == null)
            self.tx_update = .update_requested;
        self.flushKeyUpdate() catch |err| return self.fail(err);
        if (self.tx_update != null) return self.out.buf[0..0];
        const s = self.out.slot();
        const w = s[0..@min(s.len, self.out.max_fragment)];
        if (w.len != 0) {
            self.write_slot_start = @intFromPtr(w.ptr) - @intFromPtr(self.out.buf.ptr);
            self.write_slot_end = self.write_slot_start + w.len;
        }
        return w;
    }

    /// Seal the first `n` octets of the last `writeSlot` as one application
    /// data record (`n` at most its length; 0 seals nothing). `n` is what
    /// was written: octets of the slot past it must not hold data.
    pub fn commitWrite(self: *Server, n: usize) Error!void {
        if (self.config.quic != null) return error.WrongTransport;
        self.closeWriteSlot(n);
        if (n == 0) return;
        if (!self.canWrite() or self.write_closed) return error.Closed;
        std.debug.assert(n <= self.out.max_fragment);
        self.out.commit(.application_data, n) catch |err| {
            // Not sealed: the plaintext does not wait for `deinit` to go.
            zeroize(self.out.buf[self.out.len..]);
            return self.fail(err);
        };
    }

    fn checkWritable(self: *const Server) Error!void {
        if (self.state == .failed or self.write_closed) return error.Closed;
        if (!self.canWrite()) return error.NotConnected;
    }

    /// Give up the last `writeSlot` after writing its first `n` octets
    /// (`Connection` closing with a partial record): nothing is sealed, and
    /// `deinit` wipes just those `n`.
    pub fn abandonWrite(self: *Server, n: usize) void {
        if (self.config.quic != null) return;
        self.closeWriteSlot(n);
    }

    /// The open slot's first `n` octets hold data; it is closed.
    fn closeWriteSlot(self: *Server, n: usize) void {
        if (self.write_slot_end == 0) return;
        std.debug.assert(n <= self.write_slot_end - self.write_slot_start);
        self.out.touch(self.write_slot_start + n);
        self.write_slot_end = 0;
    }

    /// Turn the send key over now (RFC 8446 §4.6.3), asking the client to
    /// turn its own over too when `request` is `update_requested`. The
    /// KeyUpdate goes out before any later record — at once if the output
    /// has room. A KeyUpdate already due is not repeated, but one due
    /// without a request is turned into `update_requested` if that is asked.
    pub fn keyUpdate(self: *Server, request: KeyUpdateRequest) Error!void {
        if (self.config.quic != null) return error.WrongTransport;
        switch (self.state) {
            .connected => {},
            .failed => return error.Closed,
            else => return error.NotConnected,
        }
        if (self.write_closed) return error.Closed;
        if (self.tx_update == null or request == .update_requested) self.tx_update = request;
        self.flushKeyUpdate() catch |err| return self.fail(err);
    }

    /// Send the due KeyUpdate, if the output has room: sealed under the old
    /// key, everything after it under the next one.
    fn flushKeyUpdate(self: *Server) Error!void {
        const request = self.tx_update orelse return;
        if (self.write_closed) {
            self.tx_update = null;
            return;
        }
        const msg = [_]u8{ @backingInt(messages.HandshakeType.key_update), 0, 0, 1, @backingInt(request) };
        self.out.write(.handshake, &msg) catch |err| switch (err) {
            error.OutputFull => return,
            else => |e| return e,
        };
        self.tx_update = null;
        const secret = self.nextSecret(&self.server_application_secret);
        self.out.installTx(self.suite, secret) catch return error.InternalError;
    }

    /// `secret` ← application_traffic_secret_N+1 (RFC 8446 §7.2), in place.
    fn nextSecret(self: *const Server, secret: *[48]u8) []const u8 {
        switch (self.suite) {
            .aes_256_gcm_sha384 => {
                ks.nextApplicationTrafficSecret(S384.Hkdf, secret, secret);
                return secret;
            },
            else => {
                ks.nextApplicationTrafficSecret(S256.Hkdf, secret[0..32], secret[0..32]);
                return secret[0..32];
            },
        }
    }

    /// Queue close_notify. Nothing more can be written afterwards; the
    /// client's remaining data and its close_notify can still be read.
    /// secret-api-ok: seals one alert (`record` burns its own frame) and zeroes the send secret; no secret is copied into this frame.
    pub fn close(self: *Server) Error!void {
        if (self.config.quic != null) return error.WrongTransport;
        if (self.state == .failed or self.write_closed) return error.Closed;
        self.out.write(.alert, &alert.Alert.close_notify.encode()) catch {};
        self.write_closed = true;
        self.out.wipeKey();
        // Nothing more is sealed: the send secret is dead.
        std.crypto.secureZero(u8, &self.server_application_secret);
    }

    /// Queue the error's alert, then wipe every key and secret (the queued
    /// records stay for the caller to send).
    fn fail(self: *Server, err: anyerror) Error {
        const e: Error = @errorCast(err);
        if (self.state != .failed) {
            // QUIC: our own output failing is an internal error too.
            if (self.config.quic != null) self.quic_alert = if (e == error.OutputFull) .internal_error else alertFor(e);
            if (!self.write_closed) if (alertFor(e)) |d| {
                const a: alert.Alert = if (d == .close_notify) .close_notify else .fatal(d);
                self.out.write(.alert, &a.encode()) catch {};
            };
            self.state = .failed;
            // An encoder that ran out of room or refused a field left a
            // partial message in the slot, past what `Outbound` saw.
            if (e == error.OutputFull or e == error.InternalError) self.out.touch(self.out.buf.len);
            // A failed handshake reports no identity.
            self.peer_authenticated = false;
            self.out.wipeKey();
            self.inbound.wipe();
            self.wipeHandshakeSecrets();
            std.crypto.secureZero(u8, &self.master_secret);
            std.crypto.secureZero(u8, &self.client_application_secret);
            std.crypto.secureZero(u8, &self.server_application_secret);
            std.crypto.secureZero(u8, &self.exporter_master_secret);
        }
        return e;
    }

    /// The event a handshake message ends with, if any.
    fn onHandshake(self: *Server, m: inbound.HandshakeMessage) Error!?Event {
        const t: messages.HandshakeType = @fromBackingInt(m.msg_type);
        switch (self.state) {
            .client_hello, .client_hello_retry => {
                if (t != .client_hello) return error.UnexpectedMessage;
                try burn.run(burn.handshake_burn, Error!void, onClientHello, .{ self, m });
                if (self.state == .server_signature) return .signature_needed;
                return if (self.state == .early_data or self.quic_early) .early_data_accepted else null;
            },
            // The client has nothing to send before the server's Finished
            // (QUIC: `feed` takes nothing in this state).
            .server_signature => return error.UnexpectedMessage,
            .early_data => {
                if (t != .end_of_early_data) return error.UnexpectedMessage;
                try self.onEndOfEarlyData(m);
                return null;
            },
            // No secret is touched: the chain and the signature are public.
            .client_certificate => {
                if (t != .certificate) return error.UnexpectedMessage;
                try self.onClientCertificate(m);
                return null;
            },
            .client_certificate_verify => {
                if (t != .certificate_verify) return error.UnexpectedMessage;
                try self.onClientCertificateVerify(m);
                return null;
            },
            .client_finished => {
                if (t != .finished) return error.UnexpectedMessage;
                try burn.run(burn.handshake_burn, Error!void, onClientFinished, .{ self, m });
                return .handshake_done;
            },
            // Of the post-handshake messages a client sends only KeyUpdate
            // (no post-handshake authentication is requested).
            .connected => {
                // RFC 9001 §6: QUIC updates its keys itself; a TLS KeyUpdate
                // is a connection error.
                if (t != .key_update or self.config.quic != null) return error.UnexpectedMessage;
                try self.onKeyUpdate(m);
                return null;
            },
            .failed => unreachable,
        }
    }

    /// RFC 8446 §4.5: the early data ends; the client's next messages come
    /// under its handshake secret. It must end its record (`installRx`
    /// refuses held octets: BoGo `PartialEndOfEarlyDataWithClientHello`).
    /// No secret is derived: the handshake secret is installed as is.
    fn onEndOfEarlyData(self: *Server, m: inbound.HandshakeMessage) Error!void {
        if (m.body.len != 0) return error.DecodeError;
        self.appendTranscript(m);
        const L = self.suite.hashLen() orelse unreachable;
        self.inbound.installRx(self.suite, self.client_handshake_secret[0..L]) catch |err| return switch (err) {
            error.UnexpectedMessage => error.UnexpectedMessage,
            else => error.InternalError,
        };
        self.inbound.early_data_ok = false;
        self.state = .client_finished;
    }

    /// RFC 8446 §4.6.3: the client's next messages come under its next
    /// application secret. It must end its record (rustls
    /// `check_aligned_handshake`; `installRx` refuses held octets).
    fn onKeyUpdate(self: *Server, m: inbound.HandshakeMessage) Error!void {
        if (m.body.len != 1) return error.DecodeError;
        if (self.key_updates_left == 0) return error.TooManyKeyUpdates;
        self.key_updates_left -= 1;
        const request = std.enums.fromInt(KeyUpdateRequest, m.body[0]) orelse return error.IllegalParameter;
        const secret = self.nextSecret(&self.client_application_secret);
        self.inbound.installRx(self.suite, secret) catch |err| return switch (err) {
            error.UnexpectedMessage => error.UnexpectedMessage,
            else => error.InternalError,
        };
        // After close_notify nothing is sent, a KeyUpdate included.
        if (request == .update_requested and self.tx_update == null and !self.write_closed) {
            self.tx_update = .update_not_requested;
            try self.flushKeyUpdate();
        }
    }

    /// The client's share for `group`, if any, after checking every share:
    /// one per group, each for a group in supported_groups. Out of line:
    /// its 8 KiB bitset of the groups seen (any u16 may come) would deepen
    /// `onClientHello`'s frame, and every secret-holding frame below it,
    /// past `burn.handshake_burn` (stack probe, 2026-10-21). Public data
    /// only, so its own frame needs no burn.
    noinline fn findShare(shares_in: hello.KeyShareIter, gs: hello.U16Iter, group: u16) Error!?[]const u8 {
        var shares = shares_in;
        var seen: std.StaticBitSet(1 << 16) = .empty;
        var share: ?[]const u8 = null;
        while (shares.next()) |e| {
            if (seen.isSet(e.group)) return error.IllegalParameter;
            seen.set(e.group);
            // RFC 8446 §4.2.8: a share only for a group in supported_groups
            // (the server MAY check; rustls does not), and never for an
            // obsolete_RESERVED one (§4.2.7: "MUST NOT be offered or
            // negotiated by TLS 1.3 implementations"). Obsolete groups in
            // supported_groups alone are let through: JDK 11 lists sect*
            // and secp256k1 beside TLS 1.3 (BoGo `Server-JDK11-*`), so the
            // stricter tlsfuzzer `test-tls13-obsolete-curves` would cut it off.
            if (!gs.contains(e.group) or isObsoleteGroup(e.group)) return error.IllegalParameter;
            if (e.group == group) share = e.key_exchange;
        }
        return share;
    }

    fn onClientHello(self: *Server, m: inbound.HandshakeMessage) Error!void {
        const cfg = self.config;
        const retried = self.state == .client_hello_retry;
        // Out of line, as `findShare`: the parse keeps an 8 KiB bitset of
        // the extension types seen, which inlined here put every frame
        // below this one (kex, signing, the key schedule) 8 KiB deeper.
        const ch = @call(.never_inline, hello.parseClientHello, .{m.body}) catch |err| return switch (err) {
            error.DecodeError => error.DecodeError,
            error.IllegalParameter => error.IllegalParameter,
        };
        if (std.mem.indexOfScalar(u8, ch.legacy_compression_methods, 0) == null) return error.IllegalParameter;
        var sni: ?[]const u8 = null;
        if (ch.server_name) |sn| switch (sn) {
            .dns_name => |n| sni = n,
            .ip_address => {},
            .invalid => return error.IllegalParameter,
        };
        // rustls `ServerNameDifferedOnRetry`.
        if (retried and !optEql(sni, self.serverName())) return error.IllegalParameter;
        // RFC 8449: the client's record size limit (not in QUIC, which has
        // no records). A second hello repeats the first's (RFC 8446 §4.1.2:
        // only the listed changes; tlsfuzzer `test-record-size-limit`).
        const record_limit: ?u16 = if (cfg.quic != null) null else ch.record_size_limit;
        if (retried and !std.meta.eql(record_limit, self.peer_record_limit)) return error.IllegalParameter;
        self.peer_record_limit = record_limit;
        // The version first: a TLS 1.2 (or older) client gets
        // `protocol_version` whatever else its hello lacks (rustls order).
        // A legacy_version below TLS 1.0 (SSL 3.0, or not a version at all)
        // is refused even beside 0x0304 (RFC 8446 §D.5, RFC 7568; OpenSSL,
        // tlsfuzzer `test-tls13-legacy-version`; rustls ignores it).
        if (ch.legacy_version < 0x0301) return error.ProtocolVersion;
        const versions = ch.supportedVersions() orelse return error.ProtocolVersion;
        if (!versions.contains(messages.tls13_version)) return error.ProtocolVersion;
        const sig_algs = ch.signatureAlgorithms() orelse return error.HandshakeFailure;

        const ck: *const CertifiedKey = switch (cfg.certificate) {
            .fixed => |k| k,
            .select => |s| s.select(s.ctx, sni, &ch) orelse return error.AccessDenied,
        };
        ck.check() catch return error.InternalError;
        if (cfg.client_auth) |ca| if (self.peer_buf.len < peerBufferLen(ca.max_leaf_len)) return error.InternalError;
        // RFC 7250, in rustls's terms: each side's type is the one this
        // server requires, if the client can do it. On every hello, a
        // resuming one included (rustls too): a client resuming with a
        // raw-key server must offer RawPublicKey again.
        self.server_cert_type = try negotiateCertType(ck.raw_public_key, ch.server_certificate_types);
        self.client_cert_type = try negotiateCertType(if (cfg.client_auth) |ca| ca.raw_public_keys != null else false, ch.client_certificate_types);
        if (cfg.quic != null) {
            // RFC 9001 §8.2: transport parameters are mandatory; §8.4: no
            // middlebox compatibility mode (rustls: illegal_parameter).
            if (ch.quic_transport_parameters == null) return error.MissingExtension;
            if (ch.legacy_session_id.len != 0) return error.IllegalParameter;
            self.quic_peer_params = ch.quic_transport_parameters;
        }
        const scheme = chooseScheme(ck, &sig_algs) orelse return error.HandshakeFailure;

        var suite: record.CipherSuite = chooseSuite(cfg, &ch) orelse return error.HandshakeFailure;
        // RFC 8446 §4.1.4: the ServerHello repeats the HelloRetryRequest's
        // suite, so the second hello must still offer it (stricter than
        // rustls, which re-chooses and compares only the hash: a client
        // would abort on the change anyway).
        if (retried) {
            if (!ch.cipherSuites().contains(@backingInt(self.suite))) return error.IllegalParameter;
            suite = self.suite;
        }
        // RFC 8446 §9.2: supported_groups and key_share come together.
        const gs = ch.supportedGroups() orelse return error.MissingExtension;
        var group: u16 = chooseGroup(cfg, gs) orelse return error.HandshakeFailure;
        // RFC 8446 §4.2.8: the second hello's share is for the group asked
        // for, whatever its supported_groups now prefer (rustls re-chooses).
        if (retried) group = self.group;

        if (ch.legacy_compression_methods.len != 1) return error.IllegalParameter;
        const shares = ch.keyShares() orelse return error.MissingExtension;
        const share = try findShare(shares, gs, group);
        // RFC 8446 §4.2.10: no early data after a HelloRetryRequest.
        if (retried and ch.early_data) return error.IllegalParameter;
        const client_share = share orelse {
            // rustls `RefusedToFollowHelloRetryRequest`.
            if (retried) return error.IllegalParameter;
            return self.helloRetry(m.raw, &ch, suite, group, sni);
        };
        // RFC 8446 §4.2.9.
        if (ch.pre_shared_key != null and ch.psk_key_exchange_modes == null) return error.MissingExtension;
        if (!retried) self.startTranscript(suite);

        // A ticket's PSK (rustls: before ALPN, so a bad binder is
        // decrypt_error whatever else fails). Without psk_dhe_ke neither
        // resumption nor tickets (the only mode served).
        var psk_buf: [48]u8 = undefined;
        defer std.crypto.secureZero(u8, &psk_buf);
        var psk: ?[]const u8 = null;
        var selected: ?u16 = null;
        var taken: PskTaken = .{};
        if (cfg.tickets) |tk| {
            if (ch.pre_shared_key) |offer| {
                const took = switch (suite) {
                    .aes_256_gcm_sha384 => try self.choosePsk(S384, tk, m.body, offer, suite, sni, &psk_buf, &taken),
                    else => try self.choosePsk(S256, tk, m.body, offer, suite, sni, &psk_buf, &taken),
                };
                if (took) selected = taken.index;
            }
            const modes = ch.psk_key_exchange_modes orelse "";
            if (std.mem.indexOfScalar(u8, modes, psk_dhe_ke) != null) {
                self.tickets_due = if (tk.lifetime_s == 0) 0 else tk.count;
                if (selected != null) psk = psk_buf[0 .. suite.hashLen() orelse unreachable];
            } else selected = null;
        }
        self.resumed = selected != null;
        if (!self.resumed) {
            self.peer_len = 0;
            self.peer_scheme = 0;
            self.peer_auth_ms = 0;
        }
        self.peer_authenticated = self.peer_len != 0;

        if (ch.alpn()) |theirs| {
            for (cfg.alpn_protocols) |ours| {
                var it = theirs;
                while (it.next()) |p| if (std.mem.eql(u8, p, ours)) {
                    self.alpn = ours;
                    break;
                };
                if (self.alpn != null) break;
            }
            if (self.alpn == null and (cfg.alpn_protocols.len != 0 or cfg.quic != null)) return error.NoApplicationProtocol;
        }
        // RFC 9001 §8.1: QUIC agrees on an application protocol, or fails
        // (rustls `NoApplicationProtocol` too).
        if (cfg.quic != null and self.alpn == null) return error.NoApplicationProtocol;
        self.setServerName(sni);

        var ex: kex.ServerExchange = undefined;
        defer std.crypto.secureZero(u8, &ex.shared.bytes);
        // A share that does not exchange (wrong length, low order, off the
        // curve) is the peer's fault; a group this build cannot compute
        // being enabled is the configuration's.
        kex.serverExchange(group, client_share, cfg.random, &ex) catch |err| return switch (err) {
            error.KeyExchangeFailed => error.IllegalParameter,
            error.MissingKeyShare => if (kex.expectedShareLen(group) != 0) error.IllegalParameter else error.InternalError,
        };
        // After the exchange: a share refused does not spend the ticket's
        // single use in the replay guard (a `CacheTicketer`'s ticket was
        // spent when `choosePsk` opened it).
        // A QUIC resumption: the stack's data from the ticket.
        self.quic_received_len = if (selected != null and cfg.quic != null) taken.app_len orelse 0 else null;
        if (self.quic_received_len) |n| @memcpy(self.quic_received[0..n], taken.app_buf[0..n]);
        self.early_reason = self.decideEarlyData(&ch, selected != null, &taken);
        const early = self.early_reason == .accepted;

        self.suite = suite;
        self.has_suite = true;
        self.group = group;
        switch (suite) {
            .aes_256_gcm_sha384 => try self.serverFlight(S384, m.raw, &ch, ck, scheme, group, &ex, !retried, psk, selected, early),
            else => try self.serverFlight(S256, m.raw, &ch, ck, scheme, group, &ex, !retried, psk, selected, early),
        }
        // An offloaded signature (a full handshake: never with early data).
        const next: State = if (cfg.client_auth != null and psk == null) .client_certificate else .client_finished;
        if (self.sign_key != null) {
            std.debug.assert(!early);
            self.inbound.skip_early = if (ch.early_data) skipBudget(cfg) else 0;
            self.after_signature = next;
            self.state = .server_signature;
            return;
        }
        if (early and cfg.quic != null) {
            // RFC 9001 §8.3: no EndOfEarlyData; 0-RTT packets are the QUIC
            // stack's, under `quicSecret(.read, .early)`.
            self.quic_early = true;
        } else if (early) {
            self.inbound.early_data_ok = true;
            // The ticket's promise, or less if the server now takes less.
            self.early_left = @min(cfg.early_data.?.max_size, taken.max_early_data);
            self.state = .early_data;
            return;
        }
        // Early data the client may have sent under a PSK we did not take
        // (never after a retry: refused above).
        self.inbound.skip_early = if (ch.early_data) skipBudget(cfg) else 0;
        self.state = next;
    }

    /// Early data refused is skipped up to 2^14 octets of ciphertext, or
    /// `EarlyData.max_size` if that is more (rustls skips the configured
    /// size, 2^14 without one; BoringSSL always 2^14). Ciphertext: a client
    /// sending its `max_size` in many small records can run past it (each
    /// costs 17 octets more) and is then refused, as with rustls.
    fn skipBudget(cfg: *const Config) usize {
        const max: usize = if (cfg.early_data) |ed| ed.max_size else 0;
        return @max(record.max_plaintext_len, max);
    }

    /// RFC 8446 §4.2.10 and §8, in BoringSSL's order of reasons: early data
    /// is taken on a resumption of the first identity offered, with the
    /// ticket's ALPN protocol, a fresh reported age and no HelloRetryRequest
    /// (the suite and the version are the ticket's already: `Resumable`) —
    /// then the replay guard is asked, and only then (it remembers).
    fn decideEarlyData(self: *Server, ch: *const hello.ClientHello, resumed: bool, taken: *const PskTaken) EarlyDataReason {
        const cfg = self.config;
        const ed = cfg.early_data orelse return .disabled;
        const tk = cfg.tickets orelse return .disabled;
        if (ed.max_size == 0) return .disabled;
        if (ch.pre_shared_key == null) return .no_session_offered;
        if (!resumed) return .session_not_resumed;
        // BoringSSL decides on the first ClientHello, which the retry answered.
        if (self.early_hrr) return .hello_retry_request;
        if (!ch.early_data) return .peer_declined;
        if (taken.max_early_data == 0) return .unsupported_for_session;
        if (taken.index != 0) return .not_first_identity;
        if (!optEql(taken.alpn(), self.alpn)) return .alpn_mismatch;
        if (@abs(self.age_skew_s) > ed.max_age_skew_s) return .ticket_age_skew;
        // RFC 9001 §4.6.2: 0-RTT only where the transport parameters the
        // ticket remembers still hold — the QUIC stack's call.
        if (cfg.quic) |q| if (q.accept_early) |a| if (!a.accept(a.ctx, taken.app())) return .quic_parameter_mismatch;
        if (!ed.replay.admit(ed.replay.ctx, taken.identity, tk.clock.now_ms(tk.clock.ctx))) return .replayed;
        return .accepted;
    }

    /// RFC 8446 §4.2.11 through `tlsresume.select.selectPsk`: whether a
    /// ticket was taken; its PSK in `psk_out`, the rest in `taken`.
    fn choosePsk(
        self: *Server,
        comptime H: type,
        tk: *const Tickets,
        body: []const u8,
        offer: hello.PreSharedKey,
        suite: record.CipherSuite,
        sni: ?[]const u8,
        psk_out: *[48]u8,
        taken: *PskTaken,
    ) Error!bool {
        const L = H.len;
        var ids: [max_psk_identities]tlsresume.select.OfferedIdentity = undefined;
        var binders: [max_psk_identities][L]u8 = undefined;
        var n: usize = 0;
        var it = offer.identities();
        var bt = offer.binders();
        while (n < max_psk_identities) : (n += 1) {
            const id = it.next() orelse break;
            // As many binders as identities (`hello` checked it). A binder
            // of the wrong length never verifies: for a ticket we would
            // take, that is decrypt_error (rustls).
            const b = bt.next().?;
            ids[n] = .{ .ticket = id.identity, .obfuscated_ticket_age = id.obfuscated_ticket_age };
            binders[n] = if (b.len == L) b[0..L].* else @splat(0);
        }
        // §4.2.11.2: the transcript through the ClientHello up to its
        // binders (after a HelloRetryRequest, message_hash and the HRR too).
        const th = H.transcript(&self.transcript).wouldBeHash(@backingInt(messages.HandshakeType.client_hello), body.len, body[0..offer.binders_offset]);
        const empty_hash = tls13.keyschedule.emptyTranscriptHash(H.Hash);

        const now_ms = tk.clock.now_ms(tk.clock.ctx);
        var want: Resumable = .{
            .suite = @backingInt(suite),
            .sni = sni,
            .lifetime_ms = @as(i64, @min(tk.lifetime_s, max_ticket_lifetime_s)) * 1000,
            .now_ms = now_ms,
            .need_peer = if (self.config.client_auth) |ca| ca.mandatory else false,
            .peer_raw = self.client_cert_type == cert_type_raw_public_key,
            .quic = self.config.quic != null,
            .max_peer = if (self.config.client_auth) |ca| ca.max_leaf_len else 0,
        };
        const ring: TicketerRing = .{ .t = tk.ticketer };
        // Opened in the peer buffer (no leaf there yet): the taken ticket's
        // leaf is then moved to its place. Every ticket's secret lies before
        // `ticket_head_len`.
        var no_peer: [ticket_head_len + TicketFields.tail_len]u8 = undefined;
        const scratch: []u8 = if (self.peer_buf.len >= no_peer.len) self.peer_buf else &no_peer;
        defer zeroize(scratch[0..ticket_head_len]);
        var sel: tlsresume.select.Selection(L) = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&sel));
        tlsresume.select.selectPsk(H.Hkdf, H.Hmac, TicketerRing, &sel, &ring, .{}, ids[0..n], binders[0..n], empty_hash, &th, now_ms, null, null, .{ .ctx = &want, .accept = Resumable.accept }, scratch) catch |err| return switch (err) {
            error.NoAcceptableIdentity => false,
            error.BinderMismatch => error.DecryptError,
        };
        taken.index = @intCast(sel.selected_index);
        taken.identity = ids[sel.selected_index].ticket;
        taken.alpn_len = null;
        taken.max_early_data = want.max_early_data;
        if (want.alpn) |p| {
            @memcpy(taken.alpn_buf[0..p.len], p);
            taken.alpn_len = @intCast(p.len);
        }
        taken.app_len = null;
        if (want.app) |a| {
            @memcpy(taken.app_buf[0..a.len], a);
            taken.app_len = @intCast(a.len);
        }
        @memcpy(psk_out[0..L], &sel.psk);
        const reported_ms = ids[sel.selected_index].obfuscated_ticket_age -% sel.session.ticket_age_add;
        self.age_skew_s = @as(i64, reported_ms / 1000) - @divTrunc(now_ms - sel.session.issued_at_ms, 1000);
        // The ticket's client certificate (in `scratch`, which `selectPsk`
        // last opened the taken ticket into). Kept even if the psk modes
        // then refuse the resumption: `peer_authenticated` decides.
        if (want.peer) |p| {
            // `parse` bounded it by the cap, which the buffer holds.
            const dst = self.peer_buf[ticket_head_len..][0..p.len];
            if (@intFromPtr(dst.ptr) > @intFromPtr(p.ptr)) std.mem.copyBackwards(u8, dst, p) else std.mem.copyForwards(u8, dst, p);
            self.peer_len = @intCast(p.len);
            self.peer_raw = want.peer_raw;
            self.peer_scheme = want.peer_scheme;
            self.peer_auth_ms = want.peer_auth_ms;
        }
        return true;
    }

    /// RFC 7250 §4.2 as rustls decides it: RawPublicKey when this server
    /// requires it and the client offers it, X.509 when it does not require
    /// it and the client offers X.509; null when the client sent no list
    /// (X.509, nothing echoed); anything else `handshake_failure`.
    fn negotiateCertType(requires_raw: bool, offered: ?[]const u8) Error!?u8 {
        const list = offered orelse return if (requires_raw) error.HandshakeFailure else null;
        const raw = std.mem.indexOfScalar(u8, list, cert_type_raw_public_key) != null;
        const x = std.mem.indexOfScalar(u8, list, cert_type_x509) != null;
        if (requires_raw) return if (raw) cert_type_raw_public_key else error.HandshakeFailure;
        return if (x) cert_type_x509 else error.HandshakeFailure;
    }

    /// The key's first allowed scheme (`CertifiedKey.signature_schemes`
    /// order, else its candidates') that the client offers and it can sign.
    fn chooseScheme(ck: *const CertifiedKey, offered: *const hello.U16Iter) ?certverify.SignatureScheme {
        const key = ck.key orelse {
            // Offloaded: the signer's list, of the schemes `certverify` knows.
            const o = ck.offload orelse return null;
            for (o.schemes) |p| if (offered.contains(p) and certverify.maxSignatureLen(@fromBackingInt(p)) != 0) return @fromBackingInt(p);
            return null;
        };
        const candidates = certverify.candidateSchemes(key);
        if (ck.signature_schemes) |prefs| {
            for (prefs) |p| for (candidates) |s| {
                if (@backingInt(s) == p and offered.contains(p) and certverify.canSign(key, s)) return s;
            };
            return null;
        }
        for (candidates) |s| if (offered.contains(@backingInt(s)) and certverify.canSign(key, s)) return s;
        return null;
    }

    /// The first suite in the deciding order that both sides enable.
    fn chooseSuite(cfg: *const Config, ch: *const hello.ClientHello) ?record.CipherSuite {
        if (cfg.server_order) {
            // An unknown enabled suite (the enum is open) is never chosen.
            for (cfg.cipher_suites) |c| if (c.hashLen() != null and ch.cipherSuites().contains(@backingInt(c))) return c;
            return null;
        }
        var cs = ch.cipherSuites();
        while (cs.next()) |c| {
            const cand: record.CipherSuite = @fromBackingInt(c);
            if (cand.hashLen() != null and std.mem.indexOfScalar(record.CipherSuite, cfg.cipher_suites, cand) != null) return cand;
        }
        return null;
    }

    /// The first group in the deciding order that both sides support.
    /// RFC 8446 §4.2.7 `obsolete_RESERVED`: the TLS 1.2 binary and prime
    /// curves (0x0001–0x0016), brainpool r1 (0x001A–0x001C) and the
    /// explicit-curve codes (0xFF01, 0xFF02).
    fn isObsoleteGroup(g: u16) bool {
        return (g >= 0x0001 and g <= 0x0016) or (g >= 0x001a and g <= 0x001c) or g == 0xff01 or g == 0xff02;
    }

    fn chooseGroup(cfg: *const Config, theirs: hello.U16Iter) ?u16 {
        if (cfg.server_order) {
            for (cfg.groups) |g| if (theirs.contains(g)) return g;
            return null;
        }
        var it = theirs;
        while (it.next()) |g| if (std.mem.indexOfScalar(u16, cfg.groups, g) != null) return g;
        return null;
    }

    fn optEql(a: ?[]const u8, b: ?[]const u8) bool {
        if (a == null or b == null) return a == null and b == null;
        return std.mem.eql(u8, a.?, b.?);
    }

    fn setServerName(self: *Server, sni: ?[]const u8) void {
        if (sni) |n| {
            @memcpy(self.sni_buf[0..n.len], n);
            self.sni_len = @intCast(n.len);
        } else self.sni_len = null;
    }

    fn startTranscript(self: *Server, suite: record.CipherSuite) void {
        self.transcript = switch (suite) {
            .aes_256_gcm_sha384 => .{ .sha384 = .{} },
            else => .{ .sha256 = .{} },
        };
    }

    /// RFC 8446 §4.1.4: ask for a share of `group`. The transcript becomes
    /// `message_hash(Hash(ClientHello1)) ‖ HelloRetryRequest` (§4.4.1).
    fn helloRetry(
        self: *Server,
        client_hello_raw: []const u8,
        ch: *const hello.ClientHello,
        suite: record.CipherSuite,
        group: u16,
        sni: ?[]const u8,
    ) Error!void {
        // rustls `check_aligned_handshake`: nothing of the next flight may
        // ride with the first ClientHello.
        if (!self.inbound.joiner.isEmpty()) return error.UnexpectedMessage;
        self.startTranscript(suite);
        self.suite = suite;
        self.has_suite = true;
        self.group = group;
        self.retried = true;
        self.early_hrr = ch.early_data;
        self.setServerName(sni);
        switch (suite) {
            .aes_256_gcm_sha384 => try self.sendRetry(S384, client_hello_raw, ch),
            else => try self.sendRetry(S256, client_hello_raw, ch),
        }
        try self.out.write(.change_cipher_spec, &.{1});
        // One compatibility CCS per ClientHello (rustls).
        self.inbound.ccs_left += 1;
        // RFC 8446 §4.2.10: the client's early data is skipped up to the
        // budget (rustls: 16 KiB when the server takes none).
        self.inbound.skip_early = if (ch.early_data) skipBudget(self.config) else 0;
        self.state = .client_hello_retry;
    }

    fn sendRetry(self: *Server, comptime H: type, client_hello_raw: []const u8, ch: *const hello.ClientHello) Error!void {
        const t = H.transcript(&self.transcript);
        t.append(client_hello_raw[0], client_hello_raw[4..]);
        t.resetToMessageHash(t.currentHash());
        try self.send(H, try encoded(messages.helloRetryRequest(self.out.slot(), .{
            .legacy_session_id_echo = ch.legacy_session_id,
            .cipher_suite = @backingInt(self.suite),
            .selected_group = self.group,
        })));
    }

    /// Frame the message just encoded at the start of the output slot and
    /// add it to the transcript.
    fn send(self: *Server, comptime H: type, msg: []const u8) Error!void {
        H.transcript(&self.transcript).append(msg[0], msg[4..]);
        try self.out.commit(.handshake, msg.len);
    }

    fn encoded(r: messages.Error![]u8) Error![]u8 {
        return r catch |err| switch (err) {
            error.BufferTooSmall => error.OutputFull,
            error.FieldTooLong => error.InternalError,
        };
    }

    fn serverFlight(
        self: *Server,
        comptime H: type,
        client_hello_raw: []const u8,
        ch: *const hello.ClientHello,
        ck: *const CertifiedKey,
        scheme: certverify.SignatureScheme,
        group: u16,
        ex: *const kex.ServerExchange,
        /// The compatibility CCS, unless it followed a HelloRetryRequest.
        ccs: bool,
        /// A resumption: the PSK and the identity it came from.
        psk: ?[]const u8,
        selected_identity: ?u16,
        /// The client's early data is taken (`decideEarlyData`).
        early: bool,
    ) Error!void {
        const cfg = self.config;
        const t = H.transcript(&self.transcript);
        t.append(client_hello_raw[0], client_hello_raw[4..]);
        // RFC 8446 §7.1: client_early_traffic_secret over the ClientHello.
        const ch_hash = if (early) t.currentHash() else undefined;

        var random: [32]u8 = undefined;
        cfg.random.bytes(&random);
        try self.send(H, try encoded(messages.serverHello(self.out.slot(), .{
            .random = &random,
            .legacy_session_id_echo = ch.legacy_session_id,
            .cipher_suite = @backingInt(self.suite),
            .key_share = .{ .group = group, .key_exchange = ex.public[0..ex.public_len] },
            .selected_identity = selected_identity,
        })));
        if (ccs) try self.out.write(.change_cipher_spec, &.{1});

        // RFC 8446 §7.1: the PSK, or zeros (whose early secret's salt is a
        // constant).
        const L = H.len;
        const empty_hash = tls13.keyschedule.emptyTranscriptHash(H.Hash);
        var early_secret: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &early_secret);
        const hs = self.handshake_secret[0..L];
        if (psk) |k| {
            tls13.keyschedule.earlySecret(H.Hkdf, &early_secret, k);
            ks.deriveHandshakeSecret(H.Hkdf, hs, &early_secret, empty_hash, ex.shared.slice());
        } else {
            ks.deriveHandshakeSecretNoPsk(H.Hkdf, hs, ex.shared.slice());
        }
        var server_hs: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &server_hs);
        var th = t.currentHash();
        ks.deriveHandshakeTrafficSecrets(H.Hkdf, self.client_handshake_secret[0..L], &server_hs, hs, &th);
        self.out.installTx(self.suite, &server_hs) catch return error.InternalError;
        // RFC 8449 §4: every protected record within the client's limit,
        // which counts the content type octet in TLS 1.3 (2^14 + 1 at most).
        if (self.peer_record_limit) |l| self.out.max_fragment = @min(self.out.max_fragment, @min(l, record.max_plaintext_len + 1) - 1);
        // The client goes on under its early secret until EndOfEarlyData
        // (`onEndOfEarlyData` installs the handshake one), or at once under
        // its handshake secret.
        var client_early: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &client_early);
        if (early) ks.deriveSecret(H.Hkdf, &client_early, &early_secret, "c e traffic", &ch_hash);
        if (self.config.quic != null) {
            @memcpy(self.quic_server_hs[0..L], &server_hs);
            if (early) @memcpy(self.quic_client_early[0..L], &client_early);
        }
        const rx: []const u8 = if (early and self.config.quic == null) &client_early else self.client_handshake_secret[0..L];
        self.inbound.installRx(self.suite, rx) catch |err| return switch (err) {
            error.UnexpectedMessage => error.UnexpectedMessage,
            else => error.InternalError,
        };

        // EncryptedExtensions.
        var alpn_body: [2 + 1 + 255]u8 = undefined;
        var exts: [7]messages.Extension = undefined;
        var n_exts: usize = 0;
        // RFC 8449 §4: what this server takes, 2^14 + 1 in TLS 1.3.
        const own_limit = comptime std.mem.toBytes(std.mem.nativeToBig(u16, record.max_plaintext_len + 1));
        if (self.peer_record_limit != null) {
            exts[n_exts] = .{ .type = @backingInt(hello.ExtensionType.record_size_limit), .data = &own_limit };
            n_exts += 1;
        }
        if (cfg.quic) |q| {
            exts[n_exts] = .{ .type = @backingInt(hello.ExtensionType.quic_transport_parameters), .data = q.transport_parameters };
            n_exts += 1;
        }
        // RFC 7250 §4.2: each type only with the message it governs — the
        // server's with its Certificate, the client's with the
        // CertificateRequest.
        var server_type: [1]u8 = undefined;
        var client_type: [1]u8 = undefined;
        if (psk == null) {
            if (self.server_cert_type) |st| {
                server_type[0] = st;
                exts[n_exts] = .{ .type = @backingInt(hello.ExtensionType.server_certificate_type), .data = &server_type };
                n_exts += 1;
            }
            if (cfg.client_auth != null) if (self.client_cert_type) |ct| {
                client_type[0] = ct;
                exts[n_exts] = .{ .type = @backingInt(hello.ExtensionType.client_certificate_type), .data = &client_type };
                n_exts += 1;
            };
        }
        if (self.alpn) |p| {
            exts[n_exts] = .{ .type = 16, .data = try encoded(messages.alpnData(&alpn_body, p)) };
            n_exts += 1;
        }
        // RFC 6066 §3: not when resuming (rustls).
        if (self.sni_len != null and psk == null) {
            exts[n_exts] = .{ .type = 0, .data = "" };
            n_exts += 1;
        }
        // RFC 8446 §4.2.10: the early data is taken.
        if (early) {
            exts[n_exts] = .{ .type = @backingInt(hello.ExtensionType.early_data), .data = "" };
            n_exts += 1;
        }
        try self.send(H, try encoded(messages.encryptedExtensions(self.out.slot(), exts[0..n_exts])));

        // A resumption authenticates with the PSK (RFC 8446 §2.2).
        if (psk == null) {
            if (cfg.client_auth) |ca| try self.send(H, try encoded(messages.certificateRequest(self.out.slot(), .{
                .signature_algorithms = ca.schemes,
                .authorities = ca.authorities,
            })));

            // Certificate, with the OCSP staple and the SCT list on the
            // leaf if the client asked (`check` bounded the chain), or the
            // same compressed (RFC 8879: the CompressedCertificate is what
            // the transcript hashes).
            const staples = ck.staplesFor(ch);
            if (ck.compressedFor(ch, staples)) |c| {
                try self.send(H, try encoded(messages.compressedCertificate(self.out.slot(), c.algorithm, c.uncompressed_len, c.data)));
            } else {
                var entries: [CertifiedKey.max_chain_len]messages.CertificateEntry = undefined;
                const m = ck.certificateMessage(self.out.slot(), &entries, staples) catch |err| return switch (err) {
                    error.BufferTooSmall => error.OutputFull,
                    error.FieldTooLong, error.InvalidStaples => error.InternalError,
                };
                try self.send(H, m);
            }

            // CertificateVerify over the transcript through Certificate.
            th = t.currentHash();
            const key = ck.key orelse {
                // Offloaded: the rest waits for `provideSignature`.
                const content = certverify.buildSignedContent(.server, &th, &self.sign_content) catch unreachable;
                self.sign_len = @intCast(content.len);
                self.sign_scheme = @backingInt(scheme);
                self.sign_key = ck;
                @memcpy(self.sign_server_hs[0..L], &server_hs);
                return;
            };
            var sig_buf: [certverify.max_signature_len]u8 = undefined;
            const sig = certverify.sign(scheme, key, .server, &th, cfg.random, &sig_buf) catch return error.InternalError;
            try self.send(H, try encoded(messages.certificateVerify(self.out.slot(), @backingInt(scheme), sig)));
        }
        try self.finishFlight(H, &server_hs);
    }

    /// The server's Finished, then the application secrets over the
    /// transcript through it; the server sends under its application key
    /// from here.
    fn finishFlight(self: *Server, comptime H: type, server_hs: *const [H.len]u8) Error!void {
        const L = H.len;
        const t = H.transcript(&self.transcript);
        const empty_hash = tls13.keyschedule.emptyTranscriptHash(H.Hash);
        const hs = self.handshake_secret[0..L];
        var th = t.currentHash();
        var finished_key: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &finished_key);
        ks.deriveFinishedKey(H.Hkdf, L, &finished_key, server_hs);
        var verify_data: [L]u8 = undefined;
        tls13.keyschedule.computeFinishedVerifyData(H.Hmac, &verify_data, &finished_key, &th);
        try self.send(H, try encoded(messages.finished(self.out.slot(), &verify_data)));

        // Application secrets over the transcript through the server's
        // Finished; the server sends under its application key from here.
        const ms = self.master_secret[0..L];
        ks.deriveMasterSecret(H.Hkdf, ms, hs, empty_hash);
        th = t.currentHash();
        ks.deriveApplicationSecrets(H.Hkdf, self.client_application_secret[0..L], self.server_application_secret[0..L], self.exporter_master_secret[0..L], ms, &th);
        self.out.installTx(self.suite, self.server_application_secret[0..L]) catch return error.InternalError;
    }

    fn appendTranscript(self: *Server, m: inbound.HandshakeMessage) void {
        switch (self.transcript) {
            inline else => |*t| t.append(m.msg_type, m.body),
        }
    }

    /// RFC 8446 §4.4.2.4: the client's chain, to the verifier. Its leaf is
    /// kept for the CertificateVerify and `peerCertificate`.
    fn onClientCertificate(self: *Server, m: inbound.HandshakeMessage) Error!void {
        const ca = self.config.client_auth.?;
        const c = clientauth.parseCertificate(m.body, "") catch |err| return switch (err) {
            error.DecodeError => error.DecodeError,
            error.IllegalParameter => error.IllegalParameter,
            error.UnsupportedExtension => error.UnsupportedExtension,
        };
        if (c.isEmpty()) {
            if (ca.mandatory) return error.CertificateRequired;
            self.appendTranscript(m);
            self.state = .client_finished;
            return;
        }
        var chain: [clientauth.max_chain_len][]const u8 = undefined;
        var n: usize = 0;
        var it = c.certificates();
        while (it.next()) |der| : (n += 1) {
            if (n == chain.len) return error.BadCertificate;
            chain[n] = der;
        }
        if (chain[0].len > ca.max_leaf_len) return error.BadCertificate;
        if (self.client_cert_type == cert_type_raw_public_key) {
            // RFC 7250 §3: one entry, the SubjectPublicKeyInfo, judged by
            // the raw-key verifier alone.
            if (n != 1) return error.BadCertificate;
            _ = try clientauth.rawPublicKey(chain[0]);
            try ca.raw_public_keys.?.verify(ca.raw_public_keys.?.ctx, chain[0]);
            @memcpy(self.peer_buf[ticket_head_len..][0..chain[0].len], chain[0]);
            self.peer_len = @intCast(chain[0].len);
            self.peer_raw = true;
            self.appendTranscript(m);
            self.state = .client_certificate_verify;
            return;
        }
        // The leaf must be able to sign the CertificateVerify, whatever
        // the verifier says (BoringSSL checks both here, before it). The
        // keyUsage check copies it to its place in the peer buffer.
        _ = try clientauth.leafPublicKey(chain[0]);
        try clientauth.checkLeafKeyUsage(chain[0], self.peer_buf[ticket_head_len..]);
        const now_s = @divFloor(ca.clock.now_ms(ca.clock.ctx), 1000);
        try ca.verifier.verify(ca.verifier.ctx, chain[0..n], now_s);
        self.peer_len = @intCast(chain[0].len);
        self.appendTranscript(m);
        self.state = .client_certificate_verify;
    }

    /// RFC 8446 §4.4.3: the client's signature over the transcript through
    /// its Certificate, under a scheme the server asked for.
    fn onClientCertificateVerify(self: *Server, m: inbound.HandshakeMessage) Error!void {
        const ca = self.config.client_auth.?;
        const cv = clientauth.parseCertificateVerify(m.body) catch return error.DecodeError;
        // rustls `SignedHandshakeWithUnadvertisedSigScheme`.
        if (std.mem.indexOfScalar(u16, ca.schemes, cv.scheme) == null) return error.IllegalParameter;
        const key = try if (self.peer_raw) clientauth.rawPublicKey(self.peerLeaf()) else clientauth.leafPublicKey(self.peerLeaf());
        const scheme: certverify.SignatureScheme = @fromBackingInt(cv.scheme);
        var th_buf: [48]u8 = undefined;
        const th: []const u8 = switch (self.transcript) {
            .sha256 => |*t| blk: {
                th_buf[0..32].* = t.currentHash();
                break :blk th_buf[0..32];
            },
            .sha384 => |*t| blk: {
                th_buf = t.currentHash();
                break :blk &th_buf;
            },
        };
        certverify.verify(scheme, key, .client, th, cv.signature) catch |err| return switch (err) {
            // RSA PKCS#1 v1.5 (offered for the chain only) and any scheme
            // that does not suit the key.
            error.UnsupportedScheme, error.KeyMismatch => error.IllegalParameter,
            error.InvalidSignature => error.DecryptError,
            else => error.InternalError,
        };
        self.peer_authenticated = true;
        self.peer_scheme = cv.scheme;
        if (self.config.tickets) |tk| self.peer_auth_ms = tk.clock.now_ms(tk.clock.ctx);
        self.appendTranscript(m);
        self.state = .client_finished;
    }

    fn onClientFinished(self: *Server, m: inbound.HandshakeMessage) Error!void {
        switch (self.suite) {
            .aes_256_gcm_sha384 => try self.clientFinished(S384, m),
            else => try self.clientFinished(S256, m),
        }
        self.wipeHandshakeSecrets();
        // The tickets are out: nothing needs the master secret any more (it
        // would give every ticket's PSK away).
        std.crypto.secureZero(u8, &self.master_secret);
        self.inbound.app_data_ok = true;
        self.state = .connected;
    }

    fn clientFinished(self: *Server, comptime H: type, m: inbound.HandshakeMessage) Error!void {
        const L = H.len;
        const t = H.transcript(&self.transcript);
        const th = t.currentHash();
        var finished_key: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &finished_key);
        ks.deriveFinishedKey(H.Hkdf, L, &finished_key, self.client_handshake_secret[0..L]);
        var expected: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &expected);
        tls13.keyschedule.computeFinishedVerifyData(H.Hmac, &expected, &finished_key, &th);
        // A verify_data of another length is decrypt_error too (BoringSSL,
        // rustls; BoGo `TrailingMessageData-TLS13-ClientFinished-TLS`).
        // OpenSSL and tlsfuzzer `test-tls13-finished` want decode_error.
        if (m.body.len != L or !std.crypto.timing_safe.eql([L]u8, expected, m.body[0..L].*)) return error.DecryptError;
        t.append(m.msg_type, m.body);
        self.inbound.installRx(self.suite, self.client_application_secret[0..L]) catch |err| return switch (err) {
            error.UnexpectedMessage => error.UnexpectedMessage,
            else => error.InternalError,
        };
        // Nothing is sent after close_notify, which a server writing
        // half-RTT data may have sent before this Finished: the send key is
        // gone, and a ticket would go out in the clear.
        if (self.tickets_due != 0 and !self.write_closed) {
            const through_finished = t.currentHash();
            self.issueTickets(H, &through_finished);
        }
    }

    /// RFC 8446 §4.6.1: `tickets_due` NewSessionTickets, each for its own
    /// PSK (nonce = its index), packed into one flight (BoringSSL; the
    /// runner's `ExpectPackedEncryptedHandshake`), each with an empty GREASE
    /// extension (RFC 8701 §3.2, as BoringSSL). One that cannot be sealed
    /// or has no room is not sent, nor are the rest (rustls sends none it
    /// cannot store).
    fn issueTickets(self: *Server, comptime H: type, th: *const [H.len]u8) void {
        const L = H.len;
        const tk = self.config.tickets.?;
        const Session = tlsresume.select.SessionState(L);
        var state: Session = .{
            .resumption_master_secret = undefined,
            .ticket_nonce = undefined,
            .issued_at_ms = tk.clock.now_ms(tk.clock.ctx),
            .ticket_age_add = undefined,
        };
        defer std.crypto.secureZero(u8, &state.resumption_master_secret);
        ks.deriveResumptionMasterSecret(H.Hkdf, &state.resumption_master_secret, self.master_secret[0..L], th);
        // The plaintext is built around the leaf in the peer buffer; the
        // blob is sealed straight into its place in the output.
        var no_peer: [ticket_head_len + TicketFields.tail_len]u8 = undefined;
        const buf: []u8 = if (self.peer_buf.len >= no_peer.len) self.peer_buf else &no_peer;
        defer zeroize(buf[0..ticket_head_len]);
        const early_ext: usize = if (self.config.early_data) |ed| (if (ed.max_size != 0) 8 else 0) else 0;
        const fields: TicketFields = .{
            .sni = self.serverName(),
            .alpn = self.alpn,
            .peer = self.peerCertificate(),
            .peer_raw = self.peerRawPublicKey(),
            .peer_scheme = self.peerSignatureScheme() orelse 0,
            .peer_auth_ms = self.peer_auth_ms,
            .max_early_data = if (early_ext != 0) self.config.early_data.?.max_size else 0,
            .suite = @backingInt(self.suite),
            .quic = self.config.quic != null,
            .app = if (self.config.quic != null) self.quic_resumption_data else null,
        };
        const prefix_len = Session.wireLen(1);
        const slot = self.out.slot();
        var used: usize = 0;
        for (0..self.tickets_due) |i| {
            const nonce = [1]u8{@intCast(i)};
            state.ticket_nonce = &nonce;
            state.ticket_age_add = self.config.random.int(u32);
            const after = fields.writeAround(buf, ticket_head_len);
            const start = after.ptr - buf.ptr - prefix_len;
            _ = state.serialize(buf[start..][0..prefix_len]) catch unreachable; // sized for it
            const plain = buf[start .. start + prefix_len + after.len];
            var aead_nonce: [12]u8 = undefined;
            self.config.random.bytes(&aead_nonce);
            // NewSessionTicket (RFC 8446 §4.6.1): type, length, lifetime,
            // age_add, nonce<1>, ticket<2>, then early_data (§4.2.10) when
            // early data is taken, and one empty GREASE extension.
            const head = 4 + 4 + 4 + 1 + nonce.len + 2;
            const ext = 2 + early_ext + 4;
            if (slot.len - used < head + 1 + ext) break;
            const room = slot[used + head ..][0..@min(slot.len - used - head - ext, std.math.maxInt(u16))];
            const ticket = tk.ticketer.seal(tk.ticketer.ctx, plain, aead_nonce, room) orelse break;
            if (ticket.len == 0 or ticket.len > room.len) break;
            if (ticket.ptr != room.ptr) std.mem.copyForwards(u8, room[0..ticket.len], ticket);
            const m = slot[used..][0 .. head + ticket.len + ext];
            m[0] = @backingInt(messages.HandshakeType.new_session_ticket);
            std.mem.writeInt(u24, m[1..4], @intCast(m.len - 4), .big);
            std.mem.writeInt(u32, m[4..8], @min(tk.lifetime_s, max_ticket_lifetime_s), .big);
            std.mem.writeInt(u32, m[8..12], state.ticket_age_add, .big);
            m[12] = nonce.len;
            m[13] = nonce[0];
            std.mem.writeInt(u16, m[14..16], @intCast(ticket.len), .big);
            const g: u16 = self.config.random.int(u4);
            var e = m[head + ticket.len ..];
            std.mem.writeInt(u16, e[0..2], @intCast(early_ext + 4), .big);
            e = e[2..];
            if (early_ext != 0) {
                std.mem.writeInt(u16, e[0..2], @backingInt(hello.ExtensionType.early_data), .big);
                std.mem.writeInt(u16, e[2..4], 4, .big);
                // RFC 9001 §4.6.1: over QUIC the field only says "0-RTT
                // allowed" and MUST be 0xffffffff.
                std.mem.writeInt(u32, e[4..8], if (self.config.quic != null) 0xffff_ffff else self.config.early_data.?.max_size, .big);
                e = e[8..];
            }
            std.mem.writeInt(u16, e[0..2], (g << 12) | (g << 4) | 0x0a0a, .big);
            std.mem.writeInt(u16, e[2..4], 0, .big);
            used += m.len;
        }
        // `slot` leaves room for the records' overhead.
        if (used != 0) self.out.commit(.handshake, used) catch unreachable;
        self.tickets_due = 0;
    }
};

// ── tests ────────────────────────────────────────────────────────────────
//
// Negotiation refusals, each with the alert it sends: a ClientHello built
// field by field, fed as one plaintext record. Whole handshakes against an
// independent client are in `handshake_test.zig`.

const testing = std.testing;
const certs = @import("test_certs.zig");

const Hello = struct {
    versions: ?[]const u16 = &.{0x0304},
    legacy_version: u16 = 0x0303,
    sig_algs: ?[]const u16 = &.{0x0403},
    suites: []const u16 = &.{0x1301},
    groups: ?[]const u16 = &.{0x001d},
    /// Key shares (group, key); a real key is filled in for 0x001d and
    /// 0x0017 entries with an empty key.
    shares: ?[]const struct { u16, []const u8 } = &.{.{ 0x001d, "" }},
    compression: []const u8 = &.{0},
    sni: ?[]const u8 = null,
    alpn: ?[]const []const u8 = null,
    psk_without_modes: bool = false,
    /// `psk_key_exchange_modes`.
    psk_modes: ?[]const u8 = null,
    early_data: bool = false,
    /// `status_request` (ocsp), `signed_certificate_timestamp`.
    ocsp: bool = false,
    sct: bool = false,
    /// RFC 8879 `compress_certificate` algorithms.
    compress_certificate: ?[]const u16 = null,
    /// RFC 7250 `server_certificate_type` / `client_certificate_type` lists.
    server_cert_types: ?[]const u8 = null,
    client_cert_types: ?[]const u8 = null,
    /// RFC 9001 `quic_transport_parameters`, and a legacy_session_id.
    quic_tp: ?[]const u8 = null,
    session_id: []const u8 = "",
    /// A padding extension (RFC 7685) making the message this many octets,
    /// header included (0: none).
    pad_to: usize = 0,
    /// Octets of a next handshake message in the same record.
    trailing: []const u8 = "",
    /// RFC 8449 `record_size_limit`.
    record_size_limit: ?u16 = null,
};

fn buildRecord(gpa: std.mem.Allocator, h: Hello) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(gpa);
    const W = struct {
        fn u16be(l: *std.ArrayList(u8), a: std.mem.Allocator, v: usize) !void {
            try l.appendSlice(a, &.{ @truncate(v >> 8), @truncate(v) });
        }
        fn ext(l: *std.ArrayList(u8), a: std.mem.Allocator, t: u16, data: []const u8) !void {
            try u16be(l, a, t);
            try u16be(l, a, data.len);
            try l.appendSlice(a, data);
        }
        fn list16(a: std.mem.Allocator, comptime prefix: type, vals: []const u16) ![]u8 {
            var l: std.ArrayList(u8) = .empty;
            const n = vals.len * 2;
            if (prefix == u8) try l.append(a, @intCast(n)) else try u16be(&l, a, n);
            for (vals) |v| try u16be(&l, a, v);
            return l.toOwnedSlice(a);
        }
    };
    // Record header and handshake header, lengths patched at the end.
    try b.appendSlice(gpa, &.{ 22, 3, 1, 0, 0, 1, 0, 0, 0 });
    try W.u16be(&b, gpa, h.legacy_version);
    try b.appendNTimes(gpa, 0x42, 32);
    try b.append(gpa, @intCast(h.session_id.len));
    try b.appendSlice(gpa, h.session_id);
    try W.u16be(&b, gpa, h.suites.len * 2);
    for (h.suites) |s| try W.u16be(&b, gpa, s);
    try b.append(gpa, @intCast(h.compression.len));
    try b.appendSlice(gpa, h.compression);
    var e: std.ArrayList(u8) = .empty;
    defer e.deinit(gpa);
    if (h.versions) |v| {
        const d = try W.list16(gpa, u8, v);
        defer gpa.free(d);
        try W.ext(&e, gpa, 43, d);
    }
    if (h.sig_algs) |v| {
        const d = try W.list16(gpa, u16, v);
        defer gpa.free(d);
        try W.ext(&e, gpa, 13, d);
    }
    if (h.groups) |v| {
        const d = try W.list16(gpa, u16, v);
        defer gpa.free(d);
        try W.ext(&e, gpa, 10, d);
    }
    if (h.shares) |shares| {
        var d: std.ArrayList(u8) = .empty;
        defer d.deinit(gpa);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        for (shares) |sh| {
            var key: []const u8 = sh[1];
            var x: [32]u8 = undefined;
            var p: [65]u8 = undefined;
            if (sh[0] == 0x001d and key.len == 0) {
                const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(@splat(7));
                x = kp.public_key;
                key = &x;
            } else if (sh[0] == 0x0017 and key.len == 0) {
                const kp = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(7)) catch unreachable;
                p = kp.public_key.toUncompressedSec1();
                key = &p;
            }
            try W.u16be(&body, gpa, sh[0]);
            try W.u16be(&body, gpa, key.len);
            try body.appendSlice(gpa, key);
        }
        try W.u16be(&d, gpa, body.items.len);
        try d.appendSlice(gpa, body.items);
        try W.ext(&e, gpa, 51, d.items);
    }
    if (h.sni) |n| {
        var d: std.ArrayList(u8) = .empty;
        defer d.deinit(gpa);
        try W.u16be(&d, gpa, n.len + 3);
        try d.append(gpa, 0);
        try W.u16be(&d, gpa, n.len);
        try d.appendSlice(gpa, n);
        try W.ext(&e, gpa, 0, d.items);
    }
    if (h.alpn) |names| {
        var d: std.ArrayList(u8) = .empty;
        defer d.deinit(gpa);
        var total: usize = 0;
        for (names) |n| total += 1 + n.len;
        try W.u16be(&d, gpa, total);
        for (names) |n| {
            try d.append(gpa, @intCast(n.len));
            try d.appendSlice(gpa, n);
        }
        try W.ext(&e, gpa, 16, d.items);
    }
    if (h.ocsp) try W.ext(&e, gpa, 5, &.{ 1, 0, 0, 0, 0 });
    if (h.sct) try W.ext(&e, gpa, 18, "");
    for ([_]struct { u16, ?[]const u8 }{ .{ 20, h.server_cert_types }, .{ 19, h.client_cert_types } }) |ct| if (ct[1]) |types| {
        var d: [256]u8 = undefined;
        d[0] = @intCast(types.len);
        @memcpy(d[1..][0..types.len], types);
        try W.ext(&e, gpa, ct[0], d[0 .. 1 + types.len]);
    };
    if (h.quic_tp) |tp| try W.ext(&e, gpa, 57, tp);
    if (h.compress_certificate) |algs| {
        const d = try W.list16(gpa, u8, algs);
        defer gpa.free(d);
        try W.ext(&e, gpa, 27, d);
    }
    if (h.psk_modes) |m| {
        var d: [8]u8 = undefined;
        d[0] = @intCast(m.len);
        @memcpy(d[1..][0..m.len], m);
        try W.ext(&e, gpa, 45, d[0 .. 1 + m.len]);
    }
    if (h.early_data) try W.ext(&e, gpa, 42, "");
    if (h.record_size_limit) |l| try W.ext(&e, gpa, 28, &.{ @truncate(l >> 8), @truncate(l) });
    // pre_shared_key last (RFC 8446 §4.2.11).
    if (h.psk_without_modes) {
        const psk = [_]u8{ 0, 7, 0, 1, 0xaa, 0, 0, 0, 0, 0, 33, 32 } ++ @as([32]u8, @splat(0x55));
        try W.ext(&e, gpa, 41, &psk);
    }
    if (h.pad_to != 0) {
        // Message so far: what `b` holds after the record header, the
        // extensions' length, the extensions, a padding header.
        const so_far = (b.items.len - 5) + 2 + e.items.len + 4;
        const pad = try gpa.alloc(u8, h.pad_to - so_far);
        defer gpa.free(pad);
        @memset(pad, 0);
        try W.ext(&e, gpa, 21, pad);
    }
    try W.u16be(&b, gpa, e.items.len);
    try b.appendSlice(gpa, e.items);
    const body_len = b.items.len - 9;
    std.mem.writeInt(u24, b.items[6..9], @intCast(body_len), .big);
    try b.appendSlice(gpa, h.trailing);
    std.mem.writeInt(u16, b.items[3..5], @intCast(b.items.len - 5), .big);
    return b.toOwnedSlice(gpa);
}

var test_p256: ?std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = null;
const test_chain = [_][]const u8{&certs.p256_cert};

fn testKey() *const CertifiedKey {
    if (test_p256 == null) test_p256 = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(certs.p256_scalar) catch unreachable;
    const S = struct {
        var ck: CertifiedKey = undefined;
    };
    S.ck = .{ .chain = &test_chain, .key = .{ .ecdsa_p256 = &test_p256.? } };
    return &S.ck;
}

/// Feed `h` to a fresh server; return its error and the alert it queued.
fn refuse(h: Hello, config_override: ?Config) !struct { err: Error, alert: ?[2]u8 } {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = config_override orelse .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    const joiner = try testing.allocator.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer testing.allocator.free(joiner);
    const out = try testing.allocator.alloc(u8, 32 * 1024);
    defer testing.allocator.free(out);
    var s: Server = .init(&cfg, joiner, out);
    defer s.deinit();
    const rec = try buildRecord(testing.allocator, h);
    defer testing.allocator.free(rec);
    if (s.feed(rec)) |r| {
        std.debug.print("accepted: {t}\n", .{r.event});
        return error.HelloAccepted;
    } else |err| {
        const p = s.pendingOutput();
        // A plaintext alert record, the last thing queued.
        const a: ?[2]u8 = if (p.len >= 7 and p[p.len - 7] == 21) p[p.len - 2 ..][0..2].* else null;
        return .{ .err = err, .alert = a };
    }
}

fn expectRefusal(h: Hello, want: Error, want_alert: ?alert.Description) !void {
    const r = try refuse(h, null);
    try testing.expectEqual(want, r.err);
    if (want_alert) |d| {
        try testing.expectEqualSlices(u8, &.{ 2, @backingInt(d) }, &(r.alert orelse return error.NoAlertSent));
    } else try testing.expect(r.alert == null);
}

test "a well-formed hello gets a first flight (the builder works)" {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    const rec = try buildRecord(testing.allocator, .{ .sni = "example.com" });
    defer testing.allocator.free(rec);
    const r = try s.feed(rec);
    try testing.expect(r.event == .need_more);
    try testing.expectEqual(rec.len, r.consumed);
    try testing.expectEqualStrings("example.com", s.serverName().?);
    // ServerHello in the clear, then the CCS, then protected records.
    const p = s.pendingOutput();
    try testing.expectEqual(@as(u8, 22), p[0]);
    const sh_len = std.mem.readInt(u16, p[3..5], .big);
    try testing.expectEqualSlices(u8, &.{ 20, 3, 3, 0, 1, 1 }, p[5 + sh_len ..][0..6]);
    try testing.expectEqual(@as(u8, 23), p[5 + sh_len + 6]);
}

fn offloadedTestKey(verify: bool) CertifiedKey {
    return .{ .chain = &test_chain, .key = null, .offload = .{ .schemes = &.{ 0x0804, 0x0403 }, .verify = verify } };
}

/// A server fed one ClientHello for an offloaded key: it waits for the signature.
const OffloadRun = struct {
    prng: std.Random.DefaultPrng,
    ck: CertifiedKey,
    cfg: Config,
    joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8,
    out: [32 * 1024]u8,
    s: Server,

    fn start(r: *OffloadRun, verify: bool) !void {
        r.prng = .init(1);
        r.ck = offloadedTestKey(verify);
        r.cfg = .{ .certificate = .{ .fixed = &r.ck }, .random = r.prng.random() };
        r.s = .init(&r.cfg, &r.joiner, &r.out);
        const rec = try buildRecord(testing.allocator, .{});
        defer testing.allocator.free(rec);
        const res = try r.s.feed(rec);
        try testing.expect(res.event == .signature_needed);
        try testing.expectEqual(rec.len, res.consumed);
    }

    fn sign(_: *OffloadRun, message: []const u8, buf: []u8) ![]const u8 {
        return certverify.signContent(.ecdsa_secp256r1_sha256, testKey().key.?, message, null, buf);
    }
};

test "offloaded key: the flight stops after the Certificate until the signature comes, then goes on" {
    var r: OffloadRun = undefined;
    try r.start(true);
    defer r.s.deinit();
    // ServerHello, CCS, EncryptedExtensions and Certificate are queued.
    const before = r.s.pendingOutput().len;
    try testing.expect(before > 0);
    // Nothing is taken meanwhile; the event repeats.
    var more = [_]u8{ 20, 3, 3, 0, 1, 1 };
    const again = try r.s.feed(&more);
    try testing.expect(again.event == .signature_needed);
    try testing.expectEqual(@as(usize, 0), again.consumed);
    try testing.expect(!r.s.canWrite());
    // The client offers ecdsa_secp256r1_sha256 but not RSA-PSS: the
    // signer's first scheme the client offers.
    const req = r.s.signatureRequest().?;
    try testing.expectEqual(@as(u16, 0x0403), req.scheme);
    try testing.expectEqualSlices(u8, &@as([64]u8, @splat(0x20)), req.message[0..64]);
    try testing.expectEqualStrings(certverify.server_context_string ++ "\x00", req.message[64..][0 .. certverify.server_context_string.len + 1]);
    try testing.expectEqual(@as(usize, 64 + certverify.server_context_string.len + 1 + 32), req.message.len);
    var buf: [certverify.max_signature_len]u8 = undefined;
    try r.s.provideSignature(try r.sign(req.message, &buf));
    // CertificateVerify and Finished follow; the client's flight is next.
    try testing.expect(r.s.pendingOutput().len > before);
    try testing.expectEqual(State.client_finished, r.s.state);
    try testing.expectEqual(null, r.s.signatureRequest());
    try testing.expectError(error.NoSignatureRequested, r.s.provideSignature("x"));
    try testing.expectEqualSlices(u8, &@as([48]u8, @splat(0)), &r.s.sign_server_hs);
}

test "offloaded key: a signature that does not verify, an empty one, or the signer's failure is internal_error" {
    var buf: [certverify.max_signature_len]u8 = undefined;
    for (0..3) |case| {
        var r: OffloadRun = undefined;
        try r.start(true);
        defer r.s.deinit();
        const req = r.s.signatureRequest().?;
        switch (case) {
            0 => {
                // Signed over other content (a stale transcript).
                var other: [certverify.max_signed_content_len]u8 = undefined;
                @memcpy(other[0..req.message.len], req.message);
                other[req.message.len - 1] ^= 1;
                try testing.expectError(error.InternalError, r.s.provideSignature(try r.sign(other[0..req.message.len], &buf)));
            },
            1 => try testing.expectError(error.InternalError, r.s.provideSignature("")),
            else => r.s.signatureFailed(),
        }
        const p = r.s.pendingOutput();
        // The fatal alert is the last record queued (under the handshake key).
        try testing.expectEqual(@as(u8, 23), p[p.len - (5 + 2 + 1 + record.tag_len)]);
        try testing.expectEqual(State.failed, r.s.state);
        try testing.expectEqualSlices(u8, &@as([48]u8, @splat(0)), &r.s.sign_server_hs);
        try testing.expectError(error.Closed, r.s.feed(&.{}));
        try testing.expectError(error.Closed, r.s.provideSignature("x"));
    }
    // Without `verify` the signature goes out as given.
    var r: OffloadRun = undefined;
    try r.start(false);
    defer r.s.deinit();
    try r.s.provideSignature("not a signature");
    try testing.expectEqual(State.client_finished, r.s.state);
}

test "offloaded key: check, scheme choice and the output it needs" {
    var ck = offloadedTestKey(true);
    try ck.check();
    // Neither, both, or only schemes certverify does not know.
    ck.offload = null;
    try testing.expectError(error.SigningKey, ck.check());
    ck = testKey().*;
    ck.offload = offloadedTestKey(true).offload;
    try testing.expectError(error.SigningKey, ck.check());
    ck = offloadedTestKey(true);
    ck.offload.?.schemes = &.{ 0x0401, 0x0201 };
    try testing.expectError(error.SigningKey, ck.check());
    // None of the signer's schemes offered: handshake_failure.
    var prng = std.Random.DefaultPrng.init(1);
    const off = offloadedTestKey(true);
    const cfg: Config = .{ .certificate = .{ .fixed = &off }, .random = prng.random() };
    const r = try refuse(.{ .sig_algs = &.{0x0807} }, cfg);
    try testing.expectEqual(error.HandshakeFailure, r.err);
    // RSA-PSS among the schemes: room for a 4096-bit signature.
    try testing.expect(minOutputLen(&cfg, &off) > minOutputLen(&cfg, testKey()) + 400);
}

test "obsolete groups in supported_groups alone are served (JDK 11 lists them)" {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    const rec = try buildRecord(testing.allocator, .{ .groups = &.{ 0x001d, 0x0009, 0x0016, 0x0017 } });
    defer testing.allocator.free(rec);
    const r = try s.feed(rec);
    try testing.expect(r.event == .need_more);
    try testing.expectEqual(@as(?u16, 0x001d), s.negotiatedGroup());
}

test "refusals and their alerts" {
    // Not TLS 1.3.
    try expectRefusal(.{ .versions = null }, error.ProtocolVersion, .protocol_version);
    try expectRefusal(.{ .versions = &.{ 0x0303, 0x0302 } }, error.ProtocolVersion, .protocol_version);
    // SSL 3.0 or garbage as legacy_version, even beside 0x0304.
    try expectRefusal(.{ .legacy_version = 0x0300 }, error.ProtocolVersion, .protocol_version);
    try expectRefusal(.{ .legacy_version = 0x0002 }, error.ProtocolVersion, .protocol_version);
    // Nothing to sign with, nothing in common.
    try expectRefusal(.{ .sig_algs = null }, error.HandshakeFailure, .handshake_failure);
    try expectRefusal(.{ .sig_algs = &.{ 0x0807, 0x0804 } }, error.HandshakeFailure, .handshake_failure);
    try expectRefusal(.{ .suites = &.{ 0xc02f, 0x1304 } }, error.HandshakeFailure, .handshake_failure);
    try expectRefusal(.{ .groups = null }, error.MissingExtension, .missing_extension);
    // The version is checked before anything else the hello lacks.
    try expectRefusal(.{ .versions = null, .sig_algs = null, .groups = null }, error.ProtocolVersion, .protocol_version);
    try expectRefusal(.{ .groups = &.{ 0x0019, 0x0100 } }, error.HandshakeFailure, .handshake_failure);
    // A share for an obsolete group (RFC 8446 §4.2.7), even beside a good
    // one, at either end of each range; a share for a group the client
    // does not list.
    for ([_]u16{ 0x0001, 0x0016, 0x001a, 0x001c, 0xff01, 0xff02 }) |g| {
        try expectRefusal(.{ .groups = &.{ 0x001d, g }, .shares = &.{ .{ 0x001d, "" }, .{ g, &@as([32]u8, @splat(0xab)) } } }, error.IllegalParameter, .illegal_parameter);
    }
    try expectRefusal(.{ .groups = &.{0x0017}, .shares = &.{.{ 0x001d, "" }} }, error.IllegalParameter, .illegal_parameter);
    try expectRefusal(.{ .shares = null }, error.MissingExtension, .missing_extension);
    // Malformed or forbidden.
    try expectRefusal(.{ .shares = &.{ .{ 0x001d, "" }, .{ 0x001d, "" } } }, error.IllegalParameter, .illegal_parameter);
    try expectRefusal(.{ .shares = &.{.{ 0x001d, &@as([31]u8, @splat(9)) }} }, error.IllegalParameter, .illegal_parameter);
    try expectRefusal(.{ .shares = &.{.{ 0x001d, &@as([32]u8, @splat(0)) }} }, error.IllegalParameter, .illegal_parameter); // low-order point
    try expectRefusal(.{ .compression = &.{ 1, 0 } }, error.IllegalParameter, .illegal_parameter);
    try expectRefusal(.{ .compression = &.{1} }, error.IllegalParameter, .illegal_parameter);
    try expectRefusal(.{ .sni = "not a name" }, error.IllegalParameter, .illegal_parameter);
    try expectRefusal(.{ .psk_without_modes = true }, error.MissingExtension, .missing_extension);
}

test "ALPN: the server's first protocol the client offers; none in common is refused" {
    var prng = std.Random.DefaultPrng.init(1);
    var cfg: Config = .{
        .certificate = .{ .fixed = testKey() },
        .random = prng.random(),
        .alpn_protocols = &.{ "h2", "http/1.1" },
    };
    const r = try refuse(.{ .alpn = &.{ "spdy/3", "acme-tls/1" } }, cfg);
    try testing.expectEqual(error.NoApplicationProtocol, r.err);
    try testing.expectEqualSlices(u8, &.{ 2, 120 }, &r.alert.?);

    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    const rec = try buildRecord(testing.allocator, .{ .alpn = &.{ "http/1.1", "h2" } });
    defer testing.allocator.free(rec);
    _ = try s.feed(rec);
    try testing.expectEqualStrings("h2", s.alpn.?);
    // A client without ALPN is served without it.
    cfg.alpn_protocols = &.{"h2"};
    var s2: Server = .init(&cfg, &joiner, &out);
    defer s2.deinit();
    const rec2 = try buildRecord(testing.allocator, .{});
    defer testing.allocator.free(rec2);
    _ = try s2.feed(rec2);
    try testing.expect(s2.alpn == null);
}

test "certificate selector: sees the SNI, null is access_denied" {
    var prng = std.Random.DefaultPrng.init(1);
    const Sel = struct {
        var seen: [64]u8 = undefined;
        var seen_len: usize = 0;
        fn select(_: ?*anyopaque, sni: ?[]const u8, _: *const hello.ClientHello) ?*const CertifiedKey {
            const n = sni orelse return null;
            @memcpy(seen[0..n.len], n);
            seen_len = n.len;
            return if (std.mem.eql(u8, n, "known.example")) testKey() else null;
        }
    };
    const cfg: Config = .{ .certificate = .{ .select = .{ .select = Sel.select } }, .random = prng.random() };
    const r = try refuse(.{ .sni = "unknown.example" }, cfg);
    try testing.expectEqual(error.AccessDenied, r.err);
    try testing.expectEqualSlices(u8, &.{ 2, 49 }, &r.alert.?);
    try testing.expectEqualStrings("unknown.example", Sel.seen[0..Sel.seen_len]);
    // An IP literal is no SNI.
    const r2 = try refuse(.{ .sni = "192.0.2.1" }, cfg);
    try testing.expectEqual(error.AccessDenied, r2.err);
}

test "firstUsableKey: the first key the client's schemes allow, else the first key" {
    const ed = try std.crypto.sign.Ed25519.SecretKey.fromBytes(certs.ed25519_secret);
    const ed_chain = [_][]const u8{&certs.ed25519_cert};
    const keys = [_]CertifiedKey{ testKey().*, .{ .chain = &ed_chain, .key = .{ .ed25519 = &ed } } };
    var random: [32]u8 = @splat(0);
    var ch: hello.ClientHello = .{ .legacy_version = 0x0303, .random = &random, .legacy_session_id = "", .cipher_suites_raw = &.{ 0x13, 0x01 }, .legacy_compression_methods = &.{0} };
    // The server's order decides when the client allows both.
    ch.signature_algorithms_raw = &.{ 0x08, 0x07, 0x04, 0x03 };
    try testing.expectEqual(&keys[0], firstUsableKey(&keys, &ch).?);
    ch.signature_algorithms_raw = &.{ 0x08, 0x07 };
    try testing.expectEqual(&keys[1], firstUsableKey(&keys, &ch).?);
    // Nothing usable, or no signature_algorithms: the first key (the
    // handshake then refuses as for one key).
    ch.signature_algorithms_raw = &.{ 0x08, 0x04 };
    try testing.expectEqual(&keys[0], firstUsableKey(&keys, &ch).?);
    ch.signature_algorithms_raw = null;
    try testing.expectEqual(&keys[0], firstUsableKey(&keys, &ch).?);
    try testing.expect(firstUsableKey(&.{}, &ch) == null);
}

test "CertifiedKey.check: chain, SCT list, leaf extensions; a selected key that fails it is internal_error" {
    const k = testKey();
    const leaf = k.chain[0];
    try k.check();
    var ck: CertifiedKey = k.*;
    ck.chain = &.{};
    try testing.expectError(error.ChainLength, ck.check());
    const many: [CertifiedKey.max_chain_len + 1][]const u8 = @splat(leaf);
    ck.chain = &many;
    try testing.expectError(error.ChainLength, ck.check());
    ck.chain = many[0..CertifiedKey.max_chain_len];
    try ck.check();
    ck.chain = &.{ leaf, "" };
    try testing.expectError(error.CertificateLength, ck.check());
    // Lengths only: `check` never reads the octets.
    // One entry: 1 + 3 + (3 + L + 2) = 2^24 - 1 at L = 2^24 - 10.
    const huge: [*]const u8 = leaf.ptr;
    ck.chain = &.{huge[0 .. (1 << 24) - 10]};
    try ck.check();
    ck.chain = &.{huge[0 .. (1 << 24) - 9]};
    try testing.expectError(error.ChainTooLong, ck.check());
    // The leaf's extensions count too.
    ck.chain = &.{huge[0 .. (1 << 24) - 10 - 9]};
    ck.sct_list = "\x00\x03\x00\x01x";
    try ck.check();
    ck.chain = &.{huge[0 .. (1 << 24) - 10 - 8]};
    try testing.expectError(error.ChainTooLong, ck.check());
    ck.sct_list = null;
    ck.chain = k.chain;
    // SignedCertificateTimestampList: BoGo's well-formed one, then broken.
    for ([_][]const u8{ "", "\x00\x06\x00\x04\x05\x06\x07\x08", "\x00\x03\x00\x01x" }) |l| {
        ck.sct_list = l;
        try ck.check();
    }
    for ([_][]const u8{ "\x00", "\x00\x00", "\x00\x02\x00\x00", "\x00\x03\x00\x02x", "\x00\x04\x00\x01xy", "\x00\x07\x00\x01x\x00", "\x00\x06\x00\x04\x05\x06\x07", "\x00\x09\x00\x01x" }) |l| {
        ck.sct_list = l;
        testing.expectError(error.InvalidSctList, ck.check()) catch |e| {
            std.debug.print("sct list {x}\n", .{l});
            return e;
        };
    }
    ck.sct_list = null;
    // OCSP staple + SCT list over the leaf's extensions<0..2^16-1>.
    const big = try testing.allocator.alloc(u8, 65535 - 8);
    defer testing.allocator.free(big);
    @memset(big, 0x30);
    ck.ocsp_response = big[0 .. 65535 - 8];
    try ck.check();
    ck.ocsp_response = big[0 .. 65535 - 8 - 9];
    ck.sct_list = "\x00\x03\x00\x01x";
    try ck.check();
    ck.ocsp_response = big[0 .. 65535 - 8 - 8];
    try testing.expectError(error.LeafExtensionsTooLong, ck.check());

    // A selector handing out such a key: refused at the handshake.
    var prng = std.Random.DefaultPrng.init(1);
    const Sel = struct {
        var key: CertifiedKey = undefined;
        fn select(_: ?*anyopaque, _: ?[]const u8, _: *const hello.ClientHello) ?*const CertifiedKey {
            return &key;
        }
    };
    Sel.key = k.*;
    Sel.key.sct_list = "\x00\x00";
    const cfg: Config = .{ .certificate = .{ .select = .{ .select = Sel.select } }, .random = prng.random() };
    const r = try refuse(.{}, cfg);
    try testing.expectEqual(error.InternalError, r.err);
    try testing.expectEqualSlices(u8, &.{ 2, 80 }, &r.alert.?);
}

test "first message not a ClientHello; a second ClientHello; a bad client Finished" {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    {
        var s: Server = .init(&cfg, &joiner, &out);
        defer s.deinit();
        var rec = [_]u8{ 22, 3, 3, 0, 8, 20, 0, 0, 4, 1, 2, 3, 4 };
        try testing.expectError(error.UnexpectedMessage, s.feed(&rec));
        try testing.expectEqualSlices(u8, &.{ 21, 3, 3, 0, 2, 2, 10 }, s.pendingOutput());
        try testing.expectError(error.Closed, s.feed(&rec));
    }
    {
        // Two ClientHellos in one record: the second is data across the key
        // change.
        var s: Server = .init(&cfg, &joiner, &out);
        defer s.deinit();
        const one = try buildRecord(testing.allocator, .{});
        defer testing.allocator.free(one);
        var two: std.ArrayList(u8) = .empty;
        defer two.deinit(testing.allocator);
        try two.appendSlice(testing.allocator, one);
        try two.appendSlice(testing.allocator, one[5..]);
        std.mem.writeInt(u16, two.items[3..5], @intCast(two.items.len - 5), .big);
        try testing.expectError(error.UnexpectedMessage, s.feed(two.items));
    }
    {
        // A client Finished that does not verify: decrypt_error, sealed
        // under the server's key (so not readable here as plaintext).
        var s: Server = .init(&cfg, &joiner, &out);
        defer s.deinit();
        const rec = try buildRecord(testing.allocator, .{});
        defer testing.allocator.free(rec);
        _ = try s.feed(rec);
        const flight = s.pendingOutput().len;
        // Seal a wrong Finished under the client's handshake key.
        var tx: record.Protection = undefined;
        try tx.init(.aes_128_gcm_sha256, s.client_handshake_secret[0..32]);
        var buf: [128]u8 = undefined;
        const fin = [_]u8{ 20, 0, 0, 32 } ++ @as([32]u8, @splat(0xee));
        @memcpy(buf[5..][0..fin.len], &fin);
        const sealed = try tx.seal(&buf, fin.len, .handshake, 0);
        try testing.expectError(error.DecryptError, s.feed(sealed));
        // One more record went out: the protected alert.
        try testing.expectEqual(flight + 5 + 2 + 1 + 16, s.pendingOutput().len);
    }
    // A Finished one octet short or long: decrypt_error as well (BoGo).
    for ([_]usize{ 31, 33 }) |n| {
        var s: Server = .init(&cfg, &joiner, &out);
        defer s.deinit();
        const rec = try buildRecord(testing.allocator, .{});
        defer testing.allocator.free(rec);
        _ = try s.feed(rec);
        var tx: record.Protection = undefined;
        try tx.init(.aes_128_gcm_sha256, s.client_handshake_secret[0..32]);
        var buf: [128]u8 = undefined;
        buf[5..9].* = .{ 20, 0, 0, @intCast(n) };
        @memset(buf[9..][0..n], 0xee);
        const sealed = try tx.seal(&buf, 4 + n, .handshake, 0);
        try testing.expectError(error.DecryptError, s.feed(sealed));
    }
}

test "application data is refused before the handshake completes" {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    try testing.expectError(error.NotConnected, s.write("x"));
    try testing.expectEqual(@as(?record.CipherSuite, null), s.cipherSuite());
}

test "alertFor covers every error" {
    inline for (@typeInfo(Error).error_set.error_names.?) |name| {
        _ = alertFor(@field(anyerror, name));
    }
}

test "after a refusal every secret is wiped; the suite is unknown if it was not chosen" {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    const rec = try buildRecord(testing.allocator, .{ .groups = &.{0x0100} });
    defer testing.allocator.free(rec);
    try testing.expectError(error.HandshakeFailure, s.feed(rec));
    try testing.expectEqual(@as(?record.CipherSuite, null), s.cipherSuite());

    // Refused after the keys exist: a bad Finished.
    var s2: Server = .init(&cfg, &joiner, &out);
    defer s2.deinit();
    const ok = try buildRecord(testing.allocator, .{});
    defer testing.allocator.free(ok);
    _ = try s2.feed(ok);
    var tx: record.Protection = undefined;
    try tx.init(.aes_128_gcm_sha256, s2.client_handshake_secret[0..32]);
    var buf: [128]u8 = undefined;
    const fin = [_]u8{ 20, 0, 0, 32 } ++ @as([32]u8, @splat(0xee));
    @memcpy(buf[5..][0..fin.len], &fin);
    try testing.expectError(error.DecryptError, s2.feed(try tx.seal(&buf, fin.len, .handshake, 0)));
    for ([_][]const u8{ &s2.handshake_secret, &s2.client_handshake_secret, &s2.master_secret, &s2.client_application_secret, &s2.server_application_secret, &s2.exporter_master_secret }) |sec|
        for (sec) |b| try testing.expectEqual(@as(u8, 0), b);
    try testing.expect(!s2.out.protected and !s2.inbound.protected);
    try testing.expectEqual(record.CipherSuite.aes_128_gcm_sha256, s2.cipherSuite().?);
}

/// Feed `first` (which must get a HelloRetryRequest) and then `second` to a
/// fresh server; `between` goes between them. Returns the second feed's
/// outcome and the server's output.
const RetryOutcome = struct { err: ?Error, out: [4096]u8, out_len: usize };

fn retry(first: Hello, between: []const u8, second: Hello) !RetryOutcome {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    const r1 = try buildRecord(testing.allocator, first);
    defer testing.allocator.free(r1);
    const r = try s.feed(r1);
    try testing.expect(r.event == .need_more);
    try testing.expectEqual(State.client_hello_retry, s.state);
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(testing.allocator);
    try stream.appendSlice(testing.allocator, between);
    const r2 = try buildRecord(testing.allocator, second);
    defer testing.allocator.free(r2);
    try stream.appendSlice(testing.allocator, r2);
    var res: RetryOutcome = .{ .err = null, .out = undefined, .out_len = 0 };
    if (s.feed(stream.items)) |f| {
        try testing.expect(f.event == .need_more);
        try testing.expectEqual(stream.items.len, f.consumed);
        try testing.expectEqual(State.client_finished, s.state);
        try testing.expect(s.usedHelloRetryRequest());
    } else |err| res.err = err;
    const p = s.pendingOutput();
    res.out_len = @min(p.len, res.out.len);
    @memcpy(res.out[0..res.out_len], p[0..res.out_len]);
    return res;
}

const p256_only: Hello = .{ .groups = &.{ 0x0017, 0x001d }, .shares = &.{.{ 0x0017, "" }} };
const x25519_share_first: Hello = .{ .groups = &.{ 0x0017, 0x001d }, .shares = &.{.{ 0x001d, "" }} };

/// Feed `h` to a server under `cfg`; the server, with its first flight
/// pending.
fn accept(s: *Server, cfg: *const Config, joiner: []u8, out: []u8, h: Hello) !void {
    s.* = .init(cfg, joiner, out);
    const rec = try buildRecord(testing.allocator, h);
    defer testing.allocator.free(rec);
    const r = try s.feed(rec);
    try testing.expect(r.event == .need_more);
}

test "server_order: the suite and the group in the server's order, else the client's" {
    const h: Hello = .{
        .suites = &.{ 0x1301, 0x1302 },
        .groups = &.{ 0x001d, 0x0017 },
        .shares = &.{ .{ 0x001d, "" }, .{ 0x0017, "" } },
    };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    for ([_]bool{ false, true }) |server_order| {
        var prng = std.Random.DefaultPrng.init(1);
        const cfg: Config = .{
            .certificate = .{ .fixed = testKey() },
            .cipher_suites = &.{ .aes_256_gcm_sha384, .aes_128_gcm_sha256 },
            .groups = &.{ 0x0017, 0x001d },
            .server_order = server_order,
            .random = prng.random(),
        };
        var s: Server = undefined;
        try accept(&s, &cfg, &joiner, &out, h);
        defer s.deinit();
        try testing.expectEqual(if (server_order) record.CipherSuite.aes_256_gcm_sha384 else .aes_128_gcm_sha256, s.cipherSuite().?);
        try testing.expectEqual(@as(u16, if (server_order) 0x0017 else 0x001d), s.negotiatedGroup().?);
        try testing.expect(!s.usedHelloRetryRequest());
    }
    // An unknown suite the configuration enables is never chosen, even
    // first in the server's order and offered by the client.
    {
        var prng = std.Random.DefaultPrng.init(1);
        const cfg: Config = .{
            .certificate = .{ .fixed = testKey() },
            .cipher_suites = &.{ @fromBackingInt(0x00ff), .aes_128_gcm_sha256 },
            .server_order = true,
            .random = prng.random(),
        };
        var s: Server = undefined;
        try accept(&s, &cfg, &joiner, &out, .{ .suites = &.{ 0x00ff, 0x1301 } });
        defer s.deinit();
        try testing.expectEqual(record.CipherSuite.aes_128_gcm_sha256, s.cipherSuite().?);
    }
    // The server's first group without a share is asked for.
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .groups = &.{ 0x0017, 0x001d }, .server_order = true, .random = prng.random() };
    var s: Server = undefined;
    try accept(&s, &cfg, &joiner, &out, .{ .groups = &.{ 0x001d, 0x0017 }, .shares = &.{.{ 0x001d, "" }} });
    defer s.deinit();
    try testing.expectEqual(State.client_hello_retry, s.state);
    try testing.expectEqual(@as(u16, 0x0017), s.group);
    try testing.expect(s.usedHelloRetryRequest());
}

test "CertifiedKey.signature_schemes restricts and orders the key's schemes" {
    var prng = std.Random.DefaultPrng.init(1);
    var ck = testKey().*;
    // A scheme the key cannot make is skipped; the next one serves.
    ck.signature_schemes = &.{ 0x0804, 0x0403 };
    const cfg: Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = undefined;
    try accept(&s, &cfg, &joiner, &out, .{ .sig_algs = &.{ 0x0804, 0x0403 } });
    s.deinit();
    // None left that the key can make, or none the client offers.
    for ([_][]const u16{ &.{0x0804}, &.{}, &.{ 0x0401, 0x0201 } }) |prefs| {
        ck.signature_schemes = prefs;
        const r = try refuse(.{ .sig_algs = &.{ 0x0403, 0x0804, 0x0401 } }, cfg);
        try testing.expectEqual(error.HandshakeFailure, r.err);
    }
    ck.signature_schemes = &.{0x0403};
    try testing.expectEqual(error.HandshakeFailure, (try refuse(.{ .sig_algs = &.{0x0503} }, cfg)).err);
}

test "max_fragment_len: no record of the first flight carries more; minOutputLen holds it" {
    var prng = std.Random.DefaultPrng.init(1);
    // A 64 KiB Certificate message (the server never parses its own
    // chain): over a hundred small fragments, far more overhead than the
    // worst-case slack elsewhere in `minOutputLen` (shares, ALPN) covers.
    const blob: [4096]u8 = @splat(0xab);
    const chain: [CertifiedKey.max_chain_len][]const u8 = @splat(&blob);
    var ck = testKey().*;
    ck.chain = &chain;
    var records: [3]usize = undefined;
    for ([_]u16{ outbound.min_fragment, 600, 1 }, &records) |frag, *n_records| {
        const cfg: Config = .{ .certificate = .{ .fixed = &ck }, .max_fragment_len = frag, .random = prng.random() };
        var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
        const out = try testing.allocator.alloc(u8, minOutputLen(&cfg, &ck));
        defer testing.allocator.free(out);
        var s: Server = undefined;
        try accept(&s, &cfg, &joiner, out, .{});
        defer s.deinit();
        const limit: usize = @max(frag, outbound.min_fragment); // clamped
        const p = s.pendingOutput();
        var at: usize = 0;
        var protected: usize = 0;
        while (at < p.len) {
            const h = record.parseHeader(p[at..][0..5]);
            // Protected records hold the inner type and the tag besides.
            const content = if (h.content_type == .application_data) h.length - 1 - record.tag_len else h.length;
            try testing.expect(content <= limit);
            if (h.content_type == .application_data) protected += 1;
            at += 5 + h.length;
        }
        try testing.expectEqual(p.len, at);
        // EncryptedExtensions, CertificateVerify, Finished and the
        // Certificate's fragments.
        try testing.expect(protected >= 3 + chain.len * blob.len / limit);
        n_records.* = protected;
    }
    // Below the floor is the floor.
    try testing.expectEqual(records[0], records[2]);
}

/// The first flight to the ClientHello record `rec` (AES-128-GCM-SHA256,
/// no HelloRetryRequest), opened: the protected handshake messages,
/// joined, in `msgs`; returns their length. The server's handshake key
/// comes from its handshake secret and the transcript through the
/// ServerHello.
fn openFirstFlight(s: *Server, rec: []u8, msgs: []u8) !usize {
    const r = try s.feed(rec);
    try testing.expect(r.event == .need_more);
    const p = s.pendingOutput();
    const sh_len = std.mem.readInt(u16, p[3..5], .big);
    var th: [32]u8 = undefined;
    var hash = Sha256.init(.{});
    hash.update(rec[5..]);
    hash.update(p[5..][0..sh_len]);
    hash.final(&th);
    var c_hs: [32]u8 = undefined;
    var s_hs: [32]u8 = undefined;
    ks.deriveHandshakeTrafficSecrets(S256.Hkdf, &c_hs, &s_hs, s.handshake_secret[0..32], &th);
    var rx: record.Protection = undefined;
    try rx.init(.aes_128_gcm_sha256, &s_hs);
    var buf: [32 * 1024]u8 = undefined;
    @memcpy(buf[0..p.len], p);
    var at: usize = 5 + sh_len + 6; // the ServerHello, the CCS
    var n: usize = 0;
    while (at < p.len) {
        const hd = record.parseHeader(buf[at..][0..5]);
        const o = try rx.open(buf[at..][0 .. 5 + hd.length]);
        try testing.expectEqual(record.ContentType.handshake, o.content_type);
        @memcpy(msgs[n..][0..o.content.len], o.content);
        n += o.content.len;
        at += 5 + hd.length;
    }
    return n;
}

/// The handshake message after EncryptedExtensions in a joined flight.
fn certificateMessageOf(msgs: []const u8) []const u8 {
    const ee_len = std.mem.readInt(u24, msgs[1..4], .big);
    const m = msgs[4 + ee_len ..];
    return m[0 .. 4 + std.mem.readInt(u24, m[1..4], .big)];
}

test "RFC 8879: a compressed certificate for the staples sent, first in the server's order; the transcript hashes it" {
    const gpa = testing.allocator;
    var ck = testKey().*;
    ck.ocsp_response = "\x30\x03\x0a\x01\x00";
    ck.sct_list = "\x00\x03\x00\x01x";
    // The server never decompresses: a marker octet before the body stands
    // in for a compressor.
    var bodies: [2][]u8 = undefined;
    var datas: [3][]u8 = undefined;
    var scratch: [4096]u8 = undefined;
    for ([_]bool{ false, true }, &bodies) |ocsp, *b| b.* = try gpa.dupe(u8, try ck.uncompressedCertificate(&scratch, .{ .ocsp = ocsp }));
    defer for (bodies) |b| gpa.free(b);
    for ([_]u8{ 'E', 'S', 'O' }, [_]usize{ 0, 0, 1 }, &datas) |mark, i, *d| d.* = try std.mem.concat(gpa, u8, &.{ &.{mark}, bodies[i] });
    defer for (datas) |d| gpa.free(d);
    const compressed = [_]CertifiedKey.CompressedCertificate{
        .{ .algorithm = 0xff02, .uncompressed_len = @intCast(bodies[0].len), .data = datas[0] },
        .{ .algorithm = 0xff01, .uncompressed_len = @intCast(bodies[0].len), .data = datas[1] },
        .{ .algorithm = 0xff01, .staples = .{ .ocsp = true }, .uncompressed_len = @intCast(bodies[1].len), .data = datas[2] },
    };
    ck.compressed_certificates = &compressed;
    try ck.check();

    const Case = struct { algs: ?[]const u16, ocsp: bool = false, sct: bool = false, want: ?u8 };
    const cases = [_]Case{
        .{ .algs = null, .want = null },
        .{ .algs = &.{0x0001}, .want = null }, // no common algorithm
        .{ .algs = &.{0xff01}, .want = 'S' },
        .{ .algs = &.{ 0xff01, 0xff02 }, .want = 'E' }, // the server's order
        .{ .algs = &.{0xff01}, .ocsp = true, .want = 'O' },
        .{ .algs = &.{0xff02}, .ocsp = true, .want = null }, // none with the staple
        .{ .algs = &.{ 0xff01, 0xff02 }, .sct = true, .want = null }, // nor with the SCTs
    };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var msgs: [32 * 1024]u8 = undefined;
    for (cases, 0..) |c, i| {
        errdefer std.debug.print("case {d}\n", .{i});
        var prng = std.Random.DefaultPrng.init(1);
        const cfg: Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random() };
        var s: Server = .init(&cfg, &joiner, &out);
        defer s.deinit();
        const rec = try buildRecord(gpa, .{ .compress_certificate = c.algs, .ocsp = c.ocsp, .sct = c.sct });
        defer gpa.free(rec);
        const n = try openFirstFlight(&s, rec, &msgs);
        const m = certificateMessageOf(msgs[0..n]);
        if (c.want) |mark| {
            const cc = for (&compressed) |*x| {
                if (x.data[0] == mark) break x;
            } else unreachable;
            var want: [4096]u8 = undefined;
            try testing.expectEqualSlices(u8, try messages.compressedCertificate(&want, cc.algorithm, cc.uncompressed_len, cc.data), m);
        } else {
            try testing.expectEqual(@as(u8, 11), m[0]);
            try testing.expectEqualSlices(u8, try ck.uncompressedCertificate(&scratch, .{ .ocsp = c.ocsp, .sct = c.sct }), m[4..]);
        }

        // The client's Finished over the transcript as sent.
        var t = Sha256.init(.{});
        const p = s.pendingOutput();
        t.update(rec[5..]);
        t.update(p[5..][0..std.mem.readInt(u16, p[3..5], .big)]);
        t.update(msgs[0..n]);
        var th: [32]u8 = undefined;
        t.final(&th);
        var fk: [32]u8 = undefined;
        ks.deriveFinishedKey(S256.Hkdf, 32, &fk, s.client_handshake_secret[0..32]);
        var fin: [5 + 36 + 1 + record.tag_len]u8 = undefined;
        fin[5..][0..4].* = .{ 20, 0, 0, 32 };
        tls13.keyschedule.computeFinishedVerifyData(S256.Hmac, fin[9..41], &fk, &th);
        var tx: record.Protection = undefined;
        try tx.init(.aes_128_gcm_sha256, s.client_handshake_secret[0..32]);
        const r = try s.feed(try tx.seal(&fin, 36, .handshake, 0));
        try testing.expect(r.event == .handshake_done);
    }
}

test "CertifiedKey.check: compressed certificates must match the message they stand for" {
    var ck = testKey().*;
    var scratch: [4096]u8 = undefined;
    const body = try ck.uncompressedCertificate(&scratch, .{});
    const len: u24 = @intCast(body.len);
    ck.compressed_certificates = &.{.{ .algorithm = 1, .uncompressed_len = len, .data = "x" }};
    try ck.check();
    ck.compressed_certificates = &.{.{ .algorithm = 1, .uncompressed_len = len, .data = "" }};
    try testing.expectError(error.CompressedLength, ck.check());
    ck.compressed_certificates = &.{.{ .algorithm = 0, .uncompressed_len = len, .data = "x" }};
    try testing.expectError(error.CompressedLength, ck.check());
    // The message's own u24 length holds the algorithm and two lengths too
    // (lengths only: `check` never reads the octets).
    const huge: [*]const u8 = ck.chain[0].ptr;
    ck.compressed_certificates = &.{.{ .algorithm = 1, .uncompressed_len = len, .data = huge[0 .. (1 << 24) - 1 - 8] }};
    try ck.check();
    ck.compressed_certificates = &.{.{ .algorithm = 1, .uncompressed_len = len, .data = huge[0 .. (1 << 24) - 8] }};
    try testing.expectError(error.CompressedLength, ck.check());
    ck.compressed_certificates = &.{.{ .algorithm = 1, .uncompressed_len = len + 1, .data = "x" }};
    try testing.expectError(error.CompressedStale, ck.check());
    // A staple the key does not hold, then one it holds (the length
    // follows it).
    ck.compressed_certificates = &.{.{ .algorithm = 1, .staples = .{ .sct = true }, .uncompressed_len = len, .data = "x" }};
    try testing.expectError(error.CompressedStale, ck.check());
    try testing.expectError(error.InvalidStaples, ck.uncompressedCertificate(&scratch, .{ .sct = true }));
    ck.sct_list = "\x00\x03\x00\x01x";
    try testing.expectError(error.CompressedStale, ck.check());
    ck.compressed_certificates = &.{.{ .algorithm = 1, .staples = .{ .sct = true }, .uncompressed_len = len + 4 + 5, .data = "x" }};
    try ck.check();
    try testing.expectEqual(@as(usize, len + 4 + 5), (try ck.uncompressedCertificate(&scratch, .{ .sct = true })).len);
    try testing.expectError(error.BufferTooSmall, ck.uncompressedCertificate(scratch[0..8], .{}));
}

test "CertifiedKey.certificateDigest is the hash of the message, and catches a same-length staple" {
    // Two certificates, so the entries after the leaf (no staples) count too.
    const chain = [_][]const u8{ &certs.p256_cert, &certs.p256_cert };
    var ck = testKey().*;
    ck.chain = &chain;
    ck.ocsp_response = "\x30\x03\x0a\x01\x00";
    ck.sct_list = "\x00\x03\x00\x01x";
    var scratch: [8192]u8 = undefined;
    for ([_]CertifiedKey.Staples{ .{}, .{ .ocsp = true }, .{ .sct = true }, .{ .ocsp = true, .sct = true } }) |st| {
        var want: [32]u8 = undefined;
        Sha256.hash(try ck.uncompressedCertificate(&scratch, st), &want, .{});
        try testing.expectEqualSlices(u8, &want, &ck.certificateDigest(st).?);
    }
    try testing.expectEqual(null, (CertifiedKey{ .chain = &chain, .key = ck.key }).certificateDigest(.{ .ocsp = true }));

    const st: CertifiedKey.Staples = .{ .ocsp = true };
    const len: u24 = @intCast((try ck.uncompressedCertificate(&scratch, st)).len);
    ck.compressed_certificates = &.{.{ .algorithm = 1, .staples = st, .uncompressed_len = len, .digest = ck.certificateDigest(st).?, .data = "x" }};
    try ck.check();
    // A refreshed staple of the same length: the length cannot tell, the
    // digest can.
    ck.ocsp_response = "\x30\x03\x0a\x01\x01";
    try testing.expectError(error.CompressedStale, ck.check());
    ck.compressed_certificates = &.{.{ .algorithm = 1, .staples = st, .uncompressed_len = len, .data = "x" }};
    try ck.check(); // without a digest, as before
}

test "minOutputLen holds a compressed certificate longer than the chain" {
    var ck = testKey().*;
    const big: [8000]u8 = @splat(0xcd);
    var scratch: [4096]u8 = undefined;
    const len: u24 = @intCast((try ck.uncompressedCertificate(&scratch, .{})).len);
    ck.compressed_certificates = &.{.{ .algorithm = 2, .uncompressed_len = len, .data = &big }};
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    const out = try testing.allocator.alloc(u8, minOutputLen(&cfg, &ck));
    defer testing.allocator.free(out);
    var s: Server = undefined;
    try accept(&s, &cfg, &joiner, out, .{ .compress_certificate = &.{2} });
    defer s.deinit();
}

test "HelloRetryRequest: for the first common group, then one first flight without a second CCS" {
    const r = try retry(x25519_share_first, "", p256_only);
    try testing.expect(r.err == null);
    const p = r.out[0..r.out_len];
    // HRR: a ServerHello with the special random, selected_group P-256.
    try testing.expectEqual(@as(u8, 22), p[0]);
    try testing.expectEqual(@as(u8, 2), p[5]);
    try testing.expectEqualSlices(u8, &messages.hello_retry_request_random, p[11..43]);
    const hrr_len = std.mem.readInt(u16, p[3..5], .big);
    const hrr = p[5..][0..hrr_len];
    try testing.expect(std.mem.indexOf(u8, hrr, &.{ 0, 51, 0, 2, 0, 0x17 }) != null);
    // The CCS, the real ServerHello, then protected records only.
    var at: usize = 5 + hrr_len;
    try testing.expectEqualSlices(u8, &.{ 20, 3, 3, 0, 1, 1 }, p[at..][0..6]);
    at += 6;
    try testing.expectEqual(@as(u8, 22), p[at]);
    try testing.expect(!std.mem.eql(u8, p[at + 11 ..][0..32], &messages.hello_retry_request_random));
    at += 5 + std.mem.readInt(u16, p[at + 3 ..][0..2], .big);
    try testing.expectEqual(@as(u8, 23), p[at]);
}

test "HelloRetryRequest: early data of the first hello is skipped, plaintext and within the budget" {
    var first = x25519_share_first;
    first.early_data = true;
    const early = [_]u8{ 23, 3, 3, 0, 4, 1, 2, 3, 4 };
    const r = try retry(first, &(early ++ early), p256_only);
    try testing.expect(r.err == null);
}

test "HelloRetryRequest: second-hello refusals (rustls)" {
    const Case = struct { second: Hello, err: Error };
    var early = p256_only;
    early.early_data = true;
    var sni = p256_only;
    sni.sni = "other.example";
    var sha384 = p256_only;
    sha384.suites = &.{0x1302};
    const cases = [_]Case{
        // Still no share for the group asked for.
        .{ .second = x25519_share_first, .err = error.IllegalParameter },
        .{ .second = early, .err = error.IllegalParameter },
        .{ .second = sni, .err = error.IllegalParameter },
        // The transcript hash would change.
        .{ .second = sha384, .err = error.IllegalParameter },
    };
    for (cases) |c| {
        const r = try retry(x25519_share_first, "", c.second);
        try testing.expectEqual(c.err, r.err.?);
        // The alert goes out in the clear (no keys yet).
        try testing.expectEqualSlices(u8, &.{ 21, 3, 3, 0, 2, 2, @backingInt(alertFor(c.err).?) }, r.out[r.out_len - 7 .. r.out_len]);
    }
    // The suite and group the HelloRetryRequest named are kept, even where
    // rustls would re-choose: another suite with the same hash, or a share
    // for the client's new first group.
    var chacha = p256_only;
    chacha.suites = &.{0x1303};
    try testing.expectEqual(error.IllegalParameter, (try retry(x25519_share_first, "", chacha)).err.?);
    var regrouped = x25519_share_first;
    regrouped.groups = &.{ 0x001d, 0x0017 };
    try testing.expectEqual(error.IllegalParameter, (try retry(x25519_share_first, "", regrouped)).err.?);
    // Reordered suites: the ServerHello still says 0x1301.
    var reordered = p256_only;
    reordered.suites = &.{ 0x1303, 0x1301 };
    const r = try retry(x25519_share_first, "", reordered);
    try testing.expect(r.err == null);
    const sh = 5 + std.mem.readInt(u16, r.out[3..5], .big) + 6;
    try testing.expectEqualSlices(u8, &.{ 0x13, 0x01 }, r.out[sh + 5 + 4 + 2 + 32 + 1 ..][0..2]);
}

test "RFC 8449: protected records within the client's record_size_limit; the second hello must repeat it" {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    for ([_]u16{ 64, 100, 16385, 0xffff }) |limit| {
        var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
        const out = try testing.allocator.alloc(u8, minOutputLen(&cfg, testKey()));
        defer testing.allocator.free(out);
        var s: Server = .init(&cfg, &joiner, out);
        defer s.deinit();
        const rec = try buildRecord(testing.allocator, .{ .record_size_limit = limit, .sni = "example.com" });
        defer testing.allocator.free(rec);
        _ = try s.feed(rec);
        try testing.expectEqual(@as(?u16, limit), s.peerRecordSizeLimit());
        // ServerHello and CCS in the clear, as they are; then sealed
        // records of at most `limit` octets of TLSInnerPlaintext.
        const p = s.pendingOutput();
        var at: usize = 5 + std.mem.readInt(u16, p[3..5], .big) + 6;
        var records: usize = 0;
        while (at < p.len) : (records += 1) {
            const n = std.mem.readInt(u16, p[at + 3 ..][0..2], .big);
            try testing.expectEqual(@as(u8, 23), p[at]);
            try testing.expect(n - record.tag_len <= @min(limit, 16385));
            at += 5 + n;
        }
        try testing.expectEqual(p.len, at);
        if (limit == 64) try testing.expect(records > 4);
    }
    // A HelloRetryRequest: the second hello must carry the same limit.
    var a = p256_only;
    a.record_size_limit = 1000;
    var b = a;
    b.record_size_limit = 999;
    var first = x25519_share_first;
    first.record_size_limit = 1000;
    try testing.expectEqual(error.IllegalParameter, (try retry(first, "", b)).err.?);
    try testing.expectEqual(error.IllegalParameter, (try retry(first, "", p256_only)).err.?);
    try testing.expectEqual(error.IllegalParameter, (try retry(x25519_share_first, "", a)).err.?);
    try testing.expect((try retry(first, "", a)).err == null);
}

test "minOutputLen holds a HelloRetryRequest and the first flight undrained" {
    var prng = std.Random.DefaultPrng.init(1);
    const ck = testKey();
    const cfg: Config = .{ .certificate = .{ .fixed = ck }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    const out = try testing.allocator.alloc(u8, minOutputLen(&cfg, ck));
    defer testing.allocator.free(out);
    var s: Server = .init(&cfg, &joiner, out);
    defer s.deinit();
    const r1 = try buildRecord(testing.allocator, x25519_share_first);
    defer testing.allocator.free(r1);
    _ = try s.feed(r1);
    const r2 = try buildRecord(testing.allocator, p256_only);
    defer testing.allocator.free(r2);
    _ = try s.feed(r2);
    try testing.expectEqual(State.client_finished, s.state);
}

test "HelloRetryRequest: a first hello sharing its record with the next message is unexpected" {
    var first = x25519_share_first;
    first.trailing = &.{ 1, 0, 0 };
    try expectRefusal(first, error.UnexpectedMessage, .unexpected_message);
}

/// A server past the client's Finished, built white-box (the Finished comes
/// from the server's own secrets), with the client's side of the
/// application keys: `tx` seals what the client sends, `rx` opens what the
/// server sends, each following the KeyUpdates.
const Peer = struct {
    prng: std.Random.DefaultPrng,
    cfg: Config,
    joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8,
    out: [32 * 1024]u8,
    in: [record.max_record_len]u8,
    s: Server,
    tx: record.Protection,
    rx: record.Protection,
    tx_secret: [32]u8,
    rx_secret: [32]u8,

    fn create() !*Peer {
        const p = try testing.allocator.create(Peer);
        errdefer testing.allocator.destroy(p);
        p.prng = .init(1);
        p.cfg = .{ .certificate = .{ .fixed = testKey() }, .random = p.prng.random() };
        p.s = .init(&p.cfg, &p.joiner, &p.out);
        const rec = try buildRecord(testing.allocator, .{});
        defer testing.allocator.free(rec);
        _ = try p.s.feed(rec);
        const th = p.s.transcript.sha256.currentHash();
        var fk: [32]u8 = undefined;
        ks.deriveFinishedKey(S256.Hkdf, 32, &fk, p.s.client_handshake_secret[0..32]);
        var fin: [36]u8 = undefined;
        fin[0..4].* = .{ 20, 0, 0, 32 };
        tls13.keyschedule.computeFinishedVerifyData(S256.Hmac, fin[4..36], &fk, &th);
        var hs: record.Protection = undefined;
        try hs.init(.aes_128_gcm_sha256, p.s.client_handshake_secret[0..32]);
        @memcpy(p.in[5..][0..fin.len], &fin);
        const r = try p.s.feed(try hs.seal(&p.in, fin.len, .handshake, 0));
        try testing.expect(r.event == .handshake_done);
        p.tx_secret = p.s.client_application_secret[0..32].*;
        p.rx_secret = p.s.server_application_secret[0..32].*;
        try p.tx.init(.aes_128_gcm_sha256, &p.tx_secret);
        try p.rx.init(.aes_128_gcm_sha256, &p.rx_secret);
        // The first flight went out under the handshake keys.
        p.s.discardOutput(p.s.pendingOutput().len);
        return p;
    }

    fn destroy(p: *Peer) void {
        p.s.deinit();
        testing.allocator.destroy(p);
    }

    /// Seal `content` as one client record and feed it.
    fn send(p: *Peer, ct: record.ContentType, content: []const u8) Error!Result {
        @memcpy(p.in[5..][0..content.len], content);
        const sealed = p.tx.seal(&p.in, content.len, ct, 0) catch unreachable;
        return p.s.feed(sealed);
    }

    /// The client turns its key over after sending this record.
    fn sendKeyUpdate(p: *Peer, request: u8) Error!Result {
        const r = p.send(.handshake, &.{ 24, 0, 0, 1, request });
        ks.nextApplicationTrafficSecret(S256.Hkdf, &p.tx_secret, &p.tx_secret);
        p.tx.init(.aes_128_gcm_sha256, &p.tx_secret) catch unreachable;
        return r;
    }

    const Drained = struct {
        /// The request octet of each KeyUpdate, in order.
        updates: [8]u8 = undefined,
        n_updates: usize = 0,
        app: [256]u8 = undefined,
        app_len: usize = 0,
        alerts: usize = 0,
    };

    /// Open everything the server queued, following its KeyUpdates.
    fn drain(p: *Peer) !Drained {
        var d: Drained = .{};
        var buf: [32 * 1024]u8 = undefined;
        const pending = p.s.pendingOutput();
        @memcpy(buf[0..pending.len], pending);
        p.s.discardOutput(pending.len);
        var at: usize = 0;
        while (at < pending.len) {
            const h = record.parseHeader(buf[at..][0..5]);
            const o = try p.rx.open(buf[at..][0 .. 5 + h.length]);
            at += 5 + h.length;
            switch (o.content_type) {
                .handshake => {
                    try testing.expectEqualSlices(u8, &.{ 24, 0, 0, 1 }, o.content[0..4]);
                    try testing.expectEqual(@as(usize, 5), o.content.len);
                    d.updates[d.n_updates] = o.content[4];
                    d.n_updates += 1;
                    ks.nextApplicationTrafficSecret(S256.Hkdf, &p.rx_secret, &p.rx_secret);
                    try p.rx.init(.aes_128_gcm_sha256, &p.rx_secret);
                },
                .application_data => {
                    const n = @min(o.content.len, d.app.len - d.app_len);
                    @memcpy(d.app[d.app_len..][0..n], o.content[0..n]);
                    d.app_len += n;
                },
                .alert => d.alerts += 1,
                else => return error.UnexpectedRecord,
            }
        }
        return d;
    }
};

test "KeyUpdate from the client: update_not_requested turns only the receive key" {
    const p = try Peer.create();
    defer p.destroy();
    for (0..3) |_| {
        try testing.expect((try p.sendKeyUpdate(0)).event == .need_more);
        const r = try p.send(.application_data, "ping");
        try testing.expectEqualStrings("ping", r.event.app_data);
    }
    // Nothing went back; the server still sends under its first key.
    try testing.expectEqual(@as(usize, 0), p.s.pendingOutput().len);
    _ = try p.s.write("pong");
    const d = try p.drain();
    try testing.expectEqual(@as(usize, 0), d.n_updates);
    try testing.expectEqualStrings("pong", d.app[0..d.app_len]);
}

test "deinit wipes the output a handshake and records wrote, and an open slot's data, committed or not" {
    for ([_]?usize{ null, 10 }) |abandon| {
        const p = try Peer.create();
        defer testing.allocator.destroy(p);
        // Past the mark nothing was written (the buffer started undefined).
        @memset(p.out[p.s.out.dirty..], 0);
        _ = try p.s.write("sealed");
        const slot = try p.s.writeSlot();
        @memset(slot[0..100], 0xee);
        const flight = p.s.out.dirty;
        if (abandon) |n| p.s.abandonWrite(n);
        // Abandoned after 10 octets: the 90 past them count as never written.
        const end = @intFromPtr(slot.ptr) - @intFromPtr(&p.out) + (abandon orelse 100);
        if (abandon != null) try testing.expectEqual(@max(flight, end), p.s.out.dirty);
        p.s.deinit();
        for (p.out[0..end]) |x| try testing.expectEqual(@as(u8, 0), x);
    }
}

test "KeyUpdate from the client: update_requested is answered once, before the next record" {
    const p = try Peer.create();
    defer p.destroy();
    _ = try p.sendKeyUpdate(1);
    // The reply is queued at once: sealed under the old key.
    try testing.expect(p.s.pendingOutput().len != 0);
    try testing.expect(p.s.tx_update == null);
    _ = try p.s.write("a");
    var d = try p.drain();
    try testing.expectEqual(@as(usize, 1), d.n_updates);
    try testing.expectEqual(@as(u8, 0), d.updates[0]);
    try testing.expectEqualStrings("a", d.app[0..d.app_len]);

    // Several requests before the reply can go out (the output is full):
    // one reply.
    // Whole records while one fits, then single octets to the brim.
    while (p.s.out.slot().len > 64) _ = p.s.write(&@as([1024]u8, @splat('x'))) catch break;
    while (p.s.out.slot().len > 0) _ = p.s.write("y") catch break;
    for (0..3) |_| _ = try p.sendKeyUpdate(1);
    try testing.expectEqual(KeyUpdateRequest.update_not_requested, p.s.tx_update.?);
    try testing.expectError(error.OutputFull, p.s.write("z"));
    _ = try p.drain();
    _ = try p.s.write("z");
    d = try p.drain();
    try testing.expectEqual(@as(usize, 1), d.n_updates);
    try testing.expectEqualStrings("z", d.app[0..d.app_len]);
    // The client's data still opens under its third next key.
    try testing.expectEqualStrings("q", (try p.send(.application_data, "q")).event.app_data);
}

test "KeyUpdate from the client: a due reply also goes out from feed once there is room" {
    const p = try Peer.create();
    defer p.destroy();
    // Whole records while one fits, then single octets to the brim.
    while (p.s.out.slot().len > 64) _ = p.s.write(&@as([1024]u8, @splat('x'))) catch break;
    while (p.s.out.slot().len > 0) _ = p.s.write("y") catch break;
    _ = try p.sendKeyUpdate(1);
    try testing.expect(p.s.tx_update != null);
    _ = try p.drain();
    var empty: [0]u8 = .{};
    _ = try p.s.feed(&empty);
    try testing.expect(p.s.tx_update == null);
    try testing.expectEqual(@as(usize, 1), (try p.drain()).n_updates);
}

test "extractSecrets: the record keys and sequence numbers a kTLS socket continues with" {
    const p = try Peer.create();
    defer p.destroy();
    var x: Server.ExtractedSecrets = undefined;
    try testing.expectError(error.SecretExtractionDisabled, p.s.extractSecrets(&x));
    p.cfg.enable_secret_extraction = true;
    // Traffic both ways, a client KeyUpdate: neither sequence is 0, the
    // receive key is the second one.
    _ = try p.send(.application_data, "a");
    _ = try p.sendKeyUpdate(0);
    _ = try p.send(.application_data, "b");
    try testing.expectEqual(@as(usize, 1), try p.s.write("c"));
    try testing.expectError(error.NotQuiescent, p.s.extractSecrets(&x));
    {
        const sent = p.s.pendingOutput();
        @memcpy(p.in[0..sent.len], sent);
        try testing.expectEqualStrings("c", (try p.rx.open(p.in[0..sent.len])).content);
        p.s.discardOutput(sent.len);
    }
    // A send key at its record limit is not handed over: KeyUpdate first.
    {
        const seq = p.s.out.tx.seq;
        p.s.out.tx.seq = max_records_per_key;
        try testing.expectError(error.NotQuiescent, p.s.extractSecrets(&x));
        p.s.out.tx.seq = seq;
    }
    try p.s.extractSecrets(&x);
    defer x.wipe();
    try testing.expectEqual(record.CipherSuite.aes_128_gcm_sha256, x.suite);
    try testing.expectEqual(@as(u8, 16), x.tx.key_len);
    try testing.expectEqual(@as(u64, 1), x.tx.seq);
    try testing.expectEqual(@as(u64, 1), x.rx.seq);
    // The server's side, continued outside: its next record opens at the
    // client; the client's next record opens under the extracted key.
    var tx: record.Protection = undefined;
    try tx.initKeyIv(x.suite, x.tx.key[0..x.tx.key_len], &x.tx.iv);
    tx.seq = x.tx.seq;
    var buf: [64]u8 = undefined;
    @memcpy(buf[5..][0..1], "d");
    const r1 = try tx.seal(&buf, 1, .application_data, 0);
    try testing.expectEqualStrings("d", (try p.rx.open(r1)).content);
    var rx: record.Protection = undefined;
    try rx.initKeyIv(x.suite, x.rx.key[0..x.rx.key_len], &x.rx.iv);
    rx.seq = x.rx.seq;
    @memcpy(p.in[5..][0..1], "e");
    const r2 = try p.tx.seal(&p.in, 1, .application_data, 0);
    try testing.expectEqualStrings("e", (try rx.open(r2)).content);
    // The server is done with: every secret gone, nothing more works.
    try testing.expect(!p.s.isConnected());
    try testing.expectError(error.Closed, p.s.write("f"));
    try testing.expect(std.mem.allEqual(u8, &p.s.server_application_secret, 0));
    try testing.expect(std.mem.allEqual(u8, &p.s.client_application_secret, 0));
    try testing.expectError(error.NotConnected, p.s.extractSecrets(&x));
}

test "KeyUpdate refusals: request octet, length, alignment, too many" {
    {
        const p = try Peer.create();
        defer p.destroy();
        try testing.expectError(error.IllegalParameter, p.sendKeyUpdate(2));
    }
    for ([_][]const u8{ &.{ 24, 0, 0, 2, 0, 0 }, &.{ 24, 0, 0, 0 } }) |msg| {
        const p = try Peer.create();
        defer p.destroy();
        try testing.expectError(error.DecodeError, p.send(.handshake, msg));
    }
    {
        // A KeyUpdate must end its record: the next message's start would
        // be read under the new key (RFC 8446 §5.1).
        const p = try Peer.create();
        defer p.destroy();
        try testing.expectError(error.UnexpectedMessage, p.send(.handshake, &.{ 24, 0, 0, 1, 0, 24, 0 }));
        // Each alert went out sealed (under the key in force).
        try testing.expectEqual(@as(usize, 1), (try p.drain()).alerts);
    }
    {
        // max_key_updates in a row are fine; one more is not.
        const p = try Peer.create();
        defer p.destroy();
        for (0..max_key_updates) |_| _ = try p.sendKeyUpdate(0);
        try testing.expectEqualStrings("x", (try p.send(.application_data, "x")).event.app_data);
        // Application data resets the count.
        for (0..max_key_updates) |_| _ = try p.sendKeyUpdate(0);
        try testing.expectError(error.TooManyKeyUpdates, p.sendKeyUpdate(0));
        const d = try p.drain();
        try testing.expectEqual(@as(usize, 1), d.alerts);
    }
    {
        // An empty application_data record does not reset it: KeyUpdates
        // interleaved with empty records still hit the cap.
        const p = try Peer.create();
        defer p.destroy();
        for (0..max_key_updates) |_| _ = try p.sendKeyUpdate(0);
        try testing.expectEqual(@as(usize, 0), (try p.send(.application_data, "")).event.app_data.len);
        try testing.expectError(error.TooManyKeyUpdates, p.sendKeyUpdate(0));
    }
    {
        // Other post-handshake messages: NewSessionTicket from a client.
        const p = try Peer.create();
        defer p.destroy();
        try testing.expectError(error.UnexpectedMessage, p.send(.handshake, &.{ 4, 0, 0, 0 }));
    }
}

test "the server turns its own key over: on request, and at max_records_per_key" {
    const p = try Peer.create();
    defer p.destroy();
    try p.s.keyUpdate(.update_not_requested);
    _ = try p.s.write("1");
    var d = try p.drain();
    try testing.expectEqual(@as(usize, 1), d.n_updates);
    try testing.expectEqual(@as(u8, 0), d.updates[0]);
    try testing.expectEqualStrings("1", d.app[0..d.app_len]);

    // At the limit the next record is preceded by update_requested; the
    // sequence restarts under the new key.
    p.s.out.tx.seq = max_records_per_key - 1;
    p.rx.seq = max_records_per_key - 1;
    _ = try p.s.write("2");
    _ = try p.s.write("3");
    d = try p.drain();
    try testing.expectEqual(@as(usize, 1), d.n_updates);
    try testing.expectEqual(@as(u8, 1), d.updates[0]);
    try testing.expectEqualStrings("23", d.app[0..d.app_len]);
    try testing.expectEqual(@as(u64, 1), p.s.out.tx.seq);
    // The client answers; its data still opens.
    _ = try p.sendKeyUpdate(0);
    try testing.expectEqualStrings("ok", (try p.send(.application_data, "ok")).event.app_data);
}

test "after close_notify a requested KeyUpdate is not answered, and keyUpdate is refused" {
    const p = try Peer.create();
    defer p.destroy();
    try p.s.close();
    _ = try p.sendKeyUpdate(1);
    try testing.expect(p.s.tx_update == null);
    try testing.expectError(error.Closed, p.s.keyUpdate(.update_requested));
    // Only the close_notify went out.
    const d = try p.drain();
    try testing.expectEqual(@as(usize, 0), d.n_updates);
    try testing.expectEqual(@as(usize, 1), d.alerts);
}

test "keyUpdate before the handshake completes is NotConnected" {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [4096]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    try testing.expectError(error.NotConnected, s.keyUpdate(.update_requested));
}

test "a full output still takes the fatal alert, or close_notify" {
    {
        const p = try Peer.create();
        defer p.destroy();
        while (true) _ = p.s.write(&@as([1024]u8, @splat('x'))) catch break;
        try testing.expectError(error.IllegalParameter, p.sendKeyUpdate(7));
        const d = try p.drain();
        try testing.expectEqual(@as(usize, 1), d.alerts);
    }
    {
        const p = try Peer.create();
        defer p.destroy();
        while (true) _ = p.s.write(&@as([1024]u8, @splat('x'))) catch break;
        try p.s.close();
        try testing.expectEqual(@as(usize, 1), (try p.drain()).alerts);
    }
}

/// `f` written as `issueTickets` does: its peer copied to its place first.
fn testTicketFields(buf: []u8, f: TicketFields) []u8 {
    var g = f;
    if (f.peer) |p| {
        @memcpy(buf[TicketFields.head_max..][0..p.len], p);
        g.peer = buf[TicketFields.head_max..][0..p.len];
    }
    return g.writeAround(buf, TicketFields.head_max);
}

test "ticket fields: round trip, and what a ClientHello may resume" {
    const cap = 8192;
    var buf: [TicketFields.head_max + cap + 1 + TicketFields.tail_len]u8 = undefined;
    const long_alpn: [255]u8 = @splat('a');
    const long_sni: [253]u8 = @splat('b');
    const long_peer: [cap]u8 = @splat('c');
    for ([_]TicketFields{
        .{ .sni = "example.com", .alpn = "h2", .peer = null, .suite = 0x1302 },
        .{ .sni = null, .alpn = null, .peer = "LEAF", .peer_scheme = 0x0804, .suite = 0x1301 },
        .{ .sni = null, .alpn = null, .peer = "SPKI", .peer_raw = true, .peer_scheme = 0x0403, .suite = 0x1301 },
        // A raw-key flag without a key is not written (format 3).
        .{ .sni = "x", .alpn = null, .peer = null, .peer_raw = true, .suite = 0x1301 },
        // QUIC (formats 5, 6): with the stack's resumption data, empty or not.
        .{ .sni = "x", .alpn = "h3", .peer = null, .quic = true, .app = "TP", .suite = 0x1301 },
        .{ .sni = null, .alpn = "h3", .peer = "SPKI", .peer_raw = true, .quic = true, .suite = 0x1302 },
        .{ .sni = &long_sni, .alpn = &long_alpn, .peer = &long_peer, .peer_scheme = 0x0403, .peer_auth_ms = -2, .max_early_data = 0xfedc_ba98, .suite = 0x1303 },
    }) |f| {
        const w = testTicketFields(&buf, f);
        const n = w.len;
        const back = TicketFields.parse(w, cap).?;
        try testing.expect(Server.optEql(f.sni, back.sni) and Server.optEql(f.alpn, back.alpn) and
            Server.optEql(f.peer, back.peer) and f.peer_scheme == back.peer_scheme and f.suite == back.suite);
        try testing.expectEqual(f.peer_raw and f.peer != null, back.peer_raw);
        try testing.expectEqual(f.quic, back.quic);
        // An empty field reads back as none.
        try testing.expect(Server.optEql(if (f.quic and (f.app orelse @as([]const u8, "")).len != 0) f.app else null, back.app));
        try testing.expectEqual(f.peer_auth_ms, back.peer_auth_ms);
        try testing.expectEqual(f.max_early_data, back.max_early_data);
        // Every truncation, an extra octet and another format are refused.
        for (0..n) |cut| try testing.expect(TicketFields.parse(w[0..cut], cap) == null);
        const start = w.ptr - &buf;
        if (start + n < buf.len) {
            buf[start + n] = 0;
            try testing.expect(TicketFields.parse(buf[start..][0 .. n + 1], cap) == null);
        }
        w[0] ^= 1;
        try testing.expect(TicketFields.parse(w, cap) == null);
    }
    // A peer longer than the cap is not this server's.
    const too_long: [cap + 1]u8 = @splat('d');
    try testing.expect(TicketFields.parse(testTicketFields(&buf, .{ .sni = null, .alpn = null, .peer = &too_long, .suite = 0x1301 }), cap) == null);
    try testing.expect(TicketFields.parse(testTicketFields(&buf, .{ .sni = null, .alpn = null, .peer = "LEAF", .suite = 0x1301 }), 3) == null);

    const tail = testTicketFields(&buf, .{ .sni = "example.com", .alpn = null, .peer = null, .suite = 0x1301 });
    var want: Resumable = .{ .suite = 0x1301, .sni = "example.com", .lifetime_ms = 1000 };
    try testing.expect(want.accepts(tail, 0));
    try testing.expect(want.accepts(tail, 1000));
    try testing.expect(!want.accepts(tail, 1001));
    var other = want;
    other.suite = 0x1303; // same hash, another suite
    try testing.expect(!other.accepts(tail, 0));
    other = want;
    other.sni = "example.org";
    try testing.expect(!other.accepts(tail, 0));
    other.sni = null;
    try testing.expect(!other.accepts(tail, 0));
    const t2 = testTicketFields(&buf, .{ .sni = null, .alpn = null, .peer = null, .suite = 0x1301 });
    try testing.expect(other.accepts(t2, 0));
    try testing.expect(!want.accepts(t2, 0));

    // A mandatory client certificate: only a ticket that carries one, which
    // is handed out.
    var need: Resumable = .{ .suite = 0x1301, .sni = null, .lifetime_ms = 1000, .need_peer = true, .max_peer = cap };
    try testing.expect(!need.accepts(t2, 0));
    try testing.expectEqual(null, need.peer);
    const t3 = testTicketFields(&buf, .{ .sni = null, .alpn = null, .peer = "LEAF", .peer_scheme = 0x0807, .suite = 0x1301 });
    try testing.expect(need.accepts(t3, 0));
    try testing.expectEqualStrings("LEAF", need.peer.?);
    try testing.expectEqual(@as(u16, 0x0807), need.peer_scheme);
    // RFC 7250: a client key resumes only as the type negotiated now — a
    // raw public key never as a certificate, nor the other way round; a
    // format-4 ticket without a key is not this server's.
    {
        var raw = need;
        raw.peer_raw = true;
        try testing.expect(!raw.accepts(t3, 0));
        const t_raw = testTicketFields(&buf, .{ .sni = null, .alpn = null, .peer = "SPKI", .peer_raw = true, .suite = 0x1301 });
        try testing.expect(raw.accepts(t_raw, 0));
        try testing.expect(!need.accepts(t_raw, 0));
        // A ticket resumes only on the transport it was issued over.
        var over_quic = raw;
        over_quic.quic = true;
        try testing.expect(!over_quic.accepts(t_raw, 0));
        const t_quic = testTicketFields(&buf, .{ .sni = null, .alpn = null, .peer = "SPKI", .peer_raw = true, .quic = true, .app = "TP", .suite = 0x1301 });
        try testing.expect(!raw.accepts(t_quic, 0));
        try testing.expect(over_quic.accepts(t_quic, 0));
        try testing.expectEqualStrings("TP", over_quic.app.?);
        var no_key = testTicketFields(&buf, .{ .sni = null, .alpn = null, .peer = null, .suite = 0x1301 });
        no_key[0] = TicketFields.format_raw;
        try testing.expect(TicketFields.parse(no_key, cap) == null);
    }
    // The certificate is good for the lifetime from its proof, whatever
    // the ticket's own age (a re-issued ticket is young).
    const t4 = testTicketFields(&buf, .{ .sni = null, .alpn = null, .peer = "LEAF", .peer_auth_ms = 5_000, .suite = 0x1301 });
    need.now_ms = 6_000;
    try testing.expect(need.accepts(t4, 0));
    try testing.expectEqual(@as(i64, 5_000), need.peer_auth_ms);
    need.now_ms = 6_001;
    try testing.expect(!need.accepts(t4, 0));
    need.now_ms = 4_999; // proved in the future
    try testing.expect(!need.accepts(t4, 0));
    // Without client authentication (no cap) a ticket with a leaf is not resumed.
    var anon: Resumable = .{ .suite = 0x1301, .sni = null, .lifetime_ms = 1000 };
    try testing.expect(!anon.accepts(testTicketFields(&buf, .{ .sni = null, .alpn = null, .peer = "LEAF", .suite = 0x1301 }), 0));
    try testing.expect(anon.accepts(testTicketFields(&buf, .{ .sni = null, .alpn = null, .peer = null, .suite = 0x1301 }), 0));
}

test "CacheTicketer: a random id for the cached state, opened once" {
    const Cache = SessionCache(0);
    var cache: Cache = try .init(testing.allocator, 2, 100);
    defer cache.deinit();
    const Fixed = struct {
        fn now(_: ?*anyopaque) i64 {
            return 50_999;
        }
    };
    var prng = std.Random.DefaultPrng.init(3);
    const ct: CacheTicketer(Cache) = .{ .cache = &cache, .clock = .{ .now_ms = Fixed.now }, .random = prng.random() };
    const t = ct.ticketer();
    var room: [64]u8 = undefined;
    // Too little room for the id: nothing is stored.
    try testing.expect(t.seal(t.ctx, "state", @splat(0), room[0 .. cache_id_len - 1]) == null);
    try testing.expectEqual(@as(usize, 0), cache.count());
    var id_a: [cache_id_len]u8 = undefined;
    @memcpy(&id_a, t.seal(t.ctx, "state-a", @splat(0), &room).?);
    var id_b: [cache_id_len]u8 = undefined;
    @memcpy(&id_b, t.seal(t.ctx, "state-b", @splat(0), &room).?);
    try testing.expect(!std.mem.eql(u8, &id_a, &id_b));
    // A plaintext over the cache's entries is not sealed.
    const big: [ticketStateLen(0) + 1]u8 = @splat(1);
    try testing.expect(t.seal(t.ctx, &big, @splat(0), &room) == null);

    var out: [ticketStateLen(0)]u8 = undefined;
    // Not an id: wrong length, or a prefix of one.
    try testing.expect(t.open(t.ctx, id_a[0 .. cache_id_len - 1], 50, &out) == null);
    try testing.expectEqualStrings("state-a", t.open(t.ctx, &id_a, 50, &out).?);
    try testing.expect(t.open(t.ctx, &id_a, 50, &out) == null); // taken
    // Stored at second 50 (the clock's, floored): gone at the timeout.
    try testing.expect(t.open(t.ctx, &id_b, 150, &out) == null);
    try testing.expectEqual(@as(usize, 0), cache.count());
    const guard = ct.replayGuard();
    try testing.expect(guard.admit(guard.ctx, &id_a, 0));
}

test "tickets only for a client that offers psk_dhe_ke (rustls)" {
    const T = struct {
        fn seal(_: *const anyopaque, _: []const u8, _: [12]u8, _: []u8) ?[]u8 {
            return null;
        }
        fn open(_: *const anyopaque, _: []const u8, _: i64, _: []u8) ?[]u8 {
            return null;
        }
        fn now(_: ?*anyopaque) i64 {
            return 0;
        }
    };
    const none: u8 = 0;
    const tickets: Tickets = .{ .ticketer = .{ .ctx = &none, .seal = T.seal, .open = T.open }, .clock = .{ .now_ms = T.now }, .count = 3 };
    for ([_]struct { ?[]const u8, u8 }{ .{ null, 0 }, .{ &.{0}, 0 }, .{ &.{ 0, 2 }, 0 }, .{ &.{1}, 3 }, .{ &.{ 0, 1 }, 3 } }) |c| {
        var prng = std.Random.DefaultPrng.init(1);
        const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .tickets = &tickets };
        var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
        var out: [32 * 1024]u8 = undefined;
        var s: Server = .init(&cfg, &joiner, &out);
        defer s.deinit();
        const rec = try buildRecord(testing.allocator, .{ .psk_modes = c[0] });
        defer testing.allocator.free(rec);
        _ = try s.feed(rec);
        try testing.expectEqual(c[1], s.tickets_due);
        try testing.expect(!s.isResumed());
    } // A lifetime of 0 issues none (RFC 8446 §4.6.1: 0 = discard it).
    var zero = tickets;
    zero.lifetime_s = 0;
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .tickets = &zero };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    const rec = try buildRecord(testing.allocator, .{ .psk_modes = &.{1} });
    defer testing.allocator.free(rec);
    _ = try s.feed(rec);
    try testing.expectEqual(@as(u8, 0), s.tickets_due);
}

// ── 0-RTT ────────────────────────────────────────────────────────────────

const NoTickets = struct {
    fn seal(_: *const anyopaque, _: []const u8, _: [12]u8, _: []u8) ?[]u8 {
        return null;
    }
    fn open(_: *const anyopaque, _: []const u8, _: i64, _: []u8) ?[]u8 {
        return null;
    }
    fn now(_: ?*anyopaque) i64 {
        return 0;
    }
    const none: u8 = 0;
    const tickets: Tickets = .{ .ticketer = .{ .ctx = &none, .seal = seal, .open = open }, .clock = .{ .now_ms = now } };
};

/// Counts its calls; admits while `answer`.
const CountingGuard = struct {
    asked: usize = 0,
    answer: bool = true,

    fn guard(g: *CountingGuard) ReplayGuard {
        return .{ .ctx = g, .admit = admit };
    }

    fn admit(ctx: ?*anyopaque, ticket: []const u8, _: i64) bool {
        const g: *CountingGuard = @ptrCast(@alignCast(ctx.?));
        std.debug.assert(std.mem.eql(u8, ticket, "TICKET"));
        g.asked += 1;
        return g.answer;
    }
};

test "early data: BoringSSL's order of reasons, the replay guard asked last" {
    var g: CountingGuard = .{};
    var early: EarlyData = .{ .replay = g.guard() };
    var prng = std.Random.DefaultPrng.init(1);
    var cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .tickets = &NoTickets.tickets, .early_data = &early };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    const Parsed = struct {
        rec: []u8,
        ch: hello.ClientHello,
        fn of(h: Hello) !@This() {
            const rec = try buildRecord(testing.allocator, h);
            errdefer testing.allocator.free(rec);
            return .{ .rec = rec, .ch = try hello.parseClientHello(rec[5 + 4 ..]) };
        }
    };
    const offer = try Parsed.of(.{ .psk_without_modes = true, .early_data = true });
    defer testing.allocator.free(offer.rec);
    const no_early = try Parsed.of(.{ .psk_without_modes = true });
    defer testing.allocator.free(no_early.rec);
    const no_psk = try Parsed.of(.{ .early_data = true });
    defer testing.allocator.free(no_psk.rec);
    var taken: PskTaken = .{ .identity = "TICKET", .max_early_data = 14336 };
    taken.alpn_buf[0..2].* = "h2".*;

    // What is checked before the ticket.
    try testing.expectEqual(EarlyDataReason.accepted, s.decideEarlyData(&offer.ch, true, &taken));
    try testing.expectEqual(@as(usize, 1), g.asked);
    cfg.early_data = null;
    try testing.expectEqual(EarlyDataReason.disabled, s.decideEarlyData(&offer.ch, true, &taken));
    cfg.early_data = &early;
    cfg.tickets = null;
    try testing.expectEqual(EarlyDataReason.disabled, s.decideEarlyData(&offer.ch, true, &taken));
    cfg.tickets = &NoTickets.tickets;
    early.max_size = 0;
    try testing.expectEqual(EarlyDataReason.disabled, s.decideEarlyData(&offer.ch, true, &taken));
    early.max_size = 14336;
    try testing.expectEqual(EarlyDataReason.no_session_offered, s.decideEarlyData(&no_psk.ch, true, &taken));
    try testing.expectEqual(EarlyDataReason.session_not_resumed, s.decideEarlyData(&offer.ch, false, &taken));
    s.early_hrr = true;
    try testing.expectEqual(EarlyDataReason.hello_retry_request, s.decideEarlyData(&offer.ch, true, &taken));
    s.early_hrr = false;
    try testing.expectEqual(EarlyDataReason.peer_declined, s.decideEarlyData(&no_early.ch, true, &taken));

    // What the ticket must match (RFC 8446 §4.2.10).
    var t = taken;
    t.max_early_data = 0;
    try testing.expectEqual(EarlyDataReason.unsupported_for_session, s.decideEarlyData(&offer.ch, true, &t));
    t = taken;
    t.index = 1;
    try testing.expectEqual(EarlyDataReason.not_first_identity, s.decideEarlyData(&offer.ch, true, &t));
    t = taken;
    t.alpn_len = 2;
    try testing.expectEqual(EarlyDataReason.alpn_mismatch, s.decideEarlyData(&offer.ch, true, &t));
    s.alpn = "h2";
    try testing.expectEqual(EarlyDataReason.alpn_mismatch, s.decideEarlyData(&offer.ch, true, &taken));
    try testing.expectEqual(EarlyDataReason.accepted, s.decideEarlyData(&offer.ch, true, &t));
    s.alpn = null;
    for ([_]struct { i64, EarlyDataReason }{ .{ 60, .accepted }, .{ -60, .accepted }, .{ 61, .ticket_age_skew }, .{ -61, .ticket_age_skew } }) |c| {
        s.age_skew_s = c[0];
        try testing.expectEqual(c[1], s.decideEarlyData(&offer.ch, true, &taken));
    }
    s.age_skew_s = 0;
    try testing.expectEqual(@as(usize, 4), g.asked);

    // The guard, last: its refusal is the reason.
    g.answer = false;
    try testing.expectEqual(EarlyDataReason.replayed, s.decideEarlyData(&offer.ch, true, &taken));
    try testing.expectEqual(@as(usize, 5), g.asked);
    try testing.expectEqualStrings("accept", EarlyDataReason.accepted.name());
    try testing.expectEqualStrings("ticket_age_skew", EarlyDataReason.ticket_age_skew.name());
}

/// A server white-box in the early-data state: the client's early secret
/// (`early_secret`) installed, its handshake secret all `0x22`.
fn earlyServer(s: *Server, early_secret: []const u8) !void {
    s.suite = .aes_128_gcm_sha256;
    s.has_suite = true;
    s.startTranscript(s.suite);
    s.early_reason = .accepted;
    s.client_handshake_secret = @splat(0x22);
    try s.inbound.installRx(s.suite, early_secret);
    s.inbound.handshake_seen = true;
    s.inbound.early_data_ok = true;
    s.early_left = 4;
    s.state = .early_data;
}

test "early data: EndOfEarlyData (empty, a message of its own) switches to the handshake secret" {
    var g: CountingGuard = .{};
    const early: EarlyData = .{ .replay = g.guard() };
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .tickets = &NoTickets.tickets, .early_data = &early };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    const secret: [32]u8 = @splat(0x11);
    {
        var s: Server = .init(&cfg, &joiner, &out);
        defer s.deinit();
        try earlyServer(&s, &secret);
        try testing.expect(s.inEarlyData() and s.canWrite() and !s.isConnected());
        try testing.expectError(error.DecodeError, s.onHandshake(handshakeMessage(&.{ 5, 0, 0, 1, 0 })));
    }
    for ([_]u8{ 0, 1, 15, 20, 24 }) |t| {
        var s: Server = .init(&cfg, &joiner, &out);
        defer s.deinit();
        try earlyServer(&s, &secret);
        try testing.expectError(error.UnexpectedMessage, s.onHandshake(handshakeMessage(&.{ t, 0, 0, 0 })));
    }
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    try earlyServer(&s, &secret);
    try testing.expect(try s.onHandshake(handshakeMessage(&.{ 5, 0, 0, 0 })) == null);
    try testing.expectEqual(State.client_finished, s.state);
    try testing.expect(!s.inEarlyData() and !s.inbound.early_data_ok and s.canWrite());
    // Records now open under the handshake secret, not the early one.
    var tx: record.Protection = undefined;
    try tx.init(.aes_128_gcm_sha256, &(@as([32]u8, @splat(0x22))));
    defer tx.wipe();
    var rec: [64]u8 = undefined;
    const fin = [_]u8{ 20, 0, 0, 32 } ++ @as([32]u8, @splat(0));
    @memcpy(rec[record.header_len..][0..fin.len], &fin);
    const r = try tx.seal(&rec, fin.len, .handshake, 0);
    try testing.expectError(error.DecryptError, s.feed(rec[0..r.len]));

    // Application data under the handshake secret, after EndOfEarlyData
    // and before the Finished, is no early data any more.
    var s2: Server = .init(&cfg, &joiner, &out);
    defer s2.deinit();
    try earlyServer(&s2, &secret);
    _ = try s2.onHandshake(handshakeMessage(&.{ 5, 0, 0, 0 }));
    var tx2: record.Protection = undefined;
    try tx2.init(.aes_128_gcm_sha256, &(@as([32]u8, @splat(0x22))));
    defer tx2.wipe();
    @memcpy(rec[record.header_len..][0..2], "hi");
    const r2 = try tx2.seal(&rec, 2, .application_data, 0);
    try testing.expectError(error.UnexpectedMessage, s2.feed(rec[0..r2.len]));
}

test "early data: max_size is a budget of plaintext octets, more is unexpected_message" {
    var g: CountingGuard = .{};
    const early: EarlyData = .{ .replay = g.guard() };
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .tickets = &NoTickets.tickets, .early_data = &early };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    const secret: [32]u8 = @splat(0x11);
    var tx: record.Protection = undefined;
    try tx.init(.aes_128_gcm_sha256, &secret);
    defer tx.wipe();
    var recs: [128]u8 = undefined;
    var n: usize = 0;
    for ([_][]const u8{ "abc", "d", "e" }) |d| {
        @memcpy(recs[n + record.header_len ..][0..d.len], d);
        n += (try tx.seal(recs[n..], d.len, .application_data, 0)).len;
    }
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    try earlyServer(&s, &secret);
    var at: usize = 0;
    for ([_][]const u8{ "abc", "d" }) |want| {
        const r = try s.feed(recs[at..n]);
        try testing.expectEqualStrings(want, r.event.early_data);
        at += r.consumed;
    }
    try testing.expectEqual(@as(u32, 0), s.early_left);
    try testing.expectError(error.TooMuchEarlyData, s.feed(recs[at..n]));
    try testing.expectEqualSlices(u8, &.{ 21, 3, 3, 0, 2, 2, 10 }, s.pendingOutput());
}

test "early data: tickets advertise max_early_data_size; after a half-RTT close_notify none go out" {
    var ring: tlsresume.stek.DefaultRing = .init();
    ring.rotate(1, &(@as([32]u8, @splat(7))), 0);
    const stek: StekTicketer(tlsresume.stek.DefaultRing) = .{ .ring = &ring };
    const tickets: Tickets = .{ .ticketer = stek.ticketer(), .clock = .{ .now_ms = NoTickets.now }, .count = 1 };
    var g: CountingGuard = .{};
    const early: EarlyData = .{ .max_size = 0x01020304, .replay = g.guard() };
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .tickets = &tickets, .early_data = &early };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    s.suite = .aes_128_gcm_sha256;
    s.has_suite = true;
    s.tickets_due = 1;
    try s.out.installTx(s.suite, &(@as([32]u8, @splat(0x33))));
    var th: [32]u8 = @splat(0);
    s.issueTickets(S256, &th);
    // Open the record: NewSessionTicket ‖ extensions early_data(42, 4) then GREASE.
    var rx: record.Protection = undefined;
    try rx.init(s.suite, &(@as([32]u8, @splat(0x33))));
    defer rx.wipe();
    const sealed = try testing.allocator.dupe(u8, s.pendingOutput());
    defer testing.allocator.free(sealed);
    const o = try rx.open(sealed);
    const m = o.content;
    try testing.expectEqual(@as(u8, 4), m[0]);
    const tlen = std.mem.readInt(u16, m[14..16], .big);
    const exts = m[16 + tlen ..];
    try testing.expectEqualSlices(u8, &.{ 0, 12, 0, 42, 0, 4, 1, 2, 3, 4 }, exts[0..10]);
    try testing.expectEqual(@as(usize, 2 + 8 + 4), exts.len);

    // close_notify sent (half-RTT) before the client's Finished: the
    // Finished still completes the handshake, but no ticket follows the
    // close_notify (the send key is gone: it would go out in the clear).
    s.discardOutput(s.pendingOutput().len);
    s.startTranscript(s.suite);
    s.early_reason = .accepted;
    s.state = .client_finished;
    s.client_handshake_secret = @splat(0x22);
    try s.close();
    const closed_len = s.pendingOutput().len;
    s.tickets_due = 1;
    var finished_key: [32]u8 = undefined;
    ks.deriveFinishedKey(S256.Hkdf, 32, &finished_key, s.client_handshake_secret[0..32]);
    const th0 = s.transcript.sha256.currentHash();
    var fin = [_]u8{ 20, 0, 0, 32 } ++ @as([32]u8, undefined);
    tls13.keyschedule.computeFinishedVerifyData(S256.Hmac, fin[4..36], &finished_key, &th0);
    try testing.expect((try s.onHandshake(handshakeMessage(&fin))).? == .handshake_done);
    try testing.expect(s.isConnected());
    try testing.expectEqual(closed_len, s.pendingOutput().len);
}

// ── client certificates (RFC 8448 §6) ────────────────────────────────────

const AcceptAny = struct {
    fn verify(_: ?*const anyopaque, chain: []const []const u8, _: i64) clientauth.VerifyError!void {
        if (chain.len == 0) return error.BadCertificate;
    }
    fn clock(_: ?*anyopaque) i64 {
        return 0;
    }
};

fn handshakeMessage(raw: []const u8) inbound.HandshakeMessage {
    return .{ .msg_type = raw[0], .body = raw[4..], .raw = raw };
}

/// A server white-box at the client's second flight of RFC 8448 §6: the
/// transcript through the server's Finished.
fn rfc8448S6Server(cfg: *const Config, joiner: []u8, out: []u8, peer: []u8) Server {
    const kat = @import("message_kat_vectors.zig");
    var s: Server = .init(cfg, joiner, out);
    s.setPeerBuffer(peer);
    s.suite = .aes_128_gcm_sha256;
    s.has_suite = true;
    s.startTranscript(.aes_128_gcm_sha256);
    for ([_][]const u8{
        &kat.rfc8448_s6,                     &kat.rfc8448_s6_server_hello, &kat.rfc8448_s6_encrypted_extensions,
        &kat.rfc8448_s6_certificate_request, &kat.rfc8448_s6_certificate,  &kat.rfc8448_s6_certificate_verify,
        &kat.rfc8448_s6_server_finished,
    }) |m| s.transcript.sha256.append(m[0], m[4..]);
    s.state = .client_certificate;
    return s;
}

test "QUIC: what RFC 9001 requires of a ClientHello, levels, and the record-layer calls refused" {
    var prng = std.Random.DefaultPrng.init(1);
    const quic: Quic = .{ .transport_parameters = "TP" };
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .alpn_protocols = &.{"h3"}, .quic = &quic };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [8192]u8 = undefined;
    const good: Hello = .{ .alpn = &.{"h3"}, .quic_tp = "client" };
    const Run = struct {
        fn hello(s: *Server, cfg_: *const Config, j: []u8, o: []u8, h: Hello, level: QuicLevel) !Server.QuicResult {
            s.* = .init(cfg_, j, o);
            const rec = try buildRecord(testing.allocator, h);
            defer testing.allocator.free(rec);
            return s.quicFeed(level, rec[5..]);
        }
    };
    var s: Server = undefined;
    {
        const r = try Run.hello(&s, &cfg, &joiner, &out, good, .initial);
        try testing.expectEqualStrings("client", r.transport_parameters.?);
        // ServerHello at Initial, the rest of the flight at Handshake; the
        // keys for both directions of the Handshake level and for sending
        // at the Application level.
        const o = s.quicOutput().?;
        try testing.expectEqual(QuicLevel.initial, o.level);
        // Two levels pending, `pendingOutput` gives one at a time.
        try testing.expectEqual(o.data.len, s.pendingOutput().len);
        try testing.expectEqual(@as(u8, 2), o.data[0]); // server_hello
        s.discardOutput(o.data.len);
        const o2 = s.quicOutput().?;
        try testing.expectEqual(QuicLevel.handshake, o2.level);
        try testing.expectEqual(@as(u8, 8), o2.data[0]); // encrypted_extensions
        try testing.expect(std.mem.indexOf(u8, o2.data, &.{ 0, 57, 0, 2, 'T', 'P' }) != null);
        for ([_]struct { Server.QuicDirection, QuicLevel }{ .{ .read, .handshake }, .{ .write, .handshake }, .{ .write, .application } }) |k|
            try testing.expect(s.quicSecret(k[0], k[1]) != null);
        try testing.expect(s.quicSecret(.read, .application) == null and s.quicSecret(.read, .early) == null);
        // The record layer is not there.
        var buf: [8]u8 = undefined;
        try testing.expectError(error.WrongTransport, s.feed(&buf));
        try testing.expectError(error.WrongTransport, s.write("x"));
        try testing.expectError(error.WrongTransport, s.keyUpdate(.update_not_requested));
        try testing.expectError(error.WrongTransport, s.close());
        // Handshake data at the Initial level now: unexpected_message.
        try testing.expectError(error.UnexpectedMessage, s.quicFeed(.initial, &.{ 20, 0, 0, 0 }));
        try testing.expectEqual(alert.Description.unexpected_message, s.quicAlert().?);
        // The flight left unsent is not sent after the failure.
        try testing.expectEqual(null, s.quicOutput());
    }
    // RFC 9001 §8.2: no transport parameters; §8.4: a legacy_session_id;
    // §8.1: no ALPN protocol agreed.
    for ([_]struct { Hello, Error }{
        .{ .{ .alpn = &.{"h3"} }, error.MissingExtension },
        .{ .{ .alpn = &.{"h3"}, .quic_tp = "c", .session_id = "abcd" }, error.IllegalParameter },
        .{ .{ .alpn = &.{"h2"}, .quic_tp = "c" }, error.NoApplicationProtocol },
        .{ .{ .quic_tp = "c" }, error.NoApplicationProtocol },
    }) |c| {
        try testing.expectError(c[1], Run.hello(&s, &cfg, &joiner, &out, c[0], .initial));
        try testing.expectEqual(alertFor(c[1]).?, s.quicAlert().?);
    }
    // The ClientHello at the wrong level, or with more data behind it — in
    // the same chunk, or in the next one after a hello that fills one
    // exactly (the joiner is then empty: only the level check sees it).
    try testing.expectError(error.UnexpectedMessage, Run.hello(&s, &cfg, &joiner, &out, good, .handshake));
    try testing.expectError(error.UnexpectedMessage, Run.hello(&s, &cfg, &joiner, &out, .{ .alpn = &.{"h3"}, .quic_tp = "c", .trailing = &.{ 20, 0, 0, 0 } }, .initial));
    try testing.expectError(error.UnexpectedMessage, Run.hello(&s, &cfg, &joiner, &out, .{ .alpn = &.{"h3"}, .quic_tp = "c", .pad_to = record.max_plaintext_len, .trailing = &.{ 20, 0, 0, 0 } }, .initial));
    _ = try Run.hello(&s, &cfg, &joiner, &out, .{ .alpn = &.{"h3"}, .quic_tp = "c", .pad_to = record.max_plaintext_len }, .initial);
    // A TLS server takes no QUIC calls.
    const tls_cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    s = .init(&tls_cfg, &joiner, &out);
    try testing.expectError(error.WrongTransport, s.quicFeed(.initial, "x"));
}

test "RFC 7250: certificate types as rustls negotiates them; refusals are handshake_failure" {
    // (requires a raw key, the client's list) → the type echoed, or refused.
    try testing.expectEqual(@as(?u8, null), try Server.negotiateCertType(false, null));
    try testing.expectError(error.HandshakeFailure, Server.negotiateCertType(true, null));
    try testing.expectEqual(@as(?u8, 0), try Server.negotiateCertType(false, &.{ 2, 0 }));
    try testing.expectError(error.HandshakeFailure, Server.negotiateCertType(false, &.{2}));
    try testing.expectEqual(@as(?u8, 2), try Server.negotiateCertType(true, &.{ 0, 2 }));
    try testing.expectError(error.HandshakeFailure, Server.negotiateCertType(true, &.{0}));
    try testing.expectError(error.HandshakeFailure, Server.negotiateCertType(true, &.{ 1, 3, 255 }));

    var prng = std.Random.DefaultPrng.init(1);
    const spki = (try x509.spkiOf(&certs.p256_cert)).der;
    var raw_chain = [1][]const u8{spki};
    var ck: CertifiedKey = .{ .chain = &raw_chain, .key = testKey().key, .raw_public_key = true };
    try ck.check();
    const cfg: Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [8192]u8 = undefined;
    var s: Server = undefined;
    try accept(&s, &cfg, &joiner, &out, .{ .server_cert_types = &.{ 0, 2 } });
    try testing.expectEqual(@as(?u8, 2), s.server_cert_type);
    try testing.expectEqual(@as(?u8, null), s.client_cert_type);
    // A client that cannot take a raw key, or says nothing.
    for ([_]?[]const u8{ null, &.{0} }) |types| {
        s = .init(&cfg, &joiner, &out);
        const rec = try buildRecord(testing.allocator, .{ .server_cert_types = types });
        defer testing.allocator.free(rec);
        try testing.expectError(error.HandshakeFailure, s.feed(rec));
    }
    // An X.509 server: a client that only takes raw keys, or only sends one
    // (no client authentication asks for it), is refused as rustls does.
    const x_cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    for ([_]Hello{ .{ .server_cert_types = &.{2} }, .{ .client_cert_types = &.{2} } }) |h| {
        s = .init(&x_cfg, &joiner, &out);
        const rec = try buildRecord(testing.allocator, h);
        defer testing.allocator.free(rec);
        try testing.expectError(error.HandshakeFailure, s.feed(rec));
    }
    try accept(&s, &x_cfg, &joiner, &out, .{ .server_cert_types = &.{ 2, 0 }, .client_cert_types = &.{0} });
    try testing.expectEqual(@as(?u8, 0), s.server_cert_type);
    // `check`: one SubjectPublicKeyInfo, nothing else.
    var two = [2][]const u8{ spki, spki };
    try testing.expectError(error.ChainLength, (CertifiedKey{ .chain = &two, .key = testKey().key, .raw_public_key = true }).check());
    var cert_chain = [1][]const u8{&certs.p256_cert};
    try testing.expectError(error.InvalidRawPublicKey, (CertifiedKey{ .chain = &cert_chain, .key = testKey().key, .raw_public_key = true }).check());
}

test "RFC 7250: a client's raw public key — one entry, the allowlist's call, its key for the CertificateVerify" {
    const kat = @import("message_kat_vectors.zig");
    var prng = std.Random.DefaultPrng.init(1);
    // The RFC's client leaf, sent as its SubjectPublicKeyInfo.
    const cert_msg = &kat.rfc8448_s6_client_certificate;
    const leaf = cert_msg[11..][0..std.mem.readInt(u24, cert_msg[8..11], .big)];
    const spki = (try x509.spkiOf(leaf)).der;
    var allowed = [1][]const u8{spki};
    var allow: clientauth.RawKeyAllowlist = .{ .keys = &allowed };
    var auth: ClientAuth = .{ .verifier = .{ .verify = AcceptAny.verify }, .clock = .{ .now_ms = AcceptAny.clock }, .raw_public_keys = allow.verifier() };
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .client_auth = &auth };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [4096]u8 = undefined;
    var peer: [peerBufferLen(clientauth.default_max_leaf_len)]u8 = undefined;
    var msg_buf: [1024]u8 = undefined;
    const Msg = struct {
        /// Certificate { context "", entries each `spki` } with no extensions.
        fn build(buf: []u8, key: []const u8, n: usize) []const u8 {
            buf[0] = 11;
            buf[4] = 0;
            var at: usize = 8;
            for (0..n) |_| {
                std.mem.writeInt(u24, buf[at..][0..3], @intCast(key.len), .big);
                @memcpy(buf[at + 3 ..][0..key.len], key);
                at += 3 + key.len;
                buf[at] = 0;
                buf[at + 1] = 0;
                at += 2;
            }
            std.mem.writeInt(u24, buf[5..8], @intCast(at - 8), .big);
            std.mem.writeInt(u24, buf[1..4], @intCast(at - 4), .big);
            return buf[0..at];
        }
    };
    {
        var s = rfc8448S6Server(&cfg, &joiner, &out, &peer);
        s.client_cert_type = cert_type_raw_public_key;
        try testing.expect(try s.onHandshake(handshakeMessage(Msg.build(&msg_buf, spki, 1))) == null);
        try testing.expectEqual(State.client_certificate_verify, s.state);
        try testing.expectEqualSlices(u8, spki, s.peerLeaf());
        try testing.expect(s.peer_raw);
        // The RFC's CertificateVerify signed a transcript with the X.509
        // Certificate in it: under the raw key it is a signature that does
        // not verify (decrypt_error) — the key itself was taken.
        try testing.expectError(error.DecryptError, s.onHandshake(handshakeMessage(&kat.rfc8448_s6_client_certificate_verify)));
    }
    {
        // Two entries.
        var s = rfc8448S6Server(&cfg, &joiner, &out, &peer);
        s.client_cert_type = cert_type_raw_public_key;
        try testing.expectError(error.BadCertificate, s.onHandshake(handshakeMessage(Msg.build(&msg_buf, spki, 2))));
    }
    {
        // A key the allowlist does not hold; a certificate where the key
        // belongs.
        allowed[0] = (try x509.spkiOf(&certs.p256_cert)).der;
        var s = rfc8448S6Server(&cfg, &joiner, &out, &peer);
        s.client_cert_type = cert_type_raw_public_key;
        try testing.expectError(error.AccessDenied, s.onHandshake(handshakeMessage(Msg.build(&msg_buf, spki, 1))));
        s = rfc8448S6Server(&cfg, &joiner, &out, &peer);
        s.client_cert_type = cert_type_raw_public_key;
        try testing.expectError(error.BadCertificate, s.onHandshake(handshakeMessage(cert_msg)));
    }
}

test "RFC 8448 §6: the client's Certificate and CertificateVerify (RSA-PSS) verify" {
    const kat = @import("message_kat_vectors.zig");
    var prng = std.Random.DefaultPrng.init(1);
    var auth: ClientAuth = .{ .verifier = .{ .verify = AcceptAny.verify }, .clock = .{ .now_ms = AcceptAny.clock } };
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .client_auth = &auth };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [4096]u8 = undefined;
    var peer: [peerBufferLen(clientauth.default_max_leaf_len)]u8 = undefined;
    // The leaf: certificate_list at 4 + 1 + 3, its cert_data length first.
    const cert_msg = &kat.rfc8448_s6_client_certificate;
    const leaf = cert_msg[11..][0..std.mem.readInt(u24, cert_msg[8..11], .big)];
    {
        var s = rfc8448S6Server(&cfg, &joiner, &out, &peer);
        try testing.expect(try s.onHandshake(handshakeMessage(cert_msg)) == null);
        try testing.expectEqual(null, s.peerCertificate()); // not before its CertificateVerify
        try testing.expect(try s.onHandshake(handshakeMessage(&kat.rfc8448_s6_client_certificate_verify)) == null);
        try testing.expectEqual(State.client_finished, s.state);
        try testing.expectEqualSlices(u8, leaf, s.peerCertificate().?);
        // The client's Finished, over the transcript through its
        // CertificateVerify, under the RFC's client handshake secret.
        s.client_handshake_secret[0..32].* = kat.rfc8448_s6_client_handshake_secret;
        try testing.expect((try s.onHandshake(handshakeMessage(&kat.rfc8448_s6_client_finished))).? == .handshake_done);
        try testing.expect(s.isConnected());
    }
    // One signature octet off: decrypt_error.
    {
        var cv = kat.rfc8448_s6_client_certificate_verify;
        cv[cv.len - 1] ^= 1;
        var s = rfc8448S6Server(&cfg, &joiner, &out, &peer);
        _ = try s.onHandshake(handshakeMessage(cert_msg));
        try testing.expectError(error.DecryptError, s.onHandshake(handshakeMessage(&cv)));
    }
    // A scheme the server did not ask for, and RSA PKCS#1 v1.5 (asked for,
    // for certificates only): illegal_parameter.
    for ([_]struct { []const u16, u16 }{ .{ &.{0x0403}, 0x0804 }, .{ &.{ 0x0804, 0x0401 }, 0x0401 } }) |c| {
        auth.schemes = c[0];
        var cv = kat.rfc8448_s6_client_certificate_verify;
        std.mem.writeInt(u16, cv[4..6], c[1], .big);
        var s = rfc8448S6Server(&cfg, &joiner, &out, &peer);
        _ = try s.onHandshake(handshakeMessage(cert_msg));
        try testing.expectError(error.IllegalParameter, s.onHandshake(handshakeMessage(&cv)));
    }
    auth.schemes = &default_client_auth_schemes;
    // A leaf whose keyUsage does not allow signing (the client CA's:
    // keyCertSign, cRLSign), whatever the verifier says.
    {
        const client_certs = @import("client_certs.zig");
        const ca = &client_certs.ca_cert;
        var msg: [4 + 1 + 3 + 3 + ca.len + 2]u8 = undefined;
        msg[0] = 11;
        std.mem.writeInt(u24, msg[1..4], msg.len - 4, .big);
        msg[4] = 0;
        std.mem.writeInt(u24, msg[5..8], 3 + ca.len + 2, .big);
        std.mem.writeInt(u24, msg[8..11], ca.len, .big);
        @memcpy(msg[11..][0..ca.len], ca);
        msg[msg.len - 2] = 0;
        msg[msg.len - 1] = 0;
        var s = rfc8448S6Server(&cfg, &joiner, &out, &peer);
        try testing.expectError(error.UnsupportedCertificate, s.onHandshake(handshakeMessage(&msg)));
        try testing.expectEqual(alert.Description.unsupported_certificate, alertFor(error.UnsupportedCertificate).?);
    }
    // Out of order: a Finished where the Certificate belongs, and where
    // the CertificateVerify belongs.
    {
        var s = rfc8448S6Server(&cfg, &joiner, &out, &peer);
        try testing.expectError(error.UnexpectedMessage, s.onHandshake(handshakeMessage(&kat.rfc8448_s6_client_finished)));
    }
    {
        var s = rfc8448S6Server(&cfg, &joiner, &out, &peer);
        _ = try s.onHandshake(handshakeMessage(cert_msg));
        try testing.expectError(error.UnexpectedMessage, s.onHandshake(handshakeMessage(&kat.rfc8448_s6_client_finished)));
    }
}

test "an ML-DSA-65 client leaf: over the default cap, taken under a larger ClientAuth.max_leaf_len" {
    const gpa = testing.allocator;
    const v = @import("root.zig").testKeyVector("mldsa65-seed");
    var pair: @import("keys.zig").CertKeyPair = undefined;
    try pair.fromPem(gpa, v.cert_pem, v.key_pem);
    defer pair.deinit(gpa);
    const ck = pair.certifiedKey();
    const leaf = ck.chain[0];
    try testing.expect(leaf.len > clientauth.default_max_leaf_len);
    const msg = try gpa.alloc(u8, 4 + 1 + 3 + 3 + leaf.len + 2);
    defer gpa.free(msg);
    msg[0] = 11;
    std.mem.writeInt(u24, msg[1..4], @intCast(msg.len - 4), .big);
    msg[4] = 0;
    std.mem.writeInt(u24, msg[5..8], @intCast(3 + leaf.len + 2), .big);
    std.mem.writeInt(u24, msg[8..11], @intCast(leaf.len), .big);
    @memcpy(msg[11..][0..leaf.len], leaf);
    @memset(msg[msg.len - 2 ..], 0);

    var prng = std.Random.DefaultPrng.init(3);
    var auth: ClientAuth = .{ .verifier = .{ .verify = AcceptAny.verify }, .clock = .{ .now_ms = AcceptAny.clock }, .schemes = &.{0x0905} };
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .client_auth = &auth };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [4096]u8 = undefined;
    const peer = try gpa.alloc(u8, peerBufferLen(8192));
    defer gpa.free(peer);
    {
        var s = rfc8448S6Server(&cfg, &joiner, &out, peer);
        try testing.expectError(error.BadCertificate, s.onHandshake(handshakeMessage(msg)));
    }
    auth.max_leaf_len = 8192;
    var s = rfc8448S6Server(&cfg, &joiner, &out, peer);
    try testing.expect(try s.onHandshake(handshakeMessage(msg)) == null);
    const th = s.transcript.sha256.currentHash();
    var cv: [4 + 4 + certverify.max_signature_len]u8 = undefined;
    const sig = try certverify.sign(.mldsa65, ck.key.?, .client, &th, prng.random(), cv[8..]);
    cv[0] = 15;
    std.mem.writeInt(u24, cv[1..4], @intCast(4 + sig.len), .big);
    std.mem.writeInt(u16, cv[4..6], 0x0905, .big);
    std.mem.writeInt(u16, cv[6..8], @intCast(sig.len), .big);
    try testing.expect(try s.onHandshake(handshakeMessage(cv[0 .. 8 + sig.len])) == null);
    try testing.expectEqualSlices(u8, leaf, s.peerCertificate().?);
    try testing.expectEqual(@as(?u16, 0x0905), s.peerSignatureScheme());
}

test "client authentication without a large enough peer buffer: internal_error at the ClientHello" {
    var prng = std.Random.DefaultPrng.init(4);
    const auth: ClientAuth = .{ .verifier = .{ .verify = AcceptAny.verify }, .clock = .{ .now_ms = AcceptAny.clock } };
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .client_auth = &auth };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [16384]u8 = undefined;
    var peer: [peerBufferLen(clientauth.default_max_leaf_len)]u8 = undefined;
    const rec = try buildRecord(testing.allocator, .{});
    defer testing.allocator.free(rec);
    for ([_][]u8{ &.{}, peer[0 .. peer.len - 1], &peer }) |buf| {
        var s: Server = .init(&cfg, &joiner, &out);
        s.setPeerBuffer(buf);
        defer s.deinit();
        if (buf.len == peer.len) {
            try testing.expect((try s.feed(rec)).event == .need_more);
        } else try testing.expectError(error.InternalError, s.feed(rec));
    }
}

test "minOutputLen covers the largest first flight: ML-KEM-1024's share, an ML-DSA-87 leaf, a 255-octet ALPN name" {
    const gpa = testing.allocator;
    const v = @import("root.zig").testKeyVector("mldsa87-seed");
    var pair: @import("keys.zig").CertKeyPair = undefined;
    try pair.fromPem(gpa, v.cert_pem, v.key_pem);
    defer pair.deinit(gpa);
    const ck = pair.certifiedKey();
    var prng = std.Random.DefaultPrng.init(7);
    const proto: [255]u8 = @splat('a');
    const cfg: Config = .{ .certificate = .{ .fixed = &ck }, .groups = &.{kex.mlkem1024_group}, .alpn_protocols = &.{&proto}, .random = prng.random() };
    var kp: kex.KeyPair = undefined;
    try kex.generate(kex.mlkem1024_group, prng.random(), &kp);
    const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer gpa.free(joiner);
    const out = try gpa.alloc(u8, minOutputLen(&cfg, &ck));
    defer gpa.free(out);
    var s: Server = undefined;
    try accept(&s, &cfg, joiner, out, .{ .groups = &.{kex.mlkem1024_group}, .shares = &.{.{ kex.mlkem1024_group, kp.public[0..kp.public_len] }}, .sig_algs = &.{0x0906}, .alpn = &.{&proto} });
    defer s.deinit();
}
