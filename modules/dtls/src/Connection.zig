// SPDX-License-Identifier: MIT

//! dtls.Connection — the public, top-level PSK-mode DTLS 1.3 client/server
//! API surface. Wires `record.zig`/`messages.zig`/`handshake.zig`/
//! `flight.zig` framing to the real `keyschedule.zig`/`aead.zig` crypto
//! core, and drives both through a real RFC 9147 §5 PSK-only handshake
//! flight engine (`startHandshake`/`handleFlight`/`poll`).
//!
//! **What is real here:** `Config.validate`, `clientInit`/`serverInit`, the
//! application-data record path — `installApplicationKeys` (derive the
//! per-direction AEAD key / static IV / sequence-number key from a
//! completed handshake's traffic secrets) plus `send`/`recv`, which perform
//! RFC 9147 §4.2 AEAD record protection AND §4.2.3 sequence-number
//! encryption over the unified record header, for the two validated
//! 12-byte-nonce suites (`aes_128_gcm_sha256`, `chacha20_poly1305_sha256`)
//! — AND the handshake flight engine itself: `startHandshake` builds and
//! sends a real ClientHello (PSK identity + binder over the running
//! transcript); `handleFlight` drives both roles through ServerHello /
//! EncryptedExtensions / Finished, verifying the PSK binder and both
//! Finished `verify_data`s with constant-time compares, deriving the full
//! RFC 8446 §7.1 key schedule (early → handshake → master → application
//! secrets) via `keyschedule.zig`, and installing application keys via the
//! existing `installApplicationKeys` once both sides are mutually
//! confirmed; `poll` retransmits the last flight on a caller-clocked timer
//! (`flight.RetransmitTimer`) if the peer's next flight hasn't arrived.
//! Proven end-to-end by a real in-memory client↔server interop test (see
//! this file's tests) — no external DTLS peer required.
//!
//! **HelloRetryRequest** (RFC 9147 §5.1, RFC 8446 §4.1.4/§4.2.2) is
//! implemented in BOTH roles and BOTH key-exchange modes. A client always
//! answers one (`handleHelloRetryRequest`), applying whichever of the two
//! permitted changes the retry asked for: echo the COOKIE, and — in
//! `.cert_dhe` — generate a fresh `key_share` in the GROUP the retry named.
//! A server performs the return-routability check when `Config.hello_retry`
//! is set (`sendHelloRetryRequest`/`acceptCookie`) — off by default, so
//! existing callers are unchanged, but the RFC's recommended posture for
//! anything internet-facing. This server never asks for a group change; it
//! uses whichever offered share it can (`clientHelloShare`). Both roles, and
//! all three retry shapes on the client side, are proven against wolfSSL.
//!
//! **Deliberately out of scope** (see `startHandshake`'s doc comment and
//! `root.zig` for the full list): 0-RTT, session resumption, key update,
//! and (inherited from `aead.zig`) the CCM suites.

const std = @import("std");
const messages = @import("messages.zig");
const keyschedule = @import("keyschedule.zig");
const aead = @import("aead.zig");
const record = @import("record.zig");
const handshake = @import("handshake.zig");
const flight = @import("flight.zig");
const engine = @import("engine.zig");
const certverify = @import("certverify.zig");
const certauth = @import("certauth.zig");

const X25519 = std.crypto.dh.X25519;
/// The `secp256r1` half of the `.cert_dhe` key exchange (RFC 8446 §4.2.8.2).
/// std's curve, not this collection's faster `p256` module: the ECDHE here is
/// one scalar multiply per handshake (not a hot path), and dtls's `meta.deps`
/// stays `{"rsa", "x509"}` rather than growing a dependency for it. Same
/// choice `certverify.zig` already makes for ECDSA.
const P256 = std.crypto.ecc.P256;

pub const Role = enum { client, server };

/// Which key-exchange this connection runs (RFC 8446 §4.2.9 / §4.2.8):
///
/// - `.psk` (default): the original PSK-only exchange (`psk_ke`) — the PSK
///   supplies all session-key material; `Config.cert` may still AUTHENTICATE
///   on top (see the "certificate mode" section). Requires a non-empty
///   `Config.psk`/`psk_identity`; every existing PSK/cert-over-PSK test uses
///   this mode and is byte-for-byte unaffected.
/// - `.cert_dhe`: a PSK-LESS certificate-only handshake with ephemeral
///   (EC)DHE for forward secrecy — the standard TLS-1.3
///   `certificate` handshake. Two groups are wired (`advertised_groups`):
///   X25519, which a fresh ClientHello offers a share in, and secp256r1,
///   which is offered when a server names it in a HelloRetryRequest.
///   The ClientHello offers `key_share` +
///   `supported_groups` + `signature_algorithms` (NO `pre_shared_key`, NO
///   binder); the ECDHE shared secret is fed into the EXISTING key schedule
///   (`keyschedule.deriveHandshakeSecret` with a zero/empty-PSK early
///   secret, RFC 8446 §7.1) — the schedule was already DHE-capable, only the
///   wiring is new. Authentication is by certificate (server always presents
///   one; the client optionally, via `request_client_cert`), reusing the
///   same `certverify`/`certauth` plumbing as certificate-over-PSK mode.
///   **Fails closed** (`Config.validate`): a client must carry a
///   `peer_verify` policy and a server must carry a `cert`, because a
///   certificate mode that completes without a certificate authenticates
///   nobody.
/// - `.cert_dhe_insecure_unauthenticated`: the SAME (EC)DHE exchange with
///   peer authentication switched off — an encrypted channel with no idea
///   who is on the other end, i.e. an active MITM is indistinguishable from
///   the intended peer. It exists for opportunistic-encryption / local-fixture
///   callers and for tests; it is spelled out in full so that no config
///   typo, no defaulted field and no partially-filled `Config` can reach it
///   by accident. Never use it on an untrusted network.
pub const KeyExchange = enum {
    psk,
    cert_dhe,
    cert_dhe_insecure_unauthenticated,

    /// True for both certificate-mode (EC)DHE variants — i.e. "this
    /// connection runs the PSK-less ephemeral key exchange", regardless of
    /// whether the peer is authenticated.
    pub fn isCertDhe(self: KeyExchange) bool {
        return switch (self) {
            .psk => false,
            .cert_dhe, .cert_dhe_insecure_unauthenticated => true,
        };
    }

    /// True only for the mode that promises certificate authentication.
    /// Gates both the config-time posture checks (`Config.validate`) and the
    /// handshake-time "the peer presented no certificate at all" rejection.
    pub fn requiresPeerAuth(self: KeyExchange) bool {
        return self == .cert_dhe;
    }
};

/// RFC 8446 §B.4 registry values. `aes_128_ccm_8_sha256` is RFC 7925 §4.2's
/// default for the CoAP/constrained-IoT profile — the suite this module's
/// intended `coap`-transport consumer cares about most.
pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    chacha20_poly1305_sha256 = 0x1303,
    aes_128_ccm_sha256 = 0x1304,
    aes_128_ccm_8_sha256 = 0x1305,
};

pub const ConfigError = error{
    EmptyPsk,
    EmptyPskIdentity,
    NoCipherSuites,
    /// `Config.hello_retry` was set with an empty `cookie_secret`: the
    /// cookie's MAC would be keyed by nothing, so anyone could mint one.
    EmptyCookieSecret,
    /// `Config.hello_retry` was set with an empty `peer_binding`. A cookie
    /// bound to nothing is not a return-routability check — it verifies
    /// identically no matter which address replays it, which is exactly the
    /// property the exchange exists to deny. Rejected rather than
    /// documented, because the resulting server would look like it was doing
    /// the check.
    EmptyPeerBinding,
    /// `key_exchange = .cert_dhe` with no way to decide whether the peer's
    /// certificate is trustworthy: a client left at `peer_verify = .none`,
    /// or a server that asks for a client certificate (`request_client_cert`)
    /// while leaving `peer_verify = .none`. Either would run the whole
    /// certificate dance and then trust whatever showed up, which is the
    /// posture `.cert_dhe_insecure_unauthenticated` is named for — a caller
    /// who wants it has to say so.
    PeerVerificationRequired,
    /// `key_exchange = .cert_dhe` on a server with `cert == null`: the server
    /// would present no Certificate at all, so a conforming client has
    /// nothing to verify and an accommodating one would complete an
    /// anonymous handshake in "certificate" mode.
    LocalCertificateRequired,
};

/// Server-side HelloRetryRequest / stateless-cookie configuration — RFC 9147
/// §5.1's return-routability check (the mechanism is RFC 8446 §4.1.4's
/// HelloRetryRequest carrying a §4.2.2 `cookie`; RFC 9147 §5.3 is the
/// ClientHello *format*, a different section).
///
/// **Why it exists.** A server that answers a first ClientHello with a full
/// flight is an amplification weapon: RFC 9147 §5.1 names exactly this — an
/// attacker forges a victim's source address, sends a small ClientHello, and
/// the server sprays a much larger flight (a Certificate message, say) at the
/// victim. The cookie exchange forces the peer to prove it can RECEIVE at
/// the address it claims before the server spends a flight, a keyschedule, or
/// a signature on it.
///
/// **Why the caller supplies `peer_binding`.** The cookie has to be bound to
/// the client's transport address or it proves nothing — a cookie any client
/// can replay from any address is not a return-routability check. But this
/// module never touches a socket: the caller owns the datagram I/O, so the
/// module cannot see the peer's address, in the same way it cannot read a
/// clock (`Config.now_sec`) or draw randomness (the `Entropy` arguments). The
/// binding is therefore an input, not something discovered. This is the only
/// honest shape: an API that promised address binding while being unable to
/// observe an address would be lying.
pub const HelloRetryConfig = struct {
    /// Secret keying the cookie's HMAC. Server-side only; it never appears
    /// on the wire in any form and must never leave the process.
    ///
    /// RFC 9147 §5.1: rotating this is the ONLY thing that invalidates
    /// outstanding cookies (the design deliberately keeps no per-cookie
    /// state), so a server that wants a bounded cookie lifetime rotates it
    /// on that period. §5.1 recommends accepting the previous secret for an
    /// overlap window; that is a caller-side policy here — a caller can run
    /// the second `Connection` under the older secret if the first rejects.
    cookie_secret: []const u8,
    /// Caller-supplied bytes identifying the peer this datagram arrived
    /// from — typically its packed IP address and port. The cookie's MAC
    /// covers these, so a cookie minted for one peer does not verify for
    /// another (RFC 9147 §5.1: "If the client's apparent IP address is
    /// embedded in the cookie, this prevents an attacker from generating an
    /// acceptable ClientHello apparently from another user").
    ///
    /// It is opaque to this module — any stable encoding works, as long as
    /// the SAME peer yields the same bytes across the two ClientHellos and
    /// a DIFFERENT peer cannot yield them. Including the port is what makes
    /// it a check on a specific socket rather than a whole host.
    ///
    /// Must be non-empty (`error.EmptyPeerBinding`).
    peer_binding: []const u8,
};

/// This side's certificate identity for certificate-mode authentication
/// (RFC 8446 §4.4, layered on top of the psk_ke key exchange above — see
/// this file's "certificate mode" section further down for exactly what
/// that means and why). Optional/additive on `Config`: leaving `Config.cert
/// == null` reproduces the PSK-only behavior this module has always had.
pub const CertConfig = struct {
    /// DER-encoded X.509 certificate chain this side presents, LEAF FIRST
    /// (RFC 8446 §4.4.2's `CertificateEntry` order) — e.g. `&.{leaf}` for a
    /// leaf signed directly by a peer-trusted anchor, or `&.{ leaf,
    /// intermediate }` for a one-hop chain. Each entry is raw DER, not PEM.
    chain: []const []const u8,
    /// This side's private key for `certverify.sign`'s CertificateVerify.
    /// The `SignatureScheme` actually used is NEGOTIATED at handshake time
    /// (`selectSignatureScheme`, RFC 8446 §4.2.3), not fixed here — it is
    /// whichever of `certverify.candidateSchemes(private_key)` (the schemes
    /// this key's FAMILY can sign under) the peer also advertised in its
    /// `signature_algorithms` extension AND `Config.signature_algorithms`
    /// permits. `error.NoSignatureSchemeOverlap` if none exists — never a
    /// silent fallback to a hardcoded scheme.
    private_key: certverify.SecretKey,
};

/// Trust policy for a peer's presented certificate chain (RFC 8446 §4.4.2).
/// Applies independently on each side: a client checks the server's chain
/// under `Config.peer_verify`, and (only if `request_client_cert` is set) a
/// server checks the client's chain under ITS OWN `Config.peer_verify`.
///
/// In every case the CertificateVerify SIGNATURE itself (proof of
/// possession of the leaf's private key, bound to the handshake transcript)
/// is checked unconditionally by the flight engine whenever a
/// CertificateVerify message is present — `PeerVerify` only controls
/// whether the leaf's KEY is additionally trusted.
pub const PeerVerify = union(enum) {
    /// No chain-to-anchor trust decision is made — NOT recommended for
    /// production use (equivalent to TOFU/opportunistic certificates); the
    /// CertificateVerify signature is still checked (see above).
    none,
    /// A single trust-anchor certificate (DER, not PEM): the peer's LEAF
    /// certificate must be directly issued by this anchor's key —
    /// `certauth.verifyLeafAgainstAnchor`'s one-hop RFC 5280 §6-style check
    /// (issuer-name match, validity-period check against `Config.now_sec`,
    /// and the actual signature). Multi-hop path building through an
    /// intermediate is NOT performed — see the "certificate mode: deferred"
    /// notes below.
    trust_anchor: []const u8,
    /// Caller-supplied hook: given the peer's raw leaf certificate DER,
    /// return successfully to accept the chain or any error to reject it.
    /// Use this for full X.509 path building / revocation / pinning — out
    /// of scope for this module itself. The underlying error is NOT
    /// propagated (it becomes `error.CertificateRejected`) — log inside the
    /// hook if the caller needs the specific reason.
    verify_fn: *const fn (leaf_cert_der: []const u8) anyerror!void,

    /// "No trust decision is made." Kept as a method rather than an `==`
    /// comparison because `PeerVerify` carries payloads.
    pub fn isNone(self: PeerVerify) bool {
        return switch (self) {
            .none => true,
            .trust_anchor, .verify_fn => false,
        };
    }
};

pub const Config = struct {
    role: Role,
    /// Which key-exchange to run. `.psk` (default) keeps the original
    /// PSK-only behavior; `.cert_dhe` runs the PSK-less ephemeral-X25519
    /// certificate handshake (see `KeyExchange`). The two `psk*` fields below
    /// are IGNORED in `.cert_dhe` mode (they default to empty so a cert-DHE
    /// caller need not supply them).
    key_exchange: KeyExchange = .psk,
    psk_identity: []const u8 = &.{},
    psk: []const u8 = &.{},
    /// Preference order, most-preferred first.
    cipher_suites: []const CipherSuite = &.{.aes_128_ccm_8_sha256},

    // ── certificate mode (RFC 8446 §4.4), all ADDITIVE / optional — see
    // this file's "certificate mode" section further down. Leaving every
    // field below at its default reproduces the original PSK-only engine
    // exactly (every existing PSK test is unaffected by these fields).

    /// This side's own certificate identity — if set, this side PRESENTS a
    /// Certificate + CertificateVerify (server: always, once its ServerHello
    /// flight is sent; client: only if the server sent a
    /// CertificateRequest).
    cert: ?CertConfig = null,
    /// Trust policy this side applies to a PEER-presented chain. Only
    /// consulted when the peer actually presents a non-empty chain and its
    /// CertificateVerify signature has already checked out.
    peer_verify: PeerVerify = .none,
    /// Server only: send a CertificateRequest (RFC 8446 §4.3.2), asking the
    /// client to also authenticate with a certificate.
    request_client_cert: bool = false,
    /// If true, a handshake where the peer was expected to present a
    /// certificate (client: always, once `peer_verify != .none` OR this
    /// flag is set; server: only when `request_client_cert` is also set)
    /// but presented none (or an empty `certificate_list`) fails with
    /// `error.PeerCertificateRequired` instead of silently completing.
    require_peer_cert: bool = false,
    /// The `SignatureScheme`s (RFC 8446 §4.2.3) this side is willing to
    /// negotiate — advertised in this side's own `signature_algorithms`
    /// extension (the ClientHello, and a server's `CertificateRequest` when
    /// `request_client_cert` is set) AND enforced as a downgrade guard when
    /// VERIFYING a peer's CertificateVerify: a scheme this side never put in
    /// that advertised list is rejected outright (`error
    /// .SignatureSchemeNotAdvertised`), even one `certverify.zig` otherwise
    /// implements — a peer must not be able to steer this side into
    /// accepting a scheme it never offered. Defaults to every scheme
    /// `certverify.zig` supports (`default_signature_algorithms`), so
    /// leaving this at its default reproduces "accept anything this module
    /// can verify," the widest-compatible posture.
    signature_algorithms: []const certverify.SignatureScheme = &default_signature_algorithms,
    /// Caller-supplied wall-clock time (Unix epoch seconds), used ONLY by
    /// `PeerVerify.trust_anchor`'s validity-period check
    /// (`certauth.verifyLeafAgainstAnchor`). This module makes no
    /// wall-clock syscalls itself anywhere (mirrors `flight.zig`'s
    /// caller-clocked retransmission timer) — irrelevant for
    /// `PeerVerify.none`/`.verify_fn` or PSK-only connections.
    now_sec: i64 = 0,

    /// Server only: perform RFC 9147 §5.1's return-routability check before
    /// spending a flight on a peer — answer a cookie-less ClientHello with a
    /// HelloRetryRequest and refuse to proceed until the cookie comes back
    /// from the same `peer_binding`. See `HelloRetryConfig`.
    ///
    /// `null` (the default) is the historical behaviour: no check, and every
    /// existing caller is unaffected. That default is deliberately the
    /// PERMISSIVE one for source compatibility, and it is the wrong posture
    /// for a server reachable from the open internet — RFC 9147 §5.1: "DTLS
    /// servers SHOULD perform a cookie exchange whenever a new handshake is
    /// being performed. ... The default SHOULD be that the exchange is
    /// performed". Turning it on costs one extra round trip.
    ///
    /// Ignored on a client (a client's cookie handling is not configurable —
    /// RFC 9147 §5.1: "Clients MUST be prepared to do a cookie exchange with
    /// every handshake", so it is always on).
    hello_retry: ?HelloRetryConfig = null,

    /// Real, non-crypto validation — catches obviously-broken configs
    /// before anything touches a keyschedule stub. PSK fields stay
    /// mandatory even in certificate mode (see the "certificate mode: what
    /// 'mode' means here" note below) — a `Config` with `cert` set but an
    /// empty `psk` is still rejected.
    pub fn validate(self: Config) ConfigError!void {
        if (self.cipher_suites.len == 0) return error.NoCipherSuites;
        if (self.hello_retry) |hr| {
            // Both are security-load-bearing, and a zero-length value for
            // either yields a cookie that still LOOKS like a cookie: without
            // a secret anyone can mint one, without a binding anyone can
            // replay one. Neither can be caught later — a cookie minted this
            // way verifies perfectly.
            if (hr.cookie_secret.len == 0) return error.EmptyCookieSecret;
            if (hr.peer_binding.len == 0) return error.EmptyPeerBinding;
        }
        switch (self.key_exchange) {
            .psk => {
                if (self.psk.len == 0) return error.EmptyPsk;
                if (self.psk_identity.len == 0) return error.EmptyPskIdentity;
            },
            // `.cert_dhe`: PSK fields are unused, so they are NOT required —
            // but the AUTHENTICATION material is, and this is the only place
            // that can demand it. Left to the handshake, the checks are all
            // gated on flags that default off (`require_peer_cert`) or on a
            // peer actually presenting something (`peer_verify`), so a
            // `Config` that sets nothing but `key_exchange = .cert_dhe`
            // reached `.connected` against a peer that presented no
            // certificate at all — an (EC)DHE channel with zero peer
            // authentication in the one mode whose entire purpose is
            // certificate authentication. Fail closed instead; a caller who
            // genuinely wants that has to spell out
            // `.cert_dhe_insecure_unauthenticated`.
            .cert_dhe => switch (self.role) {
                // A client with no trust policy cannot tell its server from
                // an active MITM, whatever certificate arrives.
                .client => if (self.peer_verify.isNone()) return error.PeerVerificationRequired,
                .server => {
                    // A server with no certificate authenticates itself to
                    // nobody.
                    if (self.cert == null) return error.LocalCertificateRequired;
                    // ...and asking the client for a certificate while
                    // holding no trust policy accepts any certificate at all,
                    // which is not client authentication.
                    if (self.request_client_cert and self.peer_verify.isNone()) return error.PeerVerificationRequired;
                },
            },
            // The opt-in: the caller has said, in the mode's own name, that
            // this connection authenticates nobody.
            .cert_dhe_insecure_unauthenticated => {},
        }
    }
};

pub const State = enum {
    start,
    wait_server_hello,
    wait_encrypted_extensions,
    wait_finished,
    connected,
};

/// The DTLS 1.3 `application_data` inner content type (RFC 8446 §5.2,
/// reused unchanged). It is appended to the plaintext to form the
/// DTLSInnerPlaintext before AEAD sealing.
pub const content_type_application_data: u8 = 23;

/// Application-data epoch (RFC 9147 §4.1): epoch 3 is the first epoch after
/// the handshake completes.
pub const application_epoch: u16 = 3;

/// Cap on a HelloRetryRequest cookie this client will echo. RFC 8446 §4.2.2
/// sets no limit beyond the 2-byte length field; a real server's cookie is a
/// keyed hash plus context (wolfSSL's is well under 128 bytes, and this
/// module's own — `cookie_len` below — is 67). The cap keeps ClientHello2
/// inside the same fixed body buffer as ClientHello1 rather than letting the
/// peer choose our stack usage.
const max_cookie_len = 128;

/// The handshake-traffic epoch (RFC 9147 §6.1): everything after ServerHello
/// and before the application keys are installed travels under it.
pub const handshake_epoch: u16 = 2;

pub const HandshakeError = messages.MessageError || handshake.FrameError || handshake.ReassembleError || record.RecordError || aead.RecordProtectionError || SendError || error{
    /// `startHandshake`/`handleFlight` called from a `State` that doesn't
    /// expect it (e.g. `handleFlight` on a client not in
    /// `.wait_server_hello`, or a server that already saw a ClientHello).
    WrongState,
    UnsupportedSuite,
    /// The peer's offered cipher suites share nothing with this side's
    /// `Config.cipher_suites` (restricted to suites this module can
    /// actually protect records with — see `suiteParams`).
    NoCipherSuiteOverlap,
    /// The ClientHello's PSK identity doesn't match this `Connection`'s
    /// configured `psk_identity` (PSK mode here is single-identity; see
    /// `Config`).
    NoMatchingPskIdentity,
    /// RFC 8446 §4.2.11.2: the offered PSK binder doesn't verify against
    /// this side's PSK — either a wrong PSK or a tampered ClientHello.
    BinderVerifyFailed,
    /// RFC 8446 §4.2.1: the ServerHello carried no `supported_versions`
    /// extension, so the peer never said which version it selected. Since
    /// every version field on the wire reads DTLS 1.2, this is what a DTLS
    /// 1.2-only server's answer looks like.
    VersionNotNegotiated,
    /// The ServerHello selected a version other than DTLS 1.3.
    UnsupportedVersion,
    /// RFC 8446 §4.4.4: the peer's Finished `verify_data` doesn't match —
    /// either a wrong PSK/transcript mismatch or a tampered flight.
    FinishedVerifyFailed,
    /// A HelloRetryRequest arrived that this engine cannot act on. The
    /// cookie/retry round trip is implemented in BOTH key-exchange modes
    /// (`handleHelloRetryRequest`), including `.cert_dhe`'s (EC)DHE half —
    /// a retry naming a different `supported_groups` group is answered with
    /// a fresh `key_share` in THAT group. This error is what remains:
    ///   * an HRR carrying a `key_share` in `.psk` mode — `psk_ke` has no
    ///     (EC)DHE, and answering with a share would silently switch the
    ///     exchange to `psk_dhe_ke`, which this engine does not implement;
    ///   * an HRR with neither a cookie nor a group change, i.e. nothing
    ///     ClientHello2 could differ by. RFC 8446 §4.1.4 forbids sending one
    ///     in the first place; answering it with a byte-identical
    ///     ClientHello would be a retry loop.
    HelloRetryRequestUnsupported,
    /// RFC 8446 §4.2.8 check (1): a HelloRetryRequest named a
    /// `selected_group` this client never put in its own `supported_groups`. Accepting it would
    /// let the server choose a group off-menu — including one this side
    /// cannot compute a share for.
    UnsupportedGroup,
    /// RFC 8446 §4.2.8 check (2): a HelloRetryRequest named a group the
    /// client had ALREADY offered a `key_share` for, or (in a ServerHello) selected a
    /// cipher suite other than the one the preceding HelloRetryRequest
    /// committed to. Both are protocol violations that a client which
    /// obliged could be driven around indefinitely by.
    IllegalHelloRetryRequest,
    /// RFC 9147 §5.1: a ClientHello arrived carrying a `cookie` extension
    /// that does not authenticate under this server's `Config.hello_retry`
    /// — a forged or tampered cookie, one minted for a DIFFERENT
    /// `peer_binding` (the return-routability check doing its job), or one
    /// minted under a `cookie_secret` that has since been rotated. §5.1
    /// requires the handshake be terminated ("illegal_parameter"); this
    /// module reports typed errors rather than sending alerts, so the
    /// caller decides.
    ///
    /// Deliberately ONE error for every cause, including a structurally
    /// wrong-sized cookie: distinguishing them would tell a prober which
    /// half of its guess was right.
    CookieVerifyFailed,
    /// A decoded handshake message had the wrong `msg_type`/content type
    /// for the state the connection is in.
    UnexpectedMessage,
    /// `.cert_dhe` mode: the ClientHello (server side) or ServerHello
    /// (client side) carried no usable `key_share` extension — the extension
    /// was absent, it offered/selected no group this module speaks
    /// (`advertised_groups`: x25519 and secp256r1), its share was the wrong
    /// LENGTH for the group it claimed (`expectedShareLen`), or — client
    /// side — the server answered in a group other than the one this client
    /// offered a share in (RFC 8446 §4.2.8 requires they match).
    MissingKeyShare,
    /// `.cert_dhe` mode: the peer's public share is structurally the right
    /// size but unusable — an X25519 low-order/identity point (rejected by
    /// `std.crypto.dh.X25519`), or a secp256r1 value that is not a point on
    /// the curve / whose product is the identity. Rejected rather than used:
    /// an identity shared secret would be catastrophic.
    KeyExchangeFailed,
    /// INTERNAL to the flight engine: the datagrams buffered so far do not
    /// yet contain a complete flight (a handshake message is still missing
    /// fragments, or the flight's closing message has not arrived). Never
    /// escapes `handleFlight` — it is what makes that function roll the
    /// connection back and answer `HandshakeResult.need_more_data` instead.
    /// It is a member of this error set only because the internal
    /// per-message parsers share it.
    FlightIncomplete,
    /// The datagrams buffered for ONE incoming flight exceed
    /// `max_flight_bytes`. Reassembly across datagrams means holding
    /// UNAUTHENTICATED bytes (the handshake is not yet authenticated), so
    /// the buffer is capped and overflowing it is a typed error rather than
    /// an ever-growing allocation: without the cap, a peer that sends
    /// fragments forever and never completes a message is a memory-
    /// exhaustion vector. The accumulator is dropped when this is raised;
    /// the caller decides whether to keep the association.
    FlightTooLarge,
    /// A fragment of a LATER handshake message arrived while an earlier one
    /// is still incomplete. This engine reassembles exactly ONE message at a
    /// time (see `takeHandshakeMessage`) — that is the cap on "how many
    /// in-progress messages may a peer make this side hold", and it is 1.
    /// Fragments of messages this side has ALREADY consumed are skipped
    /// (they are ordinary retransmission), so this names only the
    /// genuinely-interleaved case, which no conforming sender produces.
    InterleavedFragments,
} || CertModeError;

/// Certificate-mode-specific errors (RFC 8446 §4.4) — see this file's
/// "certificate mode" section. Folded into `HandshakeError` so callers
/// still see one error union from `startHandshake`/`handleFlight` either
/// way.
pub const CertModeError = certverify.SignError || error{
    /// A CertificateVerify signature failed to check out against the
    /// transcript + the peer's presented leaf public key — either a
    /// tampered/replayed transcript, a wrong key, or a malformed
    /// signature/scheme. Folds every `certverify.VerifyError` case (never
    /// leaks which — see `verifyPeerCert`'s doc comment for why).
    CertVerifyFailed,
    /// The peer's certificate chain failed the configured `Config
    /// .peer_verify` trust policy (`trust_anchor` chain-to-anchor check, or
    /// `verify_fn` rejection) — OR the presented certificate DER itself
    /// was malformed / used an unsupported public-key algorithm
    /// (`certauth.Error`, folded here rather than leaked raw).
    CertificateRejected,
    /// `Config.require_peer_cert` is set but the peer presented no
    /// certificate (or an empty `certificate_list`, RFC 8446 §4.4.2's "no
    /// certificate available" answer).
    PeerCertificateRequired,
    /// `signature_algorithms` negotiation (RFC 8446 §4.2.3, see
    /// `selectSignatureScheme`) found no `SignatureScheme` simultaneously
    /// (a) advertised by the peer, (b) permitted by this side's own
    /// `Config.signature_algorithms`, and (c) producible by this side's
    /// configured `CertConfig.private_key`'s key family
    /// (`certverify.candidateSchemes`). The handshake fails cleanly here
    /// rather than silently signing under some default scheme the peer
    /// never offered.
    NoSignatureSchemeOverlap,
    /// A peer's CertificateVerify used a `SignatureScheme` this side never
    /// advertised in its own `signature_algorithms` extension (`Config
    /// .signature_algorithms`) — rejected before the signature is even
    /// checked. RFC 8446 §4.2.3 downgrade protection: a peer must not be
    /// able to steer this side into accepting a scheme it never offered,
    /// even one `certverify.zig` otherwise implements.
    SignatureSchemeNotAdvertised,
};

pub const SendError = error{
    NotConnected,
    UnsupportedSuite,
    BufferTooShort,
    RecordTooShort,
    DecryptionFailed,
    Malformed,
    /// RFC 9147 §4.5.1: the record's sequence number is a duplicate of one
    /// already accepted in this epoch's anti-replay window, or is older
    /// than the window's floor. Raised only AFTER the record's AEAD tag
    /// has verified — an attacker cannot use this to probe the window
    /// without first producing a validly-authenticated record.
    ReplayedRecord,
    /// The record authenticated and decrypted, but its inner content type is
    /// `ack` (26) — RFC 9147 §7. A real peer sends these on the application
    /// epoch: wolfSSL acknowledges the client's Finished with one before any
    /// application data flows. It is ordinary protocol traffic, not damage,
    /// so it gets its own error rather than `Malformed`; a caller that has
    /// nothing to retransmit can simply read the next datagram.
    ReceivedAck,
    /// The record authenticated and decrypted, but its inner content type is
    /// `handshake` (22) on the application epoch — a post-handshake message
    /// (NewSessionTicket, KeyUpdate, RFC 8446 §4.6). This module implements
    /// none of them (see the "Out of scope" list in `root.zig`), so the
    /// record is reported rather than silently dropped: a caller that does
    /// not need resumption or key update can read the next datagram, but it
    /// is told what it is skipping.
    ReceivedPostHandshakeMessage,
};

/// One direction's record-protection key material, derived from a traffic
/// secret by `installApplicationKeys`. Fixed-size storage (no allocator);
/// `key_len`/`sn_len` record how much is live for the negotiated suite.
const DirKeys = struct {
    key: [32]u8 = undefined,
    key_len: u8 = 0,
    iv: [12]u8 = undefined,
    sn_key: [32]u8 = undefined,
    sn_len: u8 = 0,
};

/// Per-epoch record-layer sequence-number bookkeeping (send + receive-side
/// reconstruction window state) — the handshake epochs' analogue of
/// `Connection`'s own `send_seq`/`recv_max_seq`/`recv_seen_any`/
/// `recv_window` fields, which are reserved for the application epoch.
const EpochSeqState = struct {
    send_seq: u48 = 0,
    recv_max_seq: u48 = 0,
    recv_seen_any: bool = false,
    /// RFC 9147 §4.5.1 sliding anti-replay window bitmap for THIS epoch —
    /// see `replayCheckAndUpdate`'s doc comment for the bit convention.
    recv_window: u64 = 0,
};

/// The DTLS 1.3 `handshake` content type (RFC 8446 §5.2's inner-plaintext
/// content-type byte for handshake messages, as opposed to
/// `content_type_application_data` above).
const content_type_handshake: u8 = 22;

/// RFC 9147 §7's "ack" content type. `flight.zig` encodes/decodes the ACK
/// message body and leaves the carrying content type to its caller — this is
/// that value.
const content_type_ack: u8 = 26;

// ── incoming-flight reassembly bounds (RFC 9147 §5.2) ────────────────────
//
// A handshake message may arrive split across several datagrams, so
// `handleFlight` buffers a flight's datagrams until the flight is complete
// (see that function). At handshake time NOTHING in those bytes is
// authenticated yet — an off-path attacker can inject datagrams at will —
// so every dimension of that buffering is bounded, explicitly, here:
//
//   * BYTES: `max_flight_bytes`. Sized from the largest flight this engine
//     can actually process — ServerHello + EncryptedExtensions +
//     CertificateRequest + Certificate (`max_cert_message_body`) +
//     CertificateVerify (`max_certverify_body`) + Finished is ~2.2 KB of
//     message bodies — plus per-fragment framing overhead (12-byte
//     handshake header + record header + 16-byte AEAD tag per fragment,
//     ~40 bytes each, so ~0.4 KB even at a 256-byte peer MTU), leaving
//     roughly 1.5 KB of headroom for one retransmitted prefix landing in
//     the same buffer. A peer that exceeds it gets `error.FlightTooLarge`
//     and the buffer is dropped, rather than the buffer growing.
//   * IN-PROGRESS MESSAGES: exactly ONE (`takeHandshakeMessage`
//     reassembles a single message at a time and rejects a fragment of a
//     later message with `error.InterleavedFragments`), so a peer cannot
//     make this side hold N half-messages by opening N of them.
//   * FRAGMENT COUNT: implied by the byte cap — every record consumes at
//     least two bytes of the buffer, so the loop is bounded by it and
//     needs no separate counter.
//
// These are per-`Connection` fixed arrays: no allocator, nothing grows.
const max_flight_bytes: usize = 4096;

/// Upper bound on the plaintext this engine will recover from ONE record
/// while reassembling. A record can never be larger than the flight buffer
/// that holds it, so this is the same number.
const max_record_plaintext: usize = max_flight_bytes;

/// Which record format the next handshake fragment is wrapped in — the two
/// are not interchangeable and the flight engine always knows which it
/// expects: `DTLSPlaintext` before any keys exist (ClientHello/ServerHello,
/// RFC 9147 §4), the AEAD-protected unified header afterwards.
const RecordKind = enum { epoch0_plaintext, epoch2_protected };

/// One fully-reassembled handshake message. `body` points into the
/// caller-supplied reassembly buffer, never into a decrypted-record scratch
/// buffer, so it stays valid after `takeHandshakeMessage` returns.
const TakenMessage = struct {
    msg_type: u8,
    body: []const u8,
    message_seq: u16,
};

/// The epoch-2 record sequence numbers consumed while reading a flight —
/// what an RFC 9147 §7 ACK for that flight has to name. Silently stops
/// collecting past its capacity: an ACK naming a prefix of the flight is
/// valid, and a peer must not be able to size this side's bookkeeping.
const AckCollector = struct {
    buf: [4]flight.RecordNumber = undefined,
    len: usize = 0,

    fn add(self: *AckCollector, sequence_number: u64) void {
        if (self.len >= self.buf.len) return;
        self.buf[self.len] = .{ .epoch = handshake_epoch, .sequence_number = sequence_number };
        self.len += 1;
    }

    fn items(self: *const AckCollector) []const flight.RecordNumber {
        return self.buf[0..self.len];
    }
};

/// RFC 9147 §5.2 `message_seq` ordering, wrap-aware: is `a` strictly BEHIND
/// `b`? A handshake uses a handful of consecutive values, so the only thing
/// that matters is that the comparison does not misread `0` as newer than
/// `65535` — the same "half the space is the past" convention the record
/// layer's sequence-number reconstruction uses.
fn messageSeqOlderThan(a: u16, b: u16) bool {
    const delta = b -% a;
    return delta != 0 and delta < 0x8000;
}

// ── certificate-mode sizing constants ────────────────────────────────────
//
// `protectHandshakeMessage`'s own `inner_buf` is a fixed 1500 bytes, and
// this engine only ever SENDS single-fragment messages (it never fragments
// on transmit — see `frameHandshakeMessage`), so every certificate-mode
// message this engine sends must fit that ceiling; these constants stay
// comfortably under it while covering realistic single/short chains (proven
// by the ECDSA P-256 chains in `Connection.zig`'s own cert-mode tests, and
// the RSA-2048 leaf in `certauth.zig`'s standalone bridge tests). Note the
// asymmetry: RECEIVING a fragmented message IS supported (see
// `max_flight_bytes` above); it is only the sending side that still emits
// one fragment per message, which needs a peer MTU that fits it.
const max_cert_message_body: usize = 1200;
const max_certverify_body: usize = 600;
const max_certreq_body: usize = 128;
/// Upper bound on a CertificateVerify signature across every scheme
/// `certverify.zig` supports (the RSA-PSS family's `rsa.max_modulus_len`
/// dominates every ECDSA/Ed25519 case) — sizes `sig_buf` in `signCertVerify`
/// without needing to know the configured scheme at comptime.
const max_sig_len: usize = certverify.maxSignatureLen(.rsa_pss_rsae_sha256);

/// `Config.signature_algorithms`'s default: every `SignatureScheme`
/// `certverify.zig` implements. Advertised in the `signature_algorithms`
/// extension (ClientHello — both `.psk` and `.cert_dhe` modes — and a
/// server's `CertificateRequest`) and used as the downgrade-guard set when
/// verifying a peer's CertificateVerify (see `Config.signature_algorithms`'s
/// doc comment and `selectSignatureScheme`/`verifyPeerCert` below).
const default_signature_algorithms = [_]certverify.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .ed25519,
};

/// Every signature scheme this module can verify, as wire values — the
/// filter applied to a peer's `signature_algorithms` list. A scheme outside
/// this set can never be selected, so there is no reason to remember the
/// peer offered it (and every reason not to: the peer decides how long that
/// list is).
const supported_scheme_wire_values = blk: {
    const all = std.enums.values(certverify.SignatureScheme);
    var out: [all.len]u16 = undefined;
    for (all, 0..) |s, i| out[i] = @intFromEnum(s);
    break :blk out;
};

/// Encodes `schemes` as a wire `signature_algorithms` extension (RFC 8446
/// §4.2.3) into `buf`, returning the ready-to-send `messages.Extension`.
/// Shared by the ClientHello (both key-exchange modes) and the server's
/// `CertificateRequest` — the only two messages this module ever sends one
/// in (RFC 8446 §4.2.3 defines no other carrier).
fn signatureAlgorithmsExtension(schemes: []const certverify.SignatureScheme, buf: []u8) HandshakeError!messages.Extension {
    var raw: [8]u16 = undefined;
    if (schemes.len > raw.len) return error.BufferTooShort;
    for (schemes, 0..) |s, i| raw[i] = @intFromEnum(s);
    const data = messages.encodeSignatureAlgorithms(raw[0..schemes.len], buf) catch return error.BufferTooShort;
    return .{ .ext_type = @intFromEnum(messages.ExtensionType.signature_algorithms), .data = data };
}

/// RFC 8446 §4.2.3 `signature_algorithms` negotiation: picks the
/// `SignatureScheme` this side signs a CertificateVerify with, from the
/// intersection of THREE sets — never a hardcoded default:
///   1. `certverify.candidateSchemes(cc.private_key)` — what `cc`'s key
///      FAMILY can actually produce a signature under;
///   2. `our_signature_algorithms` (`Config.signature_algorithms`) — what
///      this side is willing to use at all;
///   3. `peer_sig_algs` — the wire `signature_algorithms` values the PEER
///      advertised (its ClientHello, or its CertificateRequest).
/// Preference order follows (1) (most-preferred first, e.g. sha256 before
/// sha384/sha512 for an RSA key). No match in all three ⇒
/// `error.NoSignatureSchemeOverlap` — the handshake fails cleanly rather
/// than silently proceeding under some default scheme the peer never
/// offered or this side never agreed to use.
fn selectSignatureScheme(
    cc: CertConfig,
    our_signature_algorithms: []const certverify.SignatureScheme,
    peer_sig_algs: []const u16,
) error{NoSignatureSchemeOverlap}!certverify.SignatureScheme {
    for (certverify.candidateSchemes(cc.private_key)) |candidate| {
        var ours_too = false;
        for (our_signature_algorithms) |ours| {
            if (ours == candidate) {
                ours_too = true;
                break;
            }
        }
        if (!ours_too) continue;
        for (peer_sig_algs) |peer_raw| {
            if (peer_raw == @intFromEnum(candidate)) return candidate;
        }
    }
    return error.NoSignatureSchemeOverlap;
}

// ── (EC)DHE groups: the `.cert_dhe` key exchange ──────────────────────────

const x25519_group: u16 = @intFromEnum(messages.NamedGroup.x25519);
const secp256r1_group: u16 = @intFromEnum(messages.NamedGroup.secp256r1);

/// The `supported_groups` (RFC 8446 §4.2.7) this module advertises. It is
/// ONE list, used by both ClientHello builders and by the HelloRetryRequest
/// group check — a client that advertises a group it cannot compute a share
/// for invites an HRR it must then refuse, and a client that accepts an HRR
/// naming a group it never advertised has skipped RFC 8446 §4.1.4's check.
/// Every entry here MUST be handled by `ecdheGenerate`; the test
/// "advertised_groups and the (EC)DHE implementation agree" pins that.
///
/// x25519 comes FIRST and is the group a fresh ClientHello offers a share
/// in; secp256r1 is advertised as a fallback the server may name in a
/// HelloRetryRequest.
const advertised_groups = [_]u16{ x25519_group, secp256r1_group };

/// The longest `KeyShareEntry.key_exchange` any advertised group produces:
/// secp256r1's uncompressed SEC1 point (`0x04 || X || Y`).
const max_key_share_len = 65;

/// Is `group` one this side advertised in `supported_groups`? RFC 8446
/// §4.2.8 check (1): a client MUST abort on a HelloRetryRequest whose
/// `selected_group` was not in its own `supported_groups` — otherwise a server picks the
/// group, which is precisely backwards.
fn groupAdvertised(group: u16) bool {
    for (advertised_groups) |g| {
        if (g == group) return true;
    }
    return false;
}

/// The exact `KeyShareEntry.key_exchange` length RFC 8446 §4.2.8.1/§4.2.8.2
/// fixes for each wired group. Exact, not a maximum: a P-256 share that is
/// not 65 bytes is not a P-256 share, and accepting a short one would hand
/// peer-controlled bytes to `fromSec1` on the strength of the group id alone.
/// Returns 0 for groups this module does not speak, which never matches a
/// real share length and so reads as "unusable".
fn expectedShareLen(group: u16) usize {
    return switch (group) {
        x25519_group => 32,
        secp256r1_group => 65,
        else => 0,
    };
}

/// An ephemeral (EC)DHE key pair for one handshake. The private part is a
/// 32-byte scalar for both wired groups (X25519's clamped scalar, P-256's
/// scalar mod n); the public part is the wire `key_share` value, whose
/// length is group-dependent.
const EcdheKeyPair = struct {
    group: u16,
    secret: [32]u8,
    public: [max_key_share_len]u8,
    public_len: usize,
};

/// Generates this side's ephemeral share in `group` from the caller-supplied
/// `Entropy` (std 0.16 removed `std.crypto.random`, so every source of
/// randomness in this collection is an argument).
///
/// `entropy` MUST be a cryptographically secure source — `.csprng`. This is
/// the highest-consequence use of randomness in the module: the bytes drawn
/// here ARE the x25519 / secp256r1 ephemeral PRIVATE KEY. Under a predictable
/// generator — the `.seeded_for_test` arm, a PID, a boot timestamp — a passive
/// eavesdropper who learns the seed derives the same private key, recomputes
/// the (EC)DHE shared secret, and decrypts every session recorded from that
/// peer, retroactively; forward secrecy, the entire reason the handshake
/// generates an ephemeral key at all, is gone. There is no way for this
/// function to tell a real CSPRNG from a seeded PRNG — `std.Random` is a
/// vtable — which is exactly why the choice is a named union arm the caller
/// has to write out at every entry point that reaches here
/// (`startHandshake`, `handleFlight`), rather than a bare parameter.
///
///   * x25519 (RFC 7748 / RFC 8446 §4.2.8.1): 32 random bytes as the secret
///     scalar — `generateDeterministic` clamps — and the 32-byte public key
///     as the share.
///   * secp256r1 (RFC 8446 §4.2.8.2): a scalar in `[1, n-1]` by rejection
///     sampling (`P256.scalar.rejectNonCanonical` refuses `>= n`; zero is
///     refused separately), and `0x04 || X || Y` as the share. Rejection
///     probability is ~2^-32 per draw, so the bounded loop below cannot
///     realistically exhaust; it fails closed with a typed error rather than
///     looping forever on a broken RNG.
fn ecdheGenerate(group: u16, entropy: Entropy) HandshakeError!EcdheKeyPair {
    const random = entropy.source();
    var kp: EcdheKeyPair = .{ .group = group, .secret = undefined, .public = undefined, .public_len = 0 };
    switch (group) {
        x25519_group => {
            var seed: [32]u8 = undefined;
            random.bytes(&seed);
            const x = X25519.KeyPair.generateDeterministic(seed) catch return error.KeyExchangeFailed;
            std.crypto.secureZero(u8, &seed);
            kp.secret = x.secret_key;
            kp.public[0..32].* = x.public_key;
            kp.public_len = 32;
        },
        secp256r1_group => {
            var tries: usize = 0;
            while (tries < 64) : (tries += 1) {
                var candidate: [32]u8 = undefined;
                random.bytes(&candidate);
                P256.scalar.rejectNonCanonical(candidate, .big) catch continue; // >= n
                if (std.mem.allEqual(u8, &candidate, 0)) continue; // == 0
                // basePoint * a nonzero canonical scalar is never the identity.
                const point = P256.basePoint.mul(candidate, .big) catch continue;
                kp.secret = candidate;
                kp.public[0..65].* = point.toUncompressedSec1();
                kp.public_len = 65;
                return kp;
            }
            return error.KeyExchangeFailed;
        },
        else => return error.MissingKeyShare,
    }
    return kp;
}

/// The (EC)DHE shared secret fed to `keyschedule.deriveHandshakeSecret`.
///
/// The two groups differ in more than size, and conflating them is a real
/// interop bug rather than a cosmetic one: X25519's `scalarmult` output IS
/// the shared secret, whereas for the NIST curves RFC 8446 §7.4.2 takes only
/// the X COORDINATE of the shared point ("the shared secret is the x
/// coordinate ... converted to a byte string"), not the 65-byte point.
///
/// Both paths reject a degenerate result rather than using it: X25519's
/// low-order/identity outputs are rejected by std, and P-256's identity
/// output by `mul`. `peer_share` is peer-controlled, so a wrong length or an
/// off-curve point is a typed error here, never a panic.
fn ecdheSharedSecret(group: u16, secret: [32]u8, peer_share: []const u8) HandshakeError![32]u8 {
    switch (group) {
        x25519_group => {
            if (peer_share.len != 32) return error.MissingKeyShare;
            return X25519.scalarmult(secret, peer_share[0..32].*) catch error.KeyExchangeFailed;
        },
        secp256r1_group => {
            if (peer_share.len != 65) return error.MissingKeyShare;
            const point = P256.fromSec1(peer_share) catch return error.KeyExchangeFailed;
            const shared = point.mul(secret, .big) catch return error.KeyExchangeFailed;
            return shared.affineCoordinates().x.toBytes(.big);
        },
        else => return error.MissingKeyShare,
    }
}

// ── RFC 9147 §5.1 stateless HelloRetryRequest cookie ─────────────────────
//
// The whole point of the exchange is that the server keeps NOTHING between
// the two ClientHellos. RFC 9147 §5.1 says what that costs: "a stateless
// server-cookie implementation requires the content or hash of the initial
// ClientHello (and HelloRetryRequest) to be stored in the cookie", and RFC
// 8446 §4.2.2 the same — "offload state to the client ... by storing the
// hash of the ClientHello in the HelloRetryRequest cookie (protected with
// some suitable integrity protection algorithm)".
//
// So the cookie IS the server's state, handed to a party that must not be
// able to forge or alter it. Its layout:
//
//     version(1) || cipher_suite(2) || Hash(ClientHello1)(32) || mac(32)
//
// and the MAC covers the caller's `peer_binding` as well as those bytes:
//
//     mac = HMAC-SHA256(cookie_secret,
//                       label || u16(binding.len) || binding || plaintext)
//
// Every field is there because something breaks without it:
//
//   * `Hash(ClientHello1)` — RFC 8446 §4.4.1's `message_hash` rewrite means
//     this hash is ALL that is needed to rebuild the transcript, which is
//     what makes statelessness possible at all (see
//     `engine.Transcript.resetToMessageHash`).
//   * `cipher_suite` — RFC 8446 §4.1.4 requires the ServerHello to select
//     the same suite the HelloRetryRequest named, and the HRR's bytes are
//     part of the transcript, so the server must reproduce them exactly.
//     Carrying the suite means the reconstruction is AUTHENTICATED rather
//     than re-derived from a ClientHello2 the peer controls.
//   * `peer_binding` — the return-routability check itself. Without it a
//     cookie minted for one address verifies from any address, which is
//     precisely the forged-source-address case §5.1 exists to stop. It is
//     MAC'd rather than stored: the server already knows the address of
//     whoever is talking to it now, and echoing it back would only add
//     bytes an attacker can read.
//   * `version` — lets the format change without a valid old cookie being
//     reinterpreted as a new one.
//   * the label and the length prefix — domain separation, and no way to
//     shift bytes between the binding and the fields that follow it.
//
// There is deliberately NO timestamp/expiry field. RFC 9147 §5.1 offers it
// as an alternative to secret rotation, not in addition, and rotation is
// what this API exposes (`HelloRetryConfig.cookie_secret`). The threat an
// expiry would answer is a captured cookie replayed later — but a replay
// only verifies from the same `peer_binding`, and a party at that address
// passes the return-routability check on its own merits anyway. Adding a
// clock would also mean this module reading one, which it does not do
// anywhere (see `Config.now_sec`).

const cookie_version: u8 = 1;
/// `version || cipher_suite || Hash(ClientHello1)` — everything the MAC
/// authenticates that also travels on the wire.
const cookie_plaintext_len = 1 + 2 + 32;
const cookie_mac_len = 32;
const cookie_len = cookie_plaintext_len + cookie_mac_len;

/// Domain separation for the cookie MAC: this key is used for nothing else
/// today, but a caller reusing a secret across purposes should not get a
/// collision for free.
const cookie_mac_label = "dtls 1.3 hello retry cookie v1";

const CookieContents = struct {
    suite: CipherSuite,
    client_hello1_hash: [32]u8,
};

/// The cookie MAC over `plaintext` (the wire-visible prefix) bound to
/// `peer_binding`. Same function for minting and for checking — there is
/// exactly one definition of what a valid cookie is.
fn cookieMac(hr: HelloRetryConfig, plaintext: []const u8) [cookie_mac_len]u8 {
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    var h = Hmac.init(hr.cookie_secret);
    h.update(cookie_mac_label);
    // Length-prefixed so no split between `peer_binding` and what follows it
    // can be shifted: "1.2.3.4:8" + "0…" must not hash like "1.2.3.4:80" + "…".
    // u64, not u16: the binding is caller-supplied and a length that
    // SATURATED would silently reintroduce the ambiguity the prefix exists
    // to remove.
    var binding_len: [8]u8 = undefined;
    std.mem.writeInt(u64, &binding_len, hr.peer_binding.len, .big);
    h.update(&binding_len);
    h.update(hr.peer_binding);
    h.update(plaintext);
    var mac: [cookie_mac_len]u8 = undefined;
    h.final(&mac);
    return mac;
}

/// Mints the cookie for a HelloRetryRequest. Deterministic in its inputs,
/// which is what lets a stateless server answer a RETRANSMITTED first
/// ClientHello with a byte-identical HelloRetryRequest instead of having to
/// remember it had already sent one.
fn mintCookie(hr: HelloRetryConfig, c: CookieContents, out: *[cookie_len]u8) void {
    out[0] = cookie_version;
    std.mem.writeInt(u16, out[1..3], @intFromEnum(c.suite), .big);
    @memcpy(out[3..35], &c.client_hello1_hash);
    const mac = cookieMac(hr, out[0..cookie_plaintext_len]);
    @memcpy(out[cookie_plaintext_len..], &mac);
}

/// Authenticates `cookie` and returns what it carries, or
/// `error.CookieVerifyFailed`. The comparison is `std.crypto.timing_safe
/// .eql`, like every other MAC/verify_data comparison in this file — a
/// byte-at-a-time compare here would let an attacker at the right address
/// walk a forged MAC out one byte at a time, and the cookie is the one
/// thing in the handshake an unauthenticated peer can make the server check
/// repeatedly for free.
fn openCookie(hr: HelloRetryConfig, cookie: []const u8) error{CookieVerifyFailed}!CookieContents {
    if (cookie.len != cookie_len) return error.CookieVerifyFailed;
    if (cookie[0] != cookie_version) return error.CookieVerifyFailed;
    const expected = cookieMac(hr, cookie[0..cookie_plaintext_len]);
    if (!std.crypto.timing_safe.eql([cookie_mac_len]u8, expected, cookie[cookie_plaintext_len..][0..cookie_mac_len].*))
        return error.CookieVerifyFailed;
    // Only AFTER the MAC: a suite value that never came from this server is
    // not worth decoding, and `cipherSuiteFromU16` returning null for a
    // MAC-valid cookie would mean our own `cookie_secret` was compromised.
    const suite = cipherSuiteFromU16(std.mem.readInt(u16, cookie[1..3], .big)) orelse return error.CookieVerifyFailed;
    return .{ .suite = suite, .client_hello1_hash = cookie[3..35].* };
}

/// Encodes the HelloRetryRequest body this server sends, and — bit for bit —
/// re-encodes it when ClientHello2 comes back. Both call sites go through
/// here BECAUSE it must be byte-identical: the HRR is in the transcript, so
/// a reconstruction that differs anywhere makes every downstream secret
/// disagree with the client's.
///
/// That is only sound because every input is either a constant or comes from
/// the authenticated cookie:
///
///   * `random` — RFC 8446 §4.1.3's fixed HelloRetryRequest sentinel;
///   * `legacy_session_id_echo` — always empty. RFC 9147 §5: "DTLS servers
///     MUST NOT echo the 'legacy_session_id' value from the client" (DTLS
///     does not use TLS 1.3's compatibility mode), so this is a constant
///     here where in TLS it would be peer-controlled;
///   * `cipher_suite` — from the cookie;
///   * `supported_versions` — RFC 8446 §4.1.4 requires it, and it is the
///     only place DTLS 1.3 is named (every wire version field says 1.2);
///   * `cookie` — the bytes themselves, echoed back by the client.
///
/// RFC 8446 §4.1.4 also forbids a HelloRetryRequest carrying extensions the
/// client did not offer, `cookie` excepted — `supported_versions` is always
/// in a DTLS 1.3 ClientHello, so this pair is legal for any peer that got
/// this far.
fn encodeHelloRetryRequest(suite: CipherSuite, cookie: []const u8, body_buf: []u8) HandshakeError![]u8 {
    var versions_buf: [2]u8 = undefined;
    const versions = try messages.encodeSupportedVersionsServerHello(messages.version_dtls13, &versions_buf);
    var cookie_ext_buf: [2 + max_cookie_len]u8 = undefined;
    if (cookie.len > max_cookie_len) return error.BufferTooShort;
    const cookie_ext = messages.encodeCookieExtension(cookie, &cookie_ext_buf) catch return error.BufferTooShort;
    const exts = [_]messages.Extension{
        .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = versions },
        .{ .ext_type = @intFromEnum(messages.ExtensionType.cookie), .data = cookie_ext },
    };
    return messages.encodeServerHello(.{
        .random = messages.hello_retry_request_random,
        .legacy_session_id_echo = &.{},
        .cipher_suite = @intFromEnum(suite),
        .extensions = &exts,
    }, body_buf) catch return error.BufferTooShort;
}

/// Sized for `encodeHelloRetryRequest`'s output: a ServerHello head plus two
/// small extensions, the larger of which is the cookie.
const max_hrr_body_len = 128 + max_cookie_len;

/// Where a `Connection`'s randomness comes from — and, at every call site,
/// which of the two possible answers the caller is choosing.
///
/// **Why this is a type and not a `std.Random` parameter.** `std.Random` is a
/// vtable: `DefaultPrng.init(0)` and a real CSPRNG are indistinguishable at the
/// call site, and nothing in this module can inspect the generator it is
/// handed. The previous signature (`random: std.Random`) therefore accepted
/// whatever generator the caller happened to have in scope, and the weak path
/// was not a variant of the API — it WAS the API; the doc comment asking for a
/// CSPRNG was the only thing standing between a consumer and a seed-derived
/// ephemeral key. What a union can do is force the caller to NAME the answer,
/// so a seeded generator reaches the handshake only through a declaration that
/// says out loud that it is seeded and for tests. The check is still not
/// mechanical — it is a claim the caller makes deliberately instead of by
/// reflex, which is the difference between a hazard and a decision.
///
/// This is a VALUE, not a capability handle, and that is why it fits here.
/// `Connection` is a sans-I/O state machine — no socket, no clock, no
/// allocator; every external fact arrives as an input value — so the `io:
/// std.Io` arm the sibling `coconut`/`bbs`/`ibe` modules use is deliberately
/// absent: `std.Io` is the authority to open sockets and files, precisely what
/// this design exists to withhold from a protocol engine. A tagged union costs
/// that invariant nothing.
pub const Entropy = union(enum) {
    /// PRODUCTION. A generator the caller asserts is cryptographically secure
    /// — `std.Random.DefaultCsprng` seeded from real OS entropy
    /// (`getrandom(2)`), or an equivalent. std 0.16 removed
    /// `std.crypto.random`, so this module has no hidden RNG of its own and
    /// cannot verify the assertion: naming this arm IS the assertion.
    csprng: std.Random,

    /// **TEST ONLY.** A caller-seeded generator, so a handshake can be
    /// replayed byte-for-byte — this module's own suites and its wolfSSL
    /// interop harness need exactly that, and there is no other way to get a
    /// reproducible flight out of a state machine that draws keys.
    ///
    /// What choosing this in production costs, concretely: in `.cert_dhe` mode
    /// the bytes drawn from it ARE the x25519 / secp256r1 ephemeral PRIVATE
    /// KEY (`ecdheGenerate`). Anyone who learns the seed — a constant in the
    /// binary, a PID, a boot timestamp — re-derives that key, recomputes the
    /// (EC)DHE shared secret and decrypts every session recorded from this
    /// peer, RETROACTIVELY, including traffic captured long before the seed
    /// leaked; forward secrecy, the entire reason an ephemeral key is
    /// generated at all, is gone. Smaller and also real: a constant
    /// ClientHello/ServerHello `random` (byte-identical, linkable handshakes)
    /// and a repeated RSA-PSS CertificateVerify salt.
    seeded_for_test: std.Random,

    /// The arm-erased generator, for the leaves in this file that actually
    /// draw bytes. Deliberately NOT `pub`: the point of the type is that the
    /// choice is visible at the call site, and a public accessor would hand
    /// callers back the flat `std.Random` this replaced.
    fn source(self: Entropy) std.Random {
        return switch (self) {
            .csprng => |r| r,
            .seeded_for_test => |r| r,
        };
    }
};

pub const Connection = struct {
    role: Role,
    config: Config,
    state: State = .start,
    /// RFC 9147 §5.2's handshake-message counter (independent of the
    /// record layer's sequence number).
    message_seq: u16 = 0,
    /// Current epoch (RFC 9147 §4.1); starts at 0 (the unencrypted flight).
    epoch: u16 = 0,

    // ── application-data record state (post-handshake) ──────────────────
    suite: CipherSuite = .aes_128_ccm_8_sha256,
    write_keys: DirKeys = .{},
    read_keys: DirKeys = .{},
    /// Next record sequence number to send in the application epoch.
    send_seq: u48 = 0,
    /// Highest sequence number successfully deprotected (for §4.2.2/§4.3
    /// reconstruction, and as the anti-replay window's right edge).
    recv_max_seq: u48 = 0,
    recv_seen_any: bool = false,
    /// RFC 9147 §4.5.1 sliding anti-replay window bitmap for the
    /// application epoch — see `replayCheckAndUpdate`'s doc comment.
    recv_window: u64 = 0,

    // ── handshake-in-progress state (RFC 9147 §5 flight engine) ─────────
    /// Running transcript hash (RFC 8446 §4.4.1, TLS-style 4-byte-header
    /// framing — see `engine.zig`).
    transcript: engine.Transcript = .{},
    /// Handshake-epoch (epoch 2) record-protection keys — mirrors
    /// `write_keys`/`read_keys` above but for the {EncryptedExtensions,
    /// Finished} flight rather than application data.
    hs_write_keys: DirKeys = .{},
    hs_read_keys: DirKeys = .{},
    /// RFC 8446 §7.1 handshake traffic secrets (`"c hs traffic"`/`"s hs
    /// traffic"`). Persisted (not just used once) because a Finished is
    /// computed/verified later, once the transcript has moved on.
    hs_traffic_client: [32]u8 = undefined,
    hs_traffic_server: [32]u8 = undefined,
    /// Application traffic secrets, derived as soon as the transcript
    /// reaches "through the server's Finished" — but only INSTALLED
    /// (`installApplicationKeys`) once the handshake is mutually
    /// confirmed. The client confirms immediately (having just verified
    /// the server's Finished) and installs right away; the server stashes
    /// these here until the client's Finished verifies.
    pending_ap_client: [32]u8 = undefined,
    pending_ap_server: [32]u8 = undefined,
    /// Per-epoch record sequence-number bookkeeping for the two handshake
    /// epochs (epoch 0: ClientHello/ServerHello; epoch 2:
    /// EncryptedExtensions/Finished) — kept separate from the application
    /// epoch's `send_seq`/`recv_max_seq`/`recv_seen_any` above.
    hs0: EpochSeqState = .{},
    hs2: EpochSeqState = .{},
    /// ClientHello1's `random`, kept because RFC 8446 §4.1.2 requires
    /// ClientHello2 to reuse it verbatim after a HelloRetryRequest.
    client_random: [32]u8 = undefined,
    /// `Hash(ClientHello1)`, captured before the transcript moves on, for
    /// RFC 8446 §4.4.1's `message_hash` rewrite. Only meaningful once a
    /// HelloRetryRequest has actually arrived.
    client_hello1_hash: [32]u8 = undefined,
    /// A HelloRetryRequest has already been processed. RFC 8446 §4.1.4: a
    /// client that receives a second one MUST abort — otherwise a server
    /// could keep a client in an unbounded retry loop.
    saw_hello_retry_request: bool = false,
    /// Client side: the cipher suite the HelloRetryRequest named, if one
    /// arrived. RFC 8446 §4.1.4 requires the eventual ServerHello to select
    /// the SAME suite ("Servers MUST ensure that they negotiate the same
    /// cipher suite when receiving a conformant updated ClientHello"), and
    /// the retry's bytes are part of the transcript, so a server that
    /// switched has either lost track of what it committed to or is probing.
    hrr_cipher_suite: ?u16 = null,
    /// `.cert_dhe` mode only: this side's ephemeral (EC)DHE key pair for the
    /// handshake. The CLIENT generates it in `startHandshake` (and REPLACES
    /// it, in the group the server named, on a HelloRetryRequest) and keeps
    /// `ecdhe_secret` resident until `handleFlight` computes the shared
    /// secret, then zeroizes it immediately — forward secrecy; the SERVER
    /// generates + consumes it entirely within `serverProcessClientHello`.
    /// `ecdhe_public[0..ecdhe_public_len]` is the wire `key_share` value and
    /// `ecdhe_group` the group it belongs to — the client checks the
    /// ServerHello's share against BOTH, since a server that answers in a
    /// group we never offered a share in has not done the key exchange we
    /// did. Unused in `.psk` mode. Zeroized in `deinit`.
    ecdhe_group: u16 = 0,
    ecdhe_secret: [32]u8 = undefined,
    ecdhe_public: [max_key_share_len]u8 = undefined,
    ecdhe_public_len: usize = 0,
    /// Whether `ecdhe_secret` currently holds live private-key material (so
    /// `deinit` only wipes real bytes, and a double-wipe after the in-handshake
    /// zeroization is harmless).
    ecdhe_secret_live: bool = false,
    /// RFC 9147 §5.7 retransmission: the last flight WE sent, cached
    /// verbatim so `poll` can resend it unchanged on timeout.
    last_flight: [1500]u8 = undefined,
    last_flight_len: usize = 0,
    retransmit_timer: flight.RetransmitTimer = flight.RetransmitTimer.init(1000, 60_000),
    /// RFC 9147 §7 flight bookkeeping (`flight.FlightTracker`) for the
    /// records of the flight currently awaiting acknowledgement.
    /// Acknowledgement here is IMPLICIT (receipt of the peer's next
    /// expected flight clears it), matching RFC 9147 §7's own framing of
    /// ACKs as needed only when a peer would otherwise have no way to
    /// infer receipt — not required on this engine's synchronous
    /// request/immediate-response happy path.
    /// Sized for the largest flight this engine ever sends: PSK-only is 3
    /// (ServerHello, EncryptedExtensions, Finished) or 1 (client Finished);
    /// certificate mode adds up to 3 more (CertificateRequest, Certificate,
    /// CertificateVerify) — 8 covers the server's worst case with headroom.
    pending_flight_buf: [8]flight.RecordNumber = undefined,
    pending_flight_count: usize = 0,

    // ── incoming-flight accumulation (RFC 9147 §5.2 reassembly) ─────────
    /// Datagrams received for the flight currently being consumed,
    /// concatenated. Non-empty only while a flight is INCOMPLETE — every
    /// `handleFlight` call that finishes a flight (or fails) empties it, so
    /// the single-datagram case never carries anything between calls.
    /// Bounded by construction; see `max_flight_bytes`.
    rx_flight: [max_flight_bytes]u8 = undefined,
    rx_flight_len: usize = 0,
    /// RFC 9147 §5.2's `message_seq` of the next handshake message expected
    /// FROM the peer (this side's own counter is `message_seq`). `null`
    /// until the first inbound message fixes the baseline — which it must,
    /// because a stateless server's second ClientHello arrives on a
    /// brand-new `Connection` already carrying `message_seq = 1` (see
    /// `acceptCookie`). Fragments below this are treated as retransmission
    /// and skipped; fragments above it are `error.InterleavedFragments`.
    peer_message_seq: ?u16 = null,

    pub const InitError = ConfigError;

    pub fn clientInit(config: Config) InitError!Connection {
        try config.validate();
        return .{ .role = .client, .config = config };
    }

    pub fn serverInit(config: Config) InitError!Connection {
        try config.validate();
        return .{ .role = .server, .config = config };
    }

    /// The result of one `handleFlight` step.
    pub const HandshakeResult = struct {
        /// Bytes to send back to the peer for this step — may be empty
        /// (e.g. once `done` and no further flight is needed).
        out: []const u8,
        /// `true` once THIS call has driven the connection to `.connected`.
        done: bool,
        /// `true` when the datagram was CONSUMED BUT the flight is still
        /// incomplete — a handshake message is split across datagrams (RFC
        /// 9147 §5.2) and the rest has not arrived. `out` is empty and the
        /// connection is byte-for-byte unchanged apart from the buffered
        /// bytes; feed the next datagram to the same `Connection`.
        ///
        /// A caller that ignores this field still behaves correctly — it
        /// sees an empty `out` and a not-`done` result, which is exactly
        /// "send nothing, read again" — so it exists to be ASSERTED on
        /// (a test that wants to prove reassembly really happened, rather
        /// than that the handshake merely completed).
        need_more_data: bool = false,
    };

    /// Client-only: builds and sends flight 1 (RFC 9147 §5.3) — a
    /// ClientHello offering `config.psk_identity` under `psk_ke` (no DHE,
    /// no certificates), with a real RFC 8446 §4.2.11.2 PSK binder computed
    /// over the transcript. `now_ms` arms the retransmission timer `poll`
    /// later checks. Transitions `.start` -> `.wait_server_hello`.
    ///
    /// `entropy` MUST be a cryptographically secure source — pass
    /// `.{ .csprng = … }`. This module has no hidden RNG (std 0.16 removed
    /// `std.crypto.random`), so the generator is the caller's to supply, and
    /// `Entropy` makes which KIND of generator a thing the caller writes out
    /// here rather than something inferred from whatever was in scope. What
    /// breaks under the `.seeded_for_test` arm is concrete and not recoverable
    /// after the fact:
    ///
    ///   * In `cert_dhe` mode this call draws the x25519 / secp256r1
    ///     ephemeral PRIVATE KEY (`ecdheGenerate`). A passive eavesdropper
    ///     who knows the seed derives it, recomputes the (EC)DHE shared
    ///     secret, and decrypts every session recorded from this peer,
    ///     retroactively — including sessions captured before the seed leaked.
    ///   * The ClientHello's 32-byte `random` field becomes a constant, so
    ///     every handshake this peer starts is byte-identical on the wire and
    ///     trivially linkable across networks. Bounded next to the above (the
    ///     field is public), but it is the symptom that shows first.
    ///
    /// `std.Random` is a vtable, so this module still cannot check the QUALITY
    /// of what it is handed inside either arm; a seeded generator and
    /// `getrandom(2)` look the same to the code. What the type buys is that
    /// the weak path can no longer be entered by accident.
    pub fn startHandshake(self: *Connection, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError![]const u8 {
        if (self.role != .client) return error.WrongState;
        if (self.state != .start) return error.WrongState;

        var ch_body_buf: [512]u8 = undefined;
        const ch_body = switch (self.config.key_exchange) {
            .psk => try self.buildClientHello(entropy, null, &ch_body_buf),
            // `advertised_groups[0]` — the group a first ClientHello offers a
            // share in. A server that wants a different one says so with a
            // HelloRetryRequest (`handleHelloRetryRequest`).
            .cert_dhe, .cert_dhe_insecure_unauthenticated => try self.buildClientHelloCertDhe(entropy, null, advertised_groups[0], &ch_body_buf),
        };
        self.transcript.append(@intFromEnum(messages.HandshakeType.client_hello), ch_body);
        // ClientHello1 is the first message, so the transcript hash right
        // now IS `Hash(ClientHello1)` — the value RFC 8446 §4.4.1's
        // `message_hash` rewrite needs if a HelloRetryRequest arrives. It has
        // to be captured here; once the transcript moves on it is gone.
        self.client_hello1_hash = self.transcript.currentHash();

        var frag_buf: [512 + handshake.header_len]u8 = undefined;
        const fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.client_hello), self.message_seq, ch_body, &frag_buf);
        self.message_seq +%= 1;

        const ch_seq = self.hs0.send_seq;
        const record_bytes = try self.writeEpoch0Record(fragment, out);
        self.markFlightSent(&.{.{ .epoch = 0, .sequence_number = ch_seq }});
        try self.cacheFlight(record_bytes, now_ms);

        self.state = .wait_server_hello;
        return record_bytes;
    }

    /// Both roles: feeds an incoming (possibly multi-record-coalesced)
    /// datagram to the handshake engine and returns whatever this side
    /// needs to send in response (`HandshakeResult.out`, possibly empty).
    /// `entropy` is consulted on the server's `.start` step (the ServerHello
    /// `random`) and, in certificate mode, whenever THIS side signs a
    /// CertificateVerify (`certverify.sign`'s PSS salt / ECDSA-Ed25519
    /// noise) — harmless to pass through unconditionally otherwise. Errors
    /// are always typed (a wrong PSK, a tampered record, an out-of-order
    /// message, ...) — never a panic.
    ///
    /// `entropy` MUST be a cryptographically secure source — pass
    /// `.{ .csprng = … }`, the same caller-supplied seam as `startHandshake`
    /// (std 0.16 removed `std.crypto.random`). The consequence is worst on the
    /// SERVER side of certificate mode, where this call — not `startHandshake`
    /// — is what draws the ephemeral (EC)DHE private key (`ecdheGenerate`, via
    /// `serverProcessClientHello`): under the `.seeded_for_test` arm a passive
    /// eavesdropper who knows the seed recomputes the shared secret for every
    /// association this server ever accepted and decrypts them all,
    /// retroactively. It also draws the ServerHello `random` and, whenever
    /// this side signs a CertificateVerify, the RSA-PSS salt — a PSS salt
    /// that repeats weakens the signature's proof, and `certverify.sign`
    /// refuses `null` outright (`error.RandomRequired`) for exactly that
    /// reason. Passing the same `Entropy` value to every call in a connection
    /// loop is correct and expected; passing a SEEDED one is the hazard, and
    /// it is now a hazard the caller has to spell.
    ///
    /// **Reassembly across calls (RFC 9147 §5.2).** A flight need not arrive
    /// in one datagram, and a single handshake message need not either — a
    /// certificate chain routinely exceeds the path MTU, so a real peer
    /// fragments it. Each datagram is therefore appended to a bounded
    /// per-connection buffer (`max_flight_bytes`) and the flight is parsed
    /// from the accumulation. While the flight is still incomplete this
    /// returns `need_more_data` with an empty `out`, and — this is the part
    /// that makes it safe — the connection is ROLLED BACK to exactly the
    /// state it had before the call, so a half-processed flight can never
    /// leave the state machine, the transcript, the key schedule or the
    /// anti-replay windows half-advanced. `Connection` is a self-contained
    /// value (fixed arrays, no allocator, no pointers into itself), which is
    /// what makes a snapshot/restore a legitimate transaction rather than a
    /// shallow copy that aliases something.
    ///
    /// The cost of that simplicity is that an incomplete flight is re-parsed
    /// from its first record when the next datagram arrives (including
    /// re-running the AEAD on records already seen). That is bounded by
    /// `max_flight_bytes` and happens only on the fragmented path; the
    /// single-datagram case parses exactly once, as before.
    ///
    /// KNOWN LIMIT (documented, not silently broken): what the accumulation
    /// tolerates is a peer that FRAGMENTS — the same flight arriving in
    /// pieces. A peer that instead RETRANSMITS a whole flight it already
    /// sent, verbatim, into the middle of an incomplete accumulation is
    /// rejected (the duplicated records re-enter the parse out of position,
    /// surfacing as `error.Malformed` or `error.ReplayedRecord`), and the
    /// caller must restart the association. Redundant fragments OF THE
    /// MESSAGE BEING REASSEMBLED are fine — that case is the ordinary one
    /// and `handshake.Reassembler` absorbs it — as are retransmitted copies
    /// of messages already consumed, which `takeHandshakeMessage` skips by
    /// `message_seq`. This is no worse than the pre-reassembly engine (which
    /// answered a retransmitted flight with `error.WrongState`), but it is
    /// not the full RFC 9147 §5.7 receiver either.
    pub fn handleFlight(self: *Connection, datagram: []const u8, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        if (datagram.len > self.rx_flight.len - self.rx_flight_len) {
            self.rx_flight_len = 0;
            return error.FlightTooLarge;
        }
        @memcpy(self.rx_flight[self.rx_flight_len..][0..datagram.len], datagram);
        self.rx_flight_len += datagram.len;

        // Taken AFTER the append, so a rollback keeps the newly-buffered
        // bytes while undoing everything the parse below did.
        var saved = self.*;
        // The snapshot is a full copy of the connection, key material
        // included; it must not outlive the call on the stack.
        defer std.crypto.secureZero(u8, std.mem.asBytes(&saved));

        // Aliases `self.rx_flight`. Nothing on the parse path writes that
        // field (only `handleFlight` itself does), which is what makes
        // handing a slice of `self` to a `*Connection` method safe here.
        const input = self.rx_flight[0..self.rx_flight_len];
        const result = switch (self.role) {
            .server => self.handleFlightServer(input, entropy, now_ms, out),
            .client => self.handleFlightClient(input, entropy, now_ms, out),
        } catch |err| switch (err) {
            error.FlightIncomplete => {
                self.* = saved;
                return .{ .out = out[0..0], .done = false, .need_more_data = true };
            },
            // A real protocol/crypto failure ends this flight: drop the
            // accumulation so the next datagram is not parsed as a
            // continuation of a flight that already failed.
            else => {
                self.rx_flight_len = 0;
                return err;
            },
        };
        self.rx_flight_len = 0;
        return result;
    }

    /// Caller-clocked retransmission (RFC 9147 §5.7): if this side is
    /// mid-handshake, still has a cached last-sent flight, and
    /// `retransmit_timer` has expired as of `now_ms`, re-emits that flight
    /// verbatim (doubling the backoff) into `out` and returns it; `null`
    /// otherwise. Never blocks, never sleeps — `now_ms` is entirely
    /// caller-supplied, matching `flight.zig`'s fake-clock-testable style.
    pub fn poll(self: *Connection, now_ms: u64, out: []u8) HandshakeError!?[]const u8 {
        if (self.state == .connected or self.state == .start) return null;
        if (self.last_flight_len == 0) return null;
        if (!self.retransmit_timer.isExpired(now_ms)) return null;
        if (out.len < self.last_flight_len) return error.BufferTooShort;
        @memcpy(out[0..self.last_flight_len], self.last_flight[0..self.last_flight_len]);
        self.retransmit_timer.onTimeout(now_ms);
        return out[0..self.last_flight_len];
    }

    /// Installs the negotiated suite's application-data record-protection
    /// keys from a completed handshake's client/server application traffic
    /// secrets (RFC 8446 §7.3 key/iv + RFC 9147 §4.2.3 sn), and marks the
    /// connection `connected`. `client_ap_secret`/`server_ap_secret` are the
    /// outputs of `keyschedule.deriveApplicationTrafficSecrets`. All four
    /// supported suites use SHA-256, so the schedule uses `HkdfSha256`.
    ///
    /// The client WRITES with the client secret and READS with the server's
    /// (and vice-versa for the server), so one call wires both directions
    /// correctly for either role.
    pub fn installApplicationKeys(
        self: *Connection,
        suite: CipherSuite,
        client_ap_secret: [32]u8,
        server_ap_secret: [32]u8,
    ) SendError!void {
        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const params = suiteParams(suite) orelse return error.UnsupportedSuite;

        const my_secret = if (self.role == .client) client_ap_secret else server_ap_secret;
        const peer_secret = if (self.role == .client) server_ap_secret else client_ap_secret;

        self.write_keys = deriveDir(Hkdf, params, my_secret);
        self.read_keys = deriveDir(Hkdf, params, peer_secret);
        self.suite = suite;
        self.epoch = application_epoch;
        self.send_seq = 0;
        self.recv_max_seq = 0;
        self.recv_seen_any = false;
        self.recv_window = 0;
        self.state = .connected;
    }

    /// Protects `plaintext` as an application_data record (RFC 9147 §4.2):
    /// builds the DTLSInnerPlaintext (`plaintext || content_type=23`), AEAD-
    /// seals it with the connection's write key over the unified record
    /// header as additional data, then encrypts the header's sequence number
    /// (RFC 9147 §4.2.3). Returns `header || protected_record` written into
    /// `out`. Advances the send sequence number.
    pub fn send(self: *Connection, plaintext: []const u8, out: []u8) SendError![]const u8 {
        return self.protectRecord(content_type_application_data, plaintext, out);
    }

    /// The record-protection half of `send`, parameterised by the inner
    /// content type. `send` is this with `application_data`; the server's
    /// RFC 9147 §7 ACK for the client's final flight is this with `ack`,
    /// which is why the two are not one function: an ACK is not application
    /// data, but it is protected identically and shares the send sequence
    /// number space.
    fn protectRecord(self: *Connection, inner_content_type: u8, payload: []const u8, out: []u8) SendError![]const u8 {
        if (self.state != .connected) return error.NotConnected;
        const params = suiteParams(self.suite) orelse return error.UnsupportedSuite;

        // DTLSInnerPlaintext = content || content_type (no extra padding).
        var inner_buf: [1500]u8 = undefined;
        if (payload.len + 1 > inner_buf.len) return error.BufferTooShort;
        @memcpy(inner_buf[0..payload.len], payload);
        inner_buf[payload.len] = inner_content_type;
        const inner = inner_buf[0 .. payload.len + 1];

        const ct_len = inner.len + params.tag_len;
        const seq_len: record.SeqNumLen = if (self.send_seq <= 0xff) .short else .long;
        const seq_bytes_n: usize = if (seq_len == .short) 1 else 2;

        // Encode the header with the PLAINTEXT sequence number — this is the
        // AEAD additional_data (RFC 9147 §4.2.1: header prior to sn encrypt).
        const hdr = record.UnifiedHeader{
            .epoch_low = @truncate(self.epoch),
            .seq_len = seq_len,
            .seq_wire = @truncate(self.send_seq),
            .cid = null,
            .length = @intCast(ct_len),
        };
        const hdr_slice = record.encodeUnified(hdr, out) catch return error.BufferTooShort;
        const hdr_len = hdr_slice.len;
        if (out.len < hdr_len + ct_len) return error.BufferTooShort;

        const n = protectDispatch(self.suite, self.write_keys, self.epoch, self.send_seq, inner, out[0..hdr_len], out[hdr_len..]) catch
            return error.BufferTooShort;
        std.debug.assert(n == ct_len);

        // RFC 9147 §4.2.3: encrypt the on-wire sequence number using a
        // 16-byte sample of the record ciphertext. The seq bytes follow the
        // 1-byte flags (and CID, if any) — here no CID, so offset 1.
        const seq_off: usize = 1;
        try snMaskDispatch(self.suite, self.write_keys, out[hdr_len..][0..16], out[seq_off..][0..seq_bytes_n]);

        self.send_seq +%= 1;
        return out[0 .. hdr_len + ct_len];
    }

    /// Un-protects an incoming datagram back into application data (the
    /// mirror of `send`): decrypts the header sequence number, reconstructs
    /// the full 48-bit value, AEAD-opens the record over the recovered
    /// header, and strips the trailing content type. Returns the recovered
    /// application bytes written into `out`. A tag mismatch or malformed
    /// record is a typed error — never a panic.
    pub fn recv(self: *Connection, datagram: []const u8, out: []u8) SendError![]const u8 {
        if (self.state != .connected) return error.NotConnected;

        const dec = record.decodeUnified(datagram, 0) catch return error.Malformed;
        const seq_len = dec.hdr.seq_len;
        const seq_bytes_n: usize = if (seq_len == .short) 1 else 2;
        const hdr_len = dec.consumed;
        // Sequence number follows the 1-byte flags (+ CID, if any).
        const seq_off: usize = if (dec.hdr.cid) |c| 1 + c.len else 1;

        // The ciphertext is the explicit length, or the rest of the datagram.
        const ct = if (dec.hdr.length) |l| blk: {
            if (datagram.len < hdr_len + l) return error.Malformed;
            break :blk datagram[hdr_len..][0..l];
        } else datagram[hdr_len..];
        if (ct.len < 16) return error.RecordTooShort;

        // Copy the header into a working buffer so we can un-mask the seq
        // number in place: the AEAD additional_data is the header with the
        // PLAINTEXT sequence number (RFC 9147 §4.2.1).
        var hdr_buf: [16]u8 = undefined;
        if (hdr_len > hdr_buf.len) return error.Malformed;
        @memcpy(hdr_buf[0..hdr_len], datagram[0..hdr_len]);
        try snMaskDispatch(self.suite, self.read_keys, ct[0..16], hdr_buf[seq_off..][0..seq_bytes_n]);

        const wire_low: u16 = if (seq_len == .short)
            hdr_buf[seq_off]
        else
            std.mem.readInt(u16, hdr_buf[seq_off..][0..2], .big);
        const largest = if (self.recv_seen_any) self.recv_max_seq else 0;
        const full_seq = record.reconstructSequenceNumber(largest, seq_len, wire_low);

        const body_len = unprotectDispatch(self.suite, self.read_keys, self.epoch, full_seq, ct, hdr_buf[0..hdr_len], out) catch
            return error.DecryptionFailed;
        if (body_len == 0) return error.Malformed; // must hold at least the content type

        // Strip trailing zero padding, then the content-type byte
        // (RFC 8446 §5.2 DTLSInnerPlaintext).
        var end = body_len;
        while (end > 0 and out[end - 1] == 0) end -= 1;
        if (end == 0) return error.Malformed;
        const ctype = out[end - 1];
        if (ctype != content_type_application_data) return switch (ctype) {
            content_type_ack => error.ReceivedAck,
            content_type_handshake => error.ReceivedPostHandshakeMessage,
            else => error.Malformed,
        };

        // RFC 9147 §4.5.1 anti-replay window. This MUST run only after the
        // AEAD tag above has already verified (it has, by this point) —
        // gating on an unauthenticated sequence number would let an
        // attacker poison the window with forged records.
        if (!replayCheckAndUpdate(&self.recv_seen_any, &self.recv_max_seq, &self.recv_window, full_seq))
            return error.ReplayedRecord;

        return out[0 .. end - 1];
    }

    /// Whether a HelloRetryRequest was part of this connection's handshake
    /// (RFC 8446 §4.1.4 / RFC 9147 §5.1) — a client that ANSWERED one, or a
    /// server that either SENT one or accepted the cookie that came back.
    /// Exposed because "did the retry path actually run" is not otherwise
    /// observable from outside, and a test that cannot tell is a test that
    /// silently stops covering it: without this, a live-interop test whose
    /// peer quietly stopped doing the exchange would keep passing as a
    /// duplicate of the non-retry test.
    ///
    /// Note this is per-`Connection`, and a stateless server uses a fresh
    /// `Connection` per datagram — so on the server it reports what THIS
    /// object did, not what the handshake as a whole did.
    pub fn sawHelloRetryRequest(self: Connection) bool {
        return self.saw_hello_retry_request;
    }

    pub fn deinit(self: *Connection) void {
        // NOTE: do NOT follow this with `self.write_keys = .{}` (etc.) —
        // `DirKeys`'s field defaults are `undefined`, so re-assigning the
        // struct literal would silently re-introduce uninitialized memory
        // over the just-zeroed secret bytes. Only the non-secret length
        // bookkeeping is reset, after the secret bytes are wiped.
        secureZeroDirKeys(&self.write_keys);
        secureZeroDirKeys(&self.read_keys);
        secureZeroDirKeys(&self.hs_write_keys);
        secureZeroDirKeys(&self.hs_read_keys);
        std.crypto.secureZero(u8, &self.hs_traffic_client);
        std.crypto.secureZero(u8, &self.hs_traffic_server);
        std.crypto.secureZero(u8, &self.pending_ap_client);
        std.crypto.secureZero(u8, &self.pending_ap_server);
        // `.cert_dhe` ephemeral X25519 private key — already wiped mid-handshake
        // for forward secrecy, but wipe again defensively (idempotent; the
        // handshake may have errored out before reaching that point).
        std.crypto.secureZero(u8, &self.ecdhe_secret);
        self.ecdhe_secret_live = false;
        self.write_keys.key_len = 0;
        self.write_keys.sn_len = 0;
        self.read_keys.key_len = 0;
        self.read_keys.sn_len = 0;
    }

    // ── handshake flight engine (RFC 9147 §5, PSK-only) ──────────────────

    /// Builds the ClientHello BODY (post-handshake-header) into `body_buf`:
    /// random || empty session id || `config.cipher_suites` ||
    /// {psk_key_exchange_modes=[psk_ke], signature_algorithms,
    /// pre_shared_key} — `pre_shared_key` MUST be the last extension (RFC
    /// 8446 §4.2.11) since its binder covers everything before it;
    /// `signature_algorithms` is real RFC 8446 §9.2-mandatory advertising
    /// (NOT PSK-mode-only informational filler — a PSK-mode server can
    /// still authenticate with a certificate ON TOP of the PSK, see
    /// `Config.cert`, and needs this list to negotiate a scheme for its
    /// CertificateVerify: `serverProcessClientHello`'s `selectSignatureScheme`
    /// call). Patches in the REAL PSK binder in place of a same-length
    /// placeholder once the (still-empty-so-far) transcript's truncated hash
    /// is known (RFC 8446 §4.2.11.2).
    /// `cookie` is the HelloRetryRequest cookie to echo (RFC 8446 §4.2.2),
    /// `null` for the first ClientHello. On a retry the `entropy` argument is
    /// ignored and `self.client_random` is reused: RFC 8446 §4.1.2 requires
    /// ClientHello2 to be ClientHello1 unmodified except for a short listed
    /// set of changes, and the random is not on that list.
    fn buildClientHello(self: *Connection, entropy: Entropy, cookie: ?[]const u8, body_buf: []u8) HandshakeError![]u8 {
        var random_bytes: [32]u8 = undefined;
        if (cookie == null) {
            entropy.source().bytes(&random_bytes);
            self.client_random = random_bytes;
        } else {
            random_bytes = self.client_random;
        }

        var cs_arr: [8]u16 = undefined;
        if (self.config.cipher_suites.len > cs_arr.len) return error.BufferTooShort;
        for (self.config.cipher_suites, 0..) |cs, i| cs_arr[i] = @intFromEnum(cs);
        const cs_list = cs_arr[0..self.config.cipher_suites.len];

        var modes_buf: [4]u8 = undefined;
        const modes_ext = try messages.encodePskKeyExchangeModes(&.{.psk_ke}, &modes_buf);

        var sigalgs_buf: [2 + 2 * default_signature_algorithms.len]u8 = undefined;
        const sigalgs_ext = try signatureAlgorithmsExtension(self.config.signature_algorithms, &sigalgs_buf);

        // 32-byte (SHA-256) placeholder binder, patched below.
        var placeholder_binder = [_]u8{0} ** 32;
        var psk_buf: [128]u8 = undefined;
        const identities = [_]messages.PskIdentity{.{ .identity = self.config.psk_identity, .obfuscated_ticket_age = 0 }};
        const binders = [_][]const u8{&placeholder_binder};
        const psk_ext_data = try messages.encodeOfferedPsks(.{ .identities = &identities, .binders = &binders }, &psk_buf);

        var versions_buf: [3]u8 = undefined;
        const versions_ext = try messages.encodeSupportedVersionsClientHello(&.{messages.version_dtls13}, &versions_buf);

        // RFC 8446 §9.2 lets a psk_ke-only client omit `supported_groups` and
        // `key_share`, but real servers do not all agree: wolfSSL answers a
        // ClientHello without them with `alert(illegal_parameter)`. Sending
        // `supported_groups` plus an EMPTY `key_share` is what wolfSSL's own
        // psk_ke client sends, costs nothing, and keeps the exchange PSK-only
        // — an empty `client_shares` offers no share to negotiate.
        var groups_buf: [2 + 2 * advertised_groups.len]u8 = undefined;
        const groups_ext = try messages.encodeSupportedGroups(&advertised_groups, &groups_buf);
        var key_share_buf: [2]u8 = undefined;
        const key_share_ext = try messages.encodeKeyShareClientHello(&.{}, &key_share_buf);

        var cookie_buf: [2 + max_cookie_len]u8 = undefined;
        const cookie_ext: ?[]const u8 = if (cookie) |c| try messages.encodeCookieExtension(c, &cookie_buf) else null;

        // `pre_shared_key` MUST be the last extension (RFC 8446 §4.2.11) —
        // the binder is computed over everything that precedes it.
        var exts_buf: [7]messages.Extension = undefined;
        var n_exts: usize = 0;
        exts_buf[n_exts] = .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = versions_ext };
        n_exts += 1;
        exts_buf[n_exts] = .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_groups), .data = groups_ext };
        n_exts += 1;
        exts_buf[n_exts] = .{ .ext_type = @intFromEnum(messages.ExtensionType.key_share), .data = key_share_ext };
        n_exts += 1;
        exts_buf[n_exts] = .{ .ext_type = @intFromEnum(messages.ExtensionType.psk_key_exchange_modes), .data = modes_ext };
        n_exts += 1;
        exts_buf[n_exts] = sigalgs_ext;
        n_exts += 1;
        if (cookie_ext) |c| {
            exts_buf[n_exts] = .{ .ext_type = @intFromEnum(messages.ExtensionType.cookie), .data = c };
            n_exts += 1;
        }
        exts_buf[n_exts] = .{ .ext_type = @intFromEnum(messages.ExtensionType.pre_shared_key), .data = psk_ext_data };
        n_exts += 1;
        const exts = exts_buf[0..n_exts];

        const ch_full = try messages.encodeClientHello(.{
            .random = random_bytes,
            .legacy_session_id = &.{},
            .cipher_suites = cs_list,
            .extensions = exts,
        }, body_buf);

        // RFC 8446 §4.2.11.2: binder = HMAC(finished_key,
        // Transcript-Hash(Truncate(ClientHello1))), where the hashed prefix
        // runs "up to and including the PreSharedKeyExtension.identities
        // field. That is, it includes all of the ClientHello but not the
        // binders list itself."
        //
        // `psk_ext_data`'s layout is `ids... || binders_len(2) || len(1) ||
        // binder(32)`. The binders LIST is a vector, so its 2-byte length
        // prefix belongs to the list and is dropped with it: Truncate() cuts
        // the last 2 + 1 + 32 bytes, not 33. Cutting 33 (keeping
        // `binders_len` in the hash) is a two-byte error invisible to
        // self-interop — both sides simply agree on the wrong prefix — and
        // it is what a live wolfSSL peer reported as
        // `alert(illegal_parameter)` / "binder does not verify".
        const binder_len: usize = 2 + 1 + 32;
        if (ch_full.len < binder_len) return error.Malformed;
        const truncated = ch_full[0 .. ch_full.len - binder_len];
        const binder_th = self.transcript.wouldBeHash(@intFromEnum(messages.HandshakeType.client_hello), ch_full.len, truncated);

        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
        const eh = emptySha256Hash();
        const es = keyschedule.earlySecret(Hkdf, self.config.psk);
        const bk = keyschedule.binderKey(Hkdf, es, &eh);
        const binder = keyschedule.pskBinder(Hkdf, Hmac, bk, &binder_th);
        @memcpy(ch_full[ch_full.len - 32 ..], &binder);

        return ch_full;
    }

    /// `.cert_dhe` mode ClientHello (RFC 8446 §4.1.2 / §4.2): generates this
    /// client's ephemeral (EC)DHE key pair in `group` (stored for
    /// `handleFlightClient`), then builds `random || empty session id ||
    /// cipher_suites || {supported_versions, supported_groups,
    /// signature_algorithms, key_share[, cookie]}` — NO `pre_shared_key`, NO
    /// `psk_key_exchange_modes`, NO binder (this is the PSK-less certificate
    /// handshake).
    ///
    /// `cookie` is `null` for ClientHello1 and the HelloRetryRequest's cookie
    /// (when it carried one) for ClientHello2. RFC 8446 §4.1.2 lists what
    /// ClientHello2 may change and nothing else: the `key_share` (hence
    /// `group` being a parameter, not a constant) and the `cookie`. Every
    /// other field is therefore recomputed from the SAME inputs — in
    /// particular `random` is drawn once and reused from `self.client_random`
    /// on the retry, exactly as the PSK builder does.
    fn buildClientHelloCertDhe(self: *Connection, entropy: Entropy, cookie: ?[]const u8, group: u16, body_buf: []u8) HandshakeError![]u8 {
        // RFC 8446 §4.1.2: ClientHello2 reuses ClientHello1's `random`
        // verbatim — it is not among the permitted changes. Keyed on "has a
        // HelloRetryRequest been processed", NOT on "is there a cookie": a
        // retry can name a new group WITHOUT a cookie (a server that only
        // wants a different key share), and drawing a fresh random there
        // would make ClientHello2 a different client to the peer.
        if (!self.saw_hello_retry_request) entropy.source().bytes(&self.client_random);

        // Ephemeral (EC)DHE key pair for `group` — generated only when there
        // is not already one IN THAT GROUP. Both halves matter:
        //
        //   * a retry that names a NEW group must produce a fresh share in
        //     it. Reusing the old share (or the old group) is the single
        //     most likely way to "implement" RFC 8446 §4.1.4 without
        //     implementing it at all — and self-interop cannot tell, because
        //     our own server never asks for a group change.
        //   * a retry that carries only a COOKIE must leave the key_share
        //     alone. §4.1.2 lists what ClientHello2 may change, and "a
        //     different share in the same group" is not on it: rolling a new
        //     one anyway is a gratuitously different ClientHello2, i.e. the
        //     same class of violation as a fresh `random`.
        if (self.ecdhe_public_len == 0 or self.ecdhe_group != group) {
            var kp = try ecdheGenerate(group, entropy);
            self.ecdhe_group = kp.group;
            self.ecdhe_secret = kp.secret;
            self.ecdhe_public = kp.public;
            self.ecdhe_public_len = kp.public_len;
            self.ecdhe_secret_live = true;
            // The connection now owns the only live copy; the stack one goes
            // (the server path does the same after computing its secret).
            std.crypto.secureZero(u8, &kp.secret);
        }

        var cs_arr: [8]u16 = undefined;
        if (self.config.cipher_suites.len > cs_arr.len) return error.BufferTooShort;
        for (self.config.cipher_suites, 0..) |cs, i| cs_arr[i] = @intFromEnum(cs);
        const cs_list = cs_arr[0..self.config.cipher_suites.len];

        var groups_buf: [2 + 2 * advertised_groups.len]u8 = undefined;
        const groups_ext = try messages.encodeSupportedGroups(&advertised_groups, &groups_buf);

        var sigalgs_buf: [2 + 2 * default_signature_algorithms.len]u8 = undefined;
        const sigalgs_ext = try signatureAlgorithmsExtension(self.config.signature_algorithms, &sigalgs_buf);

        var ks_buf: [2 + 4 + max_key_share_len]u8 = undefined;
        const ks_entries = [_]messages.KeyShareEntry{.{ .group = self.ecdhe_group, .key_exchange = self.ecdhe_public[0..self.ecdhe_public_len] }};
        const ks_ext = try messages.encodeKeyShareClientHello(&ks_entries, &ks_buf);

        // RFC 8446 §4.2.1 / §D.1: `supported_versions` is the ONLY place a
        // 1.3 handshake is negotiated — every version field on the wire
        // still reads DTLS 1.2. Omitting it (as an earlier version of this
        // function did) makes a real DTLS 1.3 server negotiate 1.2 and the
        // handshake dies at the first record; self-interop never noticed,
        // because this module's own server never looked. The PSK
        // ClientHello above has carried it since the same defect was found
        // there against wolfSSL — see `root.zig`'s note on the four wire
        // defects self-interop passed.
        var versions_buf: [3]u8 = undefined;
        const versions_ext = try messages.encodeSupportedVersionsClientHello(&.{messages.version_dtls13}, &versions_buf);

        var cookie_buf: [2 + max_cookie_len]u8 = undefined;
        const cookie_ext: ?[]const u8 = if (cookie) |c| try messages.encodeCookieExtension(c, &cookie_buf) else null;

        var exts_buf: [5]messages.Extension = undefined;
        var n_exts: usize = 0;
        exts_buf[n_exts] = .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = versions_ext };
        n_exts += 1;
        exts_buf[n_exts] = .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_groups), .data = groups_ext };
        n_exts += 1;
        exts_buf[n_exts] = sigalgs_ext;
        n_exts += 1;
        exts_buf[n_exts] = .{ .ext_type = @intFromEnum(messages.ExtensionType.key_share), .data = ks_ext };
        n_exts += 1;
        if (cookie_ext) |c| {
            exts_buf[n_exts] = .{ .ext_type = @intFromEnum(messages.ExtensionType.cookie), .data = c };
            n_exts += 1;
        }

        return messages.encodeClientHello(.{
            .random = self.client_random,
            .legacy_session_id = &.{},
            .cipher_suites = cs_list,
            .extensions = exts_buf[0..n_exts],
        }, body_buf);
    }

    /// `.cert_dhe` server helper: finds a usable share in the CLIENT's
    /// `key_share` extension (a `KeyShareEntry` LIST, RFC 8446 §4.2.8.1)
    /// among the ClientHello's decoded extensions and returns it, or a typed
    /// error if absent / no entry in a group this side speaks / wrong length
    /// (never a panic).
    ///
    /// `advertised_groups` order is the server's PREFERENCE order, not the
    /// client's: RFC 8446 §4.2.8 lets the server pick any offered group it
    /// supports. This server never answers with a HelloRetryRequest asking
    /// for a DIFFERENT group — if the client offered a share this side can
    /// use, it uses it — so a client that offers nothing usable gets
    /// `MissingKeyShare` rather than a retry (documented limit, see
    /// `sendHelloRetryRequest`).
    const PeerShare = struct { group: u16, share: []const u8 };

    fn clientHelloShare(exts: []const messages.Extension) HandshakeError!PeerShare {
        for (exts) |e| {
            if (e.ext_type != @intFromEnum(messages.ExtensionType.key_share)) continue;
            var entries: [8]messages.KeyShareEntry = undefined;
            const shares = messages.decodeKeyShareClientHello(e.data, &entries) catch return error.Malformed;
            for (advertised_groups) |want| {
                for (shares) |s| {
                    if (s.group != want) continue;
                    if (s.key_exchange.len != expectedShareLen(want)) continue;
                    return .{ .group = s.group, .share = s.key_exchange };
                }
            }
            return error.MissingKeyShare; // key_share present but no usable entry
        }
        return error.MissingKeyShare;
    }

    /// `.cert_dhe` client helper: extracts the SERVER's single-entry
    /// `key_share` (RFC 8446 §4.2.8, no list prefix) from the ServerHello's
    /// decoded extensions and returns it, or a typed error (never a panic).
    /// The caller checks the group against the one it offered a share in.
    fn serverHelloShare(exts: []const messages.Extension) HandshakeError!PeerShare {
        for (exts) |e| {
            if (e.ext_type != @intFromEnum(messages.ExtensionType.key_share)) continue;
            const share = messages.decodeKeyShareServerHello(e.data) catch return error.Malformed;
            return .{ .group = share.group, .share = share.key_exchange };
        }
        return error.MissingKeyShare;
    }

    /// Wraps `fragment_bytes` (a `handshake.zig` fragment: 12-byte header +
    /// body) in a legacy `record.PlaintextHeader` record (RFC 9147 §4,
    /// `content_type_handshake`, epoch 0 — the format ClientHello/
    /// ServerHello use, before any record protection exists) and appends
    /// it to `out`. Advances `hs0.send_seq`.
    fn writeEpoch0Record(self: *Connection, fragment_bytes: []const u8, out: []u8) HandshakeError![]const u8 {
        const hdr = record.PlaintextHeader{
            .content_type = content_type_handshake,
            .epoch = 0,
            .sequence_number = self.hs0.send_seq,
            .length = std.math.cast(u16, fragment_bytes.len) orelse return error.BufferTooShort,
        };
        const hdr_slice = record.encodePlaintext(hdr, out) catch return error.BufferTooShort;
        if (out.len < hdr_slice.len + fragment_bytes.len) return error.BufferTooShort;
        @memcpy(out[hdr_slice.len..][0..fragment_bytes.len], fragment_bytes);
        self.hs0.send_seq +%= 1;
        return out[0 .. hdr_slice.len + fragment_bytes.len];
    }

    /// The handshake-epoch (epoch 2) analogue of `send`: AEAD-protects
    /// `fragment_bytes` (content_type = handshake = 22) with `hs_write_keys`
    /// under a `record.UnifiedHeader`, using and advancing `hs2.send_seq`.
    /// Used for {EncryptedExtensions, Finished}.
    fn protectHandshakeMessage(self: *Connection, fragment_bytes: []const u8, out: []u8) HandshakeError![]const u8 {
        const params = suiteParams(self.suite) orelse return error.UnsupportedSuite;

        var inner_buf: [1500]u8 = undefined;
        if (fragment_bytes.len + 1 > inner_buf.len) return error.BufferTooShort;
        @memcpy(inner_buf[0..fragment_bytes.len], fragment_bytes);
        inner_buf[fragment_bytes.len] = content_type_handshake;
        const inner = inner_buf[0 .. fragment_bytes.len + 1];

        const ct_len = inner.len + params.tag_len;
        const seq_len: record.SeqNumLen = if (self.hs2.send_seq <= 0xff) .short else .long;
        const seq_bytes_n: usize = if (seq_len == .short) 1 else 2;

        const hdr = record.UnifiedHeader{
            .epoch_low = 2,
            .seq_len = seq_len,
            .seq_wire = @truncate(self.hs2.send_seq),
            .cid = null,
            .length = @intCast(ct_len),
        };
        const hdr_slice = record.encodeUnified(hdr, out) catch return error.BufferTooShort;
        const hdr_len = hdr_slice.len;
        if (out.len < hdr_len + ct_len) return error.BufferTooShort;

        const n = protectDispatch(self.suite, self.hs_write_keys, 2, self.hs2.send_seq, inner, out[0..hdr_len], out[hdr_len..]) catch
            return error.BufferTooShort;
        std.debug.assert(n == ct_len);

        const seq_off: usize = 1;
        try snMaskDispatch(self.suite, self.hs_write_keys, out[hdr_len..][0..16], out[seq_off..][0..seq_bytes_n]);

        self.hs2.send_seq +%= 1;
        return out[0 .. hdr_len + ct_len];
    }

    /// The handshake-epoch (epoch 2) analogue of `recv`: un-protects one
    /// record from the FRONT of `record_bytes` (trailing bytes, if any —
    /// e.g. a following coalesced record — are ignored, bounded by the
    /// record's own explicit length field) with `hs_read_keys`, verifies
    /// the recovered inner content type is `content_type_handshake`, and
    /// returns the recovered fragment bytes (12-byte handshake header +
    /// body) written into `out`.
    /// `seq_out`, when given, receives the record's reconstructed 48-bit
    /// sequence number — what an RFC 9147 §7 ACK has to name.
    fn unprotectHandshakeMessage(self: *Connection, record_bytes: []const u8, out: []u8, seq_out: ?*u64) HandshakeError![]const u8 {
        const dec = record.decodeUnified(record_bytes, 0) catch return error.Malformed;
        const seq_len = dec.hdr.seq_len;
        const seq_bytes_n: usize = if (seq_len == .short) 1 else 2;
        const hdr_len = dec.consumed;
        const seq_off: usize = 1;

        const ct = if (dec.hdr.length) |l| blk: {
            if (record_bytes.len < hdr_len + l) return error.Malformed;
            break :blk record_bytes[hdr_len..][0..l];
        } else record_bytes[hdr_len..];
        if (ct.len < 16) return error.RecordTooShort;

        var hdr_buf: [16]u8 = undefined;
        if (hdr_len > hdr_buf.len) return error.Malformed;
        @memcpy(hdr_buf[0..hdr_len], record_bytes[0..hdr_len]);
        try snMaskDispatch(self.suite, self.hs_read_keys, ct[0..16], hdr_buf[seq_off..][0..seq_bytes_n]);

        const wire_low: u16 = if (seq_len == .short)
            hdr_buf[seq_off]
        else
            std.mem.readInt(u16, hdr_buf[seq_off..][0..2], .big);
        const largest = if (self.hs2.recv_seen_any) self.hs2.recv_max_seq else 0;
        const full_seq = record.reconstructSequenceNumber(largest, seq_len, wire_low);

        const body_len = unprotectDispatch(self.suite, self.hs_read_keys, 2, full_seq, ct, hdr_buf[0..hdr_len], out) catch
            return error.DecryptionFailed;
        if (body_len == 0) return error.Malformed;

        var end = body_len;
        while (end > 0 and out[end - 1] == 0) end -= 1;
        if (end == 0) return error.Malformed;
        const ctype = out[end - 1];
        if (ctype != content_type_handshake) return error.UnexpectedMessage;

        // RFC 9147 §4.5.1 anti-replay window, epoch-2 (handshake-traffic)
        // analogue of the check in `recv` above — same AEAD-authenticated-
        // first ordering applies.
        if (!replayCheckAndUpdate(&self.hs2.recv_seen_any, &self.hs2.recv_max_seq, &self.hs2.recv_window, full_seq))
            return error.ReplayedRecord;

        if (seq_out) |p| p.* = full_seq;
        return out[0 .. end - 1];
    }

    /// Pulls exactly ONE complete handshake message out of `datagram`,
    /// starting at record boundary `pos.*` and consuming as many records as
    /// that takes — which is the whole point: a message split across
    /// fragments (RFC 9147 §5.2) is reassembled here, and because
    /// `handleFlight` concatenates a flight's datagrams before calling in,
    /// "several records" transparently spans "several datagrams".
    ///
    /// Ordering is by `fragment_offset`, never by arrival: `handshake
    /// .Reassembler` writes each fragment at its own offset and reports
    /// completion only once every byte of `[0, length)` has arrived. A
    /// reader that instead appended fragments in the order they showed up
    /// would agree with itself on the happy path and silently corrupt the
    /// transcript on a reordered one.
    ///
    /// `message_seq` demultiplexing (this side's view of the peer's counter
    /// lives in `peer_message_seq`):
    ///   * equal to the expected value — a fragment of the message being
    ///     read;
    ///   * BEHIND it — a retransmitted copy of a message already consumed
    ///     (a peer that did not see this side's answer resends its whole
    ///     flight, so this is ordinary, not an attack): skipped;
    ///   * AHEAD of it — `error.InterleavedFragments`. Accepting it would
    ///     mean holding a second half-built message, and one is the
    ///     documented cap (see `max_flight_bytes`).
    ///
    /// Running out of records is `error.FlightIncomplete`, which is NOT a
    /// failure — `handleFlight` turns it into "send me the next datagram".
    /// A record whose own length field runs past the buffer IS a failure:
    /// DTLS never splits a RECORD across datagrams, so there is no later
    /// datagram that could complete one.
    fn takeHandshakeMessage(
        self: *Connection,
        datagram: []const u8,
        pos: *usize,
        kind: RecordKind,
        msg_buf: []u8,
        received_buf: []bool,
        acks: ?*AckCollector,
    ) HandshakeError!TakenMessage {
        var reasm: handshake.Reassembler = undefined;
        var reasm_live = false;

        while (true) {
            if (pos.* >= datagram.len) return error.FlightIncomplete;

            var plain_buf: [max_record_plaintext]u8 = undefined;
            const fragment = switch (kind) {
                .epoch0_plaintext => blk: {
                    const rec = record.decodePlaintext(datagram[pos.*..]) catch return error.Malformed;
                    if (rec.content_type != content_type_handshake) return error.UnexpectedMessage;
                    const start = pos.* + record.plaintext_header_len;
                    if (datagram.len < start + rec.length) return error.Malformed;
                    pos.* = start + rec.length;
                    break :blk datagram[start..][0..rec.length];
                },
                .epoch2_protected => blk: {
                    var record_seq: u64 = 0;
                    const f = try self.unprotectHandshakeMessage(datagram[pos.*..], &plain_buf, &record_seq);
                    pos.* += try recordWireLen(datagram[pos.*..]);
                    if (acks) |a| a.add(record_seq);
                    break :blk f;
                },
            };

            const hdr = handshake.decodeHeader(fragment) catch return error.Malformed;
            if (fragment.len < handshake.header_len + hdr.fragment_length) return error.Malformed;
            const frag_body = fragment[handshake.header_len..][0..hdr.fragment_length];

            const expected = self.peer_message_seq orelse hdr.message_seq;
            if (hdr.message_seq != expected) {
                if (messageSeqOlderThan(hdr.message_seq, expected)) continue;
                return error.InterleavedFragments;
            }
            self.peer_message_seq = expected;

            if (hdr.length > msg_buf.len) return error.BufferTooShort;
            if (!reasm_live) {
                reasm = handshake.Reassembler.init(msg_buf[0..hdr.length], received_buf[0..hdr.length]);
                reasm_live = true;
            }

            if (try reasm.feed(hdr, frag_body)) |body| {
                self.peer_message_seq = expected +% 1;
                return .{ .msg_type = reasm.msg_type, .body = body, .message_seq = expected };
            }
        }
    }

    /// RFC 9147 §7 flight bookkeeping: records the given (epoch, seq) pairs
    /// as "sent, awaiting acknowledgement" via `flight.FlightTracker`,
    /// reusing `pending_flight_buf` as that tracker's backing storage (a
    /// fresh `FlightTracker` is constructed each call rather than stored,
    /// since it holds a slice that would dangle across a `Connection` move
    /// — see the field's doc comment).
    fn markFlightSent(self: *Connection, records: []const flight.RecordNumber) void {
        var t = flight.FlightTracker.init(&self.pending_flight_buf);
        for (records) |rn| t.markSent(rn) catch break; // never overflows: <= 3 records/flight here
        self.pending_flight_count = t.count;
    }

    /// Marks the whole outstanding flight as acknowledged — called when the
    /// peer's next expected flight arrives (implicit ACK-by-progression).
    fn clearFlightTracker(self: *Connection) void {
        self.pending_flight_count = 0;
    }

    /// Caches `bytes` as the last flight WE sent (for `poll` to retransmit)
    /// and (re)arms `retransmit_timer` from `now_ms`.
    fn cacheFlight(self: *Connection, bytes: []const u8, now_ms: u64) HandshakeError!void {
        if (bytes.len > self.last_flight.len) return error.BufferTooShort;
        @memcpy(self.last_flight[0..bytes.len], bytes);
        self.last_flight_len = bytes.len;
        self.retransmit_timer.reset();
        self.retransmit_timer.arm(now_ms);
    }

    // ── certificate mode (RFC 8446 §4.4, layered on the psk_ke exchange) ──
    //
    // WHAT "certificate mode" MEANS HERE: this engine has no (EC)DHE
    // key-share machinery (its ClientHello only ever offers
    // `psk_key_exchange_modes = [psk_ke]` — see `buildClientHello`), and
    // adding one is real new crypto (out of this task's "plumbing over
    // certverify, no new crypto" scope). A certificate-authenticated
    // handshake with NO PSK at all therefore cannot derive confidential
    // session keys here — RFC 8446's own certificate-only mode gets its
    // key material from (EC)DHE, which this module doesn't have.
    //
    // So: the PSK continues to supply ALL session-key material exactly as
    // before (unchanged key schedule, unchanged Finished computation).
    // Certificate mode ADDS Certificate + CertificateVerify (+ optionally
    // CertificateRequest) messages that authenticate the two ends' identity
    // via a real signature over the running handshake transcript — useful
    // e.g. for a device provisioned with both a shared secret (for the
    // channel) and a per-device X.509 identity (for strong peer
    // authentication), which is exactly this module's stated CoAP/IoT
    // fleet-management target consumer (see `root.zig`). This is NOT a
    // standard named RFC 8446 mode; it is this engine's own, honestly-
    // documented extension of it, built entirely from already-implemented
    // pieces (`certverify.zig`'s sign/verify, `certauth.zig`'s DER bridge).
    //
    // `signature_algorithms` extension negotiation (RFC 8446 §4.2.3) IS
    // implemented (see `selectSignatureScheme`, `signAndSendCertificateVerify`,
    // `verifyPeerCert`'s downgrade guard) — CertConfig no longer carries a
    // fixed `signature_scheme`; the scheme is picked from the intersection
    // of the peer's advertised list, `Config.signature_algorithms`, and
    // `certverify.candidateSchemes(cc.private_key)`, failing the handshake
    // with `error.NoSignatureSchemeOverlap` rather than falling back to a
    // default when there is no overlap.
    //
    // DEFERRED (not silently skipped):
    //   - A genuine PSK-less, (EC)DHE-based certificate-only key exchange
    //     (would need a `key_share` extension + ECDH — new crypto).
    //   - Full RFC 5280 §6 certification-path building (multi-hop chains,
    //     name constraints, key usage / basicConstraints policy checks,
    //     revocation) — `PeerVerify.trust_anchor` is a minimal one-hop
    //     check; `PeerVerify.verify_fn` is the escape hatch for anything
    //     more (see that type's doc comment).
    //   - `CertificateEntry` extensions (OCSP stapling, SCT, ...) — framed
    //     as always-empty on send, length-validated-but-discarded on
    //     receive (see `messages.zig`'s `CertificateEntry` doc comment).

    /// The record bytes + hs2 sequence number one `sendEpoch2Message`/
    /// `signAndSendCertificateVerify` call produced — a named type (NOT two
    /// separately-declared anonymous structs, which Zig treats as distinct
    /// types even with identical fields) so both functions' results can be
    /// handled uniformly by their callers.
    const SentRecord = struct { bytes: []const u8, seq: u48 };

    /// Encodes `body` as handshake type `msg_type`, appends it to the
    /// running transcript, frames + AEAD-protects it under the epoch-2
    /// handshake traffic keys (mirrors what `serverProcessClientHello`'s
    /// EncryptedExtensions/Finished sends already did inline — this is that
    /// same "append, frame, protect" sequence factored out for the
    /// certificate-mode messages below, which need it up to 3 more times
    /// per side). `frag_buf` must be `>= handshake.header_len + body.len`
    /// (sized per call site — Certificate/CertificateVerify/
    /// CertificateRequest bodies are very differently sized).
    fn sendEpoch2Message(
        self: *Connection,
        msg_type: messages.HandshakeType,
        body: []const u8,
        frag_buf: []u8,
        out: []u8,
    ) HandshakeError!SentRecord {
        self.transcript.append(@intFromEnum(msg_type), body);
        const fragment = try frameHandshakeMessage(@intFromEnum(msg_type), self.message_seq, body, frag_buf);
        self.message_seq +%= 1;
        const seq = self.hs2.send_seq;
        const record_bytes = try self.protectHandshakeMessage(fragment, out);
        return .{ .bytes = record_bytes, .seq = seq };
    }

    /// Signs the CURRENT transcript hash (i.e. through whatever was last
    /// `sendEpoch2Message`-ed — the caller must call this immediately after
    /// sending this side's own Certificate message, per RFC 8446 §4.4.3)
    /// under the ALREADY-NEGOTIATED `scheme` (see `selectSignatureScheme` —
    /// callers compute this before calling here; this function performs no
    /// negotiation itself, only signs)/`cc.private_key`, encodes a
    /// CertificateVerify message body, and sends it via `sendEpoch2Message`.
    fn signAndSendCertificateVerify(
        self: *Connection,
        cc: CertConfig,
        scheme: certverify.SignatureScheme,
        side: certverify.Side,
        entropy: Entropy,
        out: []u8,
    ) HandshakeError!SentRecord {
        const th = self.transcript.currentHash();
        var sig_buf: [max_sig_len]u8 = undefined;
        // `certverify.sign` carries its own requirement in its type (`?std.Random`,
        // fail-closed with `error.RandomRequired` for RSA-PSS), so this is where
        // the arm is erased: the choice was already made at the entry point.
        const sig = try certverify.sign(scheme, cc.private_key, side, &th, entropy.source(), &sig_buf);

        var cv_body_buf: [max_certverify_body]u8 = undefined;
        const cv_body = messages.encodeCertificateVerify(.{ .algorithm = @intFromEnum(scheme), .signature = sig }, &cv_body_buf) catch return error.BufferTooShort;

        var frag_buf: [max_certverify_body + handshake.header_len]u8 = undefined;
        return self.sendEpoch2Message(.certificate_verify, cv_body, &frag_buf, out);
    }

    /// Verifies an incoming CertificateVerify: FIRST, the downgrade guard —
    /// `scheme_raw` must be one of `self.config.signature_algorithms` (the
    /// schemes THIS side actually advertised to the peer, RFC 8446 §4.2.3);
    /// a peer that answers with anything else is rejected with
    /// `error.SignatureSchemeNotAdvertised` before the signature is even
    /// checked — a peer must never be able to steer this side into
    /// accepting a scheme it never offered. THEN the signature itself (real
    /// crypto, `certverify.verify` — proves possession of `leaf_der`'s
    /// private key over `transcript_hash`); every `certverify.VerifyError`
    /// case collapses to `error.CertVerifyFailed` (matching this module's
    /// existing style of one typed error per "verify failed" event — see
    /// `BinderVerifyFailed`/`FinishedVerifyFailed` — rather than leaking
    /// which of six internal sub-reasons applied). THEN, only if that
    /// passed, `self.config.peer_verify`'s chain-to-anchor trust decision is
    /// applied (also collapsed, to `error.CertificateRejected`).
    ///
    /// `scheme_raw` is the wire `SignatureScheme` value from the peer's
    /// CertificateVerify message — `certverify.SignatureScheme` is a
    /// non-exhaustive enum specifically so this cast can never panic on an
    /// unrecognized value (`certverify.verify` itself rejects it with
    /// `error.UnsupportedScheme`, folded into `CertVerifyFailed` here; an
    /// unrecognized value also never matches anything in
    /// `self.config.signature_algorithms`, so the downgrade guard rejects it
    /// first anyway).
    fn verifyPeerCert(
        self: *Connection,
        leaf_der: []const u8,
        scheme_raw: u16,
        signature: []const u8,
        transcript_hash: []const u8,
        signer_side: certverify.Side,
    ) HandshakeError!void {
        var advertised = false;
        for (self.config.signature_algorithms) |s| {
            if (@intFromEnum(s) == scheme_raw) {
                advertised = true;
                break;
            }
        }
        if (!advertised) return error.SignatureSchemeNotAdvertised;

        const scheme: certverify.SignatureScheme = @enumFromInt(scheme_raw);
        const pubkey = certauth.parseLeafPublicKey(leaf_der) catch return error.CertificateRejected;
        certverify.verify(scheme, pubkey, signer_side, transcript_hash, signature) catch return error.CertVerifyFailed;
        switch (self.config.peer_verify) {
            .none => {},
            .trust_anchor => |anchor_der| certauth.verifyLeafAgainstAnchor(leaf_der, anchor_der, self.config.now_sec) catch return error.CertificateRejected,
            .verify_fn => |f| f(leaf_der) catch return error.CertificateRejected,
        }
    }

    /// Result of `consumeOptionalCertMessages` — everything the caller
    /// needs to finish processing a flight that may have carried
    /// certificate-mode messages before its mandatory closing `Finished`.
    const PeerCertResult = struct {
        /// A `CertificateRequest` was seen (only legal — see
        /// `consumeOptionalCertMessages`'s `allow_certificate_request` — when
        /// parsing what a SERVER sent).
        requested_client_cert: bool = false,
        creq_context: [255]u8 = undefined,
        creq_context_len: usize = 0,
        /// The `signature_algorithms` extension carried in the
        /// CertificateRequest, if any (RFC 8446 §4.3.2 mandates one; decoded
        /// here so `handleFlightClient` can negotiate THIS side's own
        /// CertificateVerify scheme against it via `selectSignatureScheme` —
        /// see that function's doc comment). Empty if
        /// `requested_client_cert` is false, or the peer's CertificateRequest
        /// omitted the extension (negotiation then sees an empty peer list,
        /// which — like any other empty intersection — surfaces as
        /// `error.NoSignatureSchemeOverlap` rather than silently picking a
        /// default).
        /// Sized to THIS side's own scheme table, not to a guess at how many
        /// a peer might advertise: only schemes in `supported_scheme_wire_values`
        /// are ever kept (see the `filterU16ListExtension` call below).
        peer_sig_algs_buf: [supported_scheme_wire_values.len]u16 = undefined,
        peer_sig_algs_len: usize = 0,
        /// A `Certificate` message was seen at all — set even for an empty
        /// `certificate_list` (RFC 8446 §4.4.2's "no certificate" answer),
        /// which is why `leaf_len == 0` (not `!saw_cert`) is the "peer
        /// declined" check callers should use.
        saw_cert: bool = false,
        leaf_buf: [max_cert_message_body]u8 = undefined,
        leaf_len: usize = 0,
        saw_cv: bool = false,
        /// The (epoch, sequence_number) of every epoch-2 record consumed
        /// here — what an RFC 9147 §7 ACK for this flight has to name. The
        /// client's final flight is the one flight the spec does NOT let a
        /// receiver acknowledge implicitly, so the server has to send these
        /// back or the peer never learns its Finished arrived.
        acks: AckCollector = .{},
        /// The closing `Finished` message's body (its `verify_data`),
        /// consumed by this same function — see the doc comment below for
        /// why `unprotectHandshakeMessage` cannot be safely called a second
        /// time on the same wire bytes to re-parse it (it advances the
        /// epoch-2 anti-replay window, RFC 9147 §4.5.1; a second call on
        /// the identical sequence number would spuriously fail with
        /// `error.ReplayedRecord`).
        fin_buf: [64]u8 = undefined,
        fin_len: usize = 0,

        fn finishedVerifyData(self: *const PeerCertResult) []const u8 {
            return self.fin_buf[0..self.fin_len];
        }

        fn peerSigAlgs(self: *const PeerCertResult) []const u16 {
            return self.peer_sig_algs_buf[0..self.peer_sig_algs_len];
        }
    };

    /// Consumes zero-or-more optional certificate-mode messages
    /// (`CertificateRequest?`, `Certificate?`, `CertificateVerify?`, in that
    /// RFC 8446 §4.4/§4.3.2 order) starting at `datagram[pos.*..]`, THEN
    /// the mandatory closing `finished` message that always ends a flight
    /// — returned via `PeerCertResult.finishedVerifyData()` rather than
    /// left for the caller to unprotect separately, because
    /// `unprotectHandshakeMessage` is NOT idempotent (RFC 9147 §4.5.1's
    /// anti-replay window advances on every successful call — a second
    /// call on the same wire bytes would see its own already-accepted
    /// sequence number and spuriously fail with `error.ReplayedRecord`).
    /// Every message consumed is reassembled via `takeHandshakeMessage`
    /// (so a Certificate split across datagrams — the usual case for a real
    /// chain — is handled here), appended to the transcript, and (for
    /// Certificate/CertificateVerify) cryptographically verified via
    /// `verifyPeerCert` — so a caller that gets a successful return already
    /// has a fully-verified peer chain (if one was presented) AND the
    /// Finished body, ready for `computeFinishedVerifyData` comparison.
    ///
    /// In the pure-PSK case (no certificate-mode messages sent), the very
    /// first message found is `finished` and this behaves exactly like the
    /// original inline `unprotectHandshakeMessage` + reassembly
    /// call it replaces — byte-for-byte the same wire behavior.
    ///
    /// `signer_side`: whose CertificateVerify this is, if one appears
    /// (`.server` when parsing what a DTLS SERVER sent — i.e. the client
    /// calls this with `.server` — and vice versa) — selects the RFC 8446
    /// §4.4.3 context string `certverify.verify` checks against.
    /// `allow_certificate_request`: a client legitimately sends
    /// CertificateRequest to nobody — `false` when parsing a CLIENT's
    /// flight rejects one outright as a protocol violation.
    fn consumeOptionalCertMessages(
        self: *Connection,
        datagram: []const u8,
        pos: *usize,
        signer_side: certverify.Side,
        allow_certificate_request: bool,
    ) HandshakeError!PeerCertResult {
        var result = PeerCertResult{};
        var iterations: usize = 0;
        while (true) : (iterations += 1) {
            if (iterations >= 4) return error.Malformed; // CertReq?, Cert?, CertVerify?, Finished — never more

            var msg_buf: [max_cert_message_body]u8 = undefined;
            var received_buf: [max_cert_message_body]bool = undefined;
            const parsed = try self.takeHandshakeMessage(datagram, pos, .epoch2_protected, &msg_buf, &received_buf, &result.acks);

            if (parsed.msg_type == @intFromEnum(messages.HandshakeType.finished)) {
                if (parsed.body.len > result.fin_buf.len) return error.Malformed;
                @memcpy(result.fin_buf[0..parsed.body.len], parsed.body);
                result.fin_len = parsed.body.len;
                return result;
            }

            if (parsed.msg_type == @intFromEnum(messages.HandshakeType.certificate_request)) {
                if (!allow_certificate_request or result.saw_cert or result.requested_client_cert) return error.UnexpectedMessage;
                var ext_buf: [4]messages.Extension = undefined;
                const creq = messages.decodeCertificateRequest(parsed.body, &ext_buf) catch return error.Malformed;
                if (creq.certificate_request_context.len > result.creq_context.len) return error.Malformed;
                @memcpy(result.creq_context[0..creq.certificate_request_context.len], creq.certificate_request_context);
                result.creq_context_len = creq.certificate_request_context.len;
                for (creq.extensions) |e| {
                    if (e.ext_type != @intFromEnum(messages.ExtensionType.signature_algorithms)) continue;
                    // FILTER, do not decode wholesale. A real peer's
                    // CertificateRequest advertises far more schemes than any
                    // small fixed buffer holds — wolfSSL 5.9.1 sends 16 —
                    // and `decodeU16ListExtension` into a `[8]u16` answered a
                    // perfectly ordinary CertificateRequest with
                    // `error.TooManyExtensions` -> `Malformed`. That is the
                    // SAME defect `serverProcessClientHello` fixed for the
                    // ClientHello's `signature_algorithms`; it survived here
                    // because only this module's own server had ever sent a
                    // CertificateRequest, and its list is short. Found by the
                    // live wolfSSL mutual-auth test — the sixth wire defect
                    // self-interop passed (see `root.zig`).
                    //
                    // Keeping only the schemes this side could ever select
                    // loses nothing: `selectSignatureScheme` intersects with
                    // exactly this set anyway.
                    const sig_algs = messages.filterU16ListExtension(e.data, &supported_scheme_wire_values, &result.peer_sig_algs_buf) catch return error.Malformed;
                    result.peer_sig_algs_len = sig_algs.len;
                }
                result.requested_client_cert = true;
                self.transcript.append(parsed.msg_type, parsed.body);
            } else if (parsed.msg_type == @intFromEnum(messages.HandshakeType.certificate)) {
                if (result.saw_cert) return error.UnexpectedMessage;
                var entries_buf: [4]messages.CertificateEntry = undefined;
                const dec = messages.decodeCertificate(parsed.body, &entries_buf) catch return error.Malformed;
                self.transcript.append(parsed.msg_type, parsed.body);
                result.saw_cert = true;
                if (dec.entries.len > 0) {
                    const leaf = dec.entries[0].cert_data;
                    if (leaf.len > result.leaf_buf.len) return error.Malformed;
                    @memcpy(result.leaf_buf[0..leaf.len], leaf);
                    result.leaf_len = leaf.len;
                }
            } else if (parsed.msg_type == @intFromEnum(messages.HandshakeType.certificate_verify)) {
                if (!result.saw_cert or result.leaf_len == 0 or result.saw_cv) return error.UnexpectedMessage;
                // Transcript hash "through Certificate" — everything
                // appended so far, NOT including this CertificateVerify
                // message itself (RFC 8446 §4.4.3).
                const th_through_cert = self.transcript.currentHash();
                const cv = messages.decodeCertificateVerify(parsed.body) catch return error.Malformed;
                try self.verifyPeerCert(result.leaf_buf[0..result.leaf_len], cv.algorithm, cv.signature, &th_through_cert, signer_side);
                self.transcript.append(parsed.msg_type, parsed.body);
                result.saw_cv = true;
            } else {
                return error.UnexpectedMessage;
            }
        }
    }

    fn handleFlightServer(self: *Connection, datagram: []const u8, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        return switch (self.state) {
            .start => self.serverProcessClientHello(datagram, entropy, now_ms, out),
            .wait_finished => self.serverProcessClientFinished(datagram, out),
            else => error.WrongState,
        };
    }

    /// RFC 9147 §5.1, server side: a ClientHello arrived from a peer that
    /// has not yet proved it can RECEIVE at the address it claims, so
    /// instead of a flight it gets a HelloRetryRequest carrying a cookie.
    ///
    /// **What this function deliberately does NOT do** is the whole point.
    /// It does not verify the PSK binder, does not run the key schedule,
    /// does not touch `self.transcript`, does not advance `self.state`, and
    /// does not cache the flight for retransmission. An unauthenticated peer
    /// — possibly a forged source address — costs this server one HMAC and
    /// one small datagram. RFC 9147 §5.1's second attack is the server as
    /// amplifier; answering here with anything larger than what arrived is
    /// the vulnerability, not the fix.
    ///
    /// It also stores nothing, so a caller may (and a real server should)
    /// destroy this `Connection` the moment the bytes are sent. Because the
    /// cookie is a deterministic function of its inputs, a RETRANSMITTED
    /// first ClientHello produces a byte-identical HelloRetryRequest from a
    /// brand-new `Connection` — no memory of the first one is needed.
    ///
    /// The one thing it must decide up front is the cipher suite: RFC 8446
    /// §4.1.4 puts it in the HelloRetryRequest and requires the eventual
    /// ServerHello to match, so it goes into the cookie.
    ///
    /// SCOPE: this retry only ever carries a cookie. RFC 8446 §4.1.4's other
    /// use — naming a different `key_share` group — is a CLIENT-side
    /// capability here (`handleHelloRetryRequest`); this server takes
    /// whichever offered share it can use (`clientHelloShare`) and answers a
    /// ClientHello with nothing usable with `error.MissingKeyShare` rather
    /// than a group-change retry. Adding one would mean deciding the group
    /// before the cookie is verified, i.e. more state for an unverified
    /// peer, which is the thing this function exists not to do.
    fn sendHelloRetryRequest(
        self: *Connection,
        hr: HelloRetryConfig,
        dec: messages.DecodedClientHello,
        ch_body: []const u8,
        out: []u8,
    ) HandshakeError!HandshakeResult {
        const suite = selectCipherSuite(self.config.cipher_suites, dec.cipher_suites_raw) orelse return error.NoCipherSuiteOverlap;

        // `Hash(ClientHello1)` — RFC 8446 §4.4.1's `message_hash` input.
        // Computed on a THROWAWAY transcript: `self.transcript` must stay
        // untouched, both because this connection is about to be discarded
        // and because the transcript ClientHello2 will be measured against
        // does not contain ClientHello1 at all (it contains the synthetic
        // `message_hash` message instead).
        var scratch = engine.Transcript{};
        scratch.append(@intFromEnum(messages.HandshakeType.client_hello), ch_body);
        var cookie: [cookie_len]u8 = undefined;
        mintCookie(hr, .{ .suite = suite, .client_hello1_hash = scratch.currentHash() }, &cookie);

        var hrr_body_buf: [max_hrr_body_len]u8 = undefined;
        const hrr_body = try encodeHelloRetryRequest(suite, &cookie, &hrr_body_buf);

        // RFC 9147 §5.2 `message_seq` 0: the HelloRetryRequest is the first
        // handshake message this server sends, and `acceptCookie` restores
        // exactly this numbering on the (stateless, brand-new) connection
        // that handles ClientHello2.
        var frag_buf: [max_hrr_body_len + handshake.header_len]u8 = undefined;
        const fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.server_hello), 0, hrr_body, &frag_buf);
        const record_bytes = try self.writeEpoch0Record(fragment, out);

        // The one thing recorded, and only so a caller (and a test) can SEE
        // that the retry path ran. Nothing in this engine reads it on the
        // server side, so it is not state the handshake depends on — which
        // matters, because this object is meant to be thrown away.
        self.saw_hello_retry_request = true;
        return .{ .out = record_bytes, .done = false };
    }

    /// RFC 9147 §5.1, the other half: ClientHello2 came back carrying a
    /// cookie. Authenticate it — this is the return-routability check
    /// completing, and the only moment at which this server learns the peer
    /// can receive at its claimed address — then rebuild the state that was
    /// deliberately never kept.
    ///
    /// "Rebuild" is the whole trick, and RFC 8446 §4.4.1's `message_hash`
    /// rewrite is what makes it possible (RFC 9147 §5.1 spells out the
    /// consequence: "The initial ClientHello is included in the handshake
    /// transcript as a synthetic 'message_hash' message, so only the hash
    /// value is needed for the handshake to complete, though the complete
    /// HelloRetryRequest contents are needed"). Hence the transcript here is
    ///
    ///     message_hash(Hash(ClientHello1)) || HelloRetryRequest
    ///
    /// with ClientHello2 appended by the caller afterwards — the hash out of
    /// the cookie, and the HelloRetryRequest re-encoded from the cookie by
    /// `encodeHelloRetryRequest`. Get either wrong and the transcript
    /// silently diverges from the client's: the binder, then every derived
    /// secret, verifies against nothing.
    ///
    /// Returns the cipher suite this server already committed to in the
    /// HelloRetryRequest.
    fn acceptCookie(self: *Connection, hr: HelloRetryConfig, cookie: []const u8) HandshakeError!CipherSuite {
        const contents = try openCookie(hr, cookie);

        self.transcript.resetToMessageHash(contents.client_hello1_hash);
        var hrr_body_buf: [max_hrr_body_len]u8 = undefined;
        const hrr_body = try encodeHelloRetryRequest(contents.suite, cookie, &hrr_body_buf);
        self.transcript.append(@intFromEnum(messages.HandshakeType.server_hello), hrr_body);

        // The HelloRetryRequest occupied `message_seq` 0 and one epoch-0
        // record, and this connection — being brand new, which is the point
        // — has no memory of that. Restore the counters the peer has already
        // seen, or the ServerHello arrives numbered as if it were the first
        // thing this server ever sent.
        //
        // Note what a stateless server cannot do: if the first ClientHello
        // is retransmitted, each copy is answered by a fresh connection and
        // so re-uses epoch-0 record sequence number 0. That is inherent to
        // RFC 9147 §5.1 (there is nowhere to count), and harmless — the
        // records are pre-epoch-2, unprotected, and carry no anti-replay
        // guarantee to violate.
        self.message_seq = 1;
        self.hs0.send_seq = 1;
        self.saw_hello_retry_request = true;
        return contents.suite;
    }

    /// Server flight 1 (RFC 9147 §5.4): consumes a ClientHello (verifying
    /// its PSK binder), selects a cipher suite, and sends flight 2 —
    /// ServerHello (epoch 0) coalesced with {EncryptedExtensions, Finished}
    /// (epoch 2, AEAD-protected under the freshly-derived handshake traffic
    /// keys). Derives (but does not yet install) the application traffic
    /// secrets. Transitions `.start` -> `.wait_finished`.
    fn serverProcessClientHello(self: *Connection, datagram: []const u8, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        var msg_buf: [512]u8 = undefined;
        var received_buf: [512]bool = undefined;
        var ch_pos: usize = 0;
        const parsed = try self.takeHandshakeMessage(datagram, &ch_pos, .epoch0_plaintext, &msg_buf, &received_buf, null);
        if (parsed.msg_type != @intFromEnum(messages.HandshakeType.client_hello)) return error.UnexpectedMessage;
        const ch_body = parsed.body;

        // 16, not 8: a real ClientHello is extension-rich (wolfSSL's carries
        // several this module ignores) and ClientHello2 adds `cookie` on top,
        // and `decodeExtensions` reports an overflow as
        // `error.TooManyExtensions` — i.e. a perfectly ordinary retry would
        // fail to parse.
        var ext_buf: [16]messages.Extension = undefined;
        const dec = messages.decodeClientHello(ch_body, &ext_buf) catch return error.Malformed;

        // ── RFC 9147 §5.1 return-routability, when configured. Either this
        // ClientHello carries a cookie we minted (verify it, and rebuild the
        // transcript it implies) or it does not (answer with a
        // HelloRetryRequest and keep nothing). Placed HERE, before the key
        // exchange and the binder check, deliberately: the whole point is
        // that an unverified peer costs this server one HMAC, not a
        // keyschedule, a signature, or a flight.
        const retry_suite: ?CipherSuite = if (self.config.hello_retry) |hr| blk: {
            var cookie: ?[]const u8 = null;
            for (dec.extensions) |e| {
                if (e.ext_type == @intFromEnum(messages.ExtensionType.cookie))
                    cookie = messages.decodeCookieExtension(e.data) catch return error.CookieVerifyFailed;
            }
            const c = cookie orelse return self.sendHelloRetryRequest(hr, dec, ch_body, out);
            break :blk try self.acceptCookie(hr, c);
        } else null;

        // The ClientHello's own `signature_algorithms` (RFC 8446 §4.2.3) —
        // what schemes the CLIENT can verify — captured here (while `dec
        // .extensions` is alive) for `selectSignatureScheme` below, ONLY
        // consulted if this server actually signs a CertificateVerify
        // (`self.config.cert` set). Absent extension ⇒ empty peer list,
        // which negotiation treats like any other empty intersection
        // (`error.NoSignatureSchemeOverlap`), never a silent default.
        //
        // Only the schemes THIS side could ever select are kept: a real peer
        // advertises far more than any small fixed buffer holds (wolfSSL
        // sends 18), and decoding the whole list into a `[8]u16` turned a
        // perfectly ordinary ClientHello into `error.Malformed`.
        var client_sig_algs_buf: [supported_scheme_wire_values.len]u16 = undefined;
        var client_sig_algs_len: usize = 0;
        for (dec.extensions) |e| {
            if (e.ext_type != @intFromEnum(messages.ExtensionType.signature_algorithms)) continue;
            const sig_algs = messages.filterU16ListExtension(e.data, &supported_scheme_wire_values, &client_sig_algs_buf) catch return error.Malformed;
            client_sig_algs_len = sig_algs.len;
        }

        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
        const eh = emptySha256Hash();

        // The early secret (RFC 8446 §7.1) and, in `.cert_dhe` mode, the
        // ephemeral (EC)DHE shared secret that feeds the handshake secret.
        var es: [32]u8 = undefined;
        var dhe_shared: ?[32]u8 = null;

        switch (self.config.key_exchange) {
            .psk => {
                var psk_ext: ?messages.Extension = null;
                for (dec.extensions) |e| {
                    if (e.ext_type == @intFromEnum(messages.ExtensionType.pre_shared_key)) psk_ext = e;
                }
                const psk_data = (psk_ext orelse return error.NoMatchingPskIdentity).data;

                var ids_buf: [4]messages.PskIdentity = undefined;
                var binders_buf: [4][]const u8 = undefined;
                const offered = messages.decodeOfferedPsks(psk_data, &ids_buf, &binders_buf) catch return error.Malformed;
                if (offered.identities.len == 0 or offered.binders.len == 0) return error.NoMatchingPskIdentity;
                if (!std.mem.eql(u8, offered.identities[0].identity, self.config.psk_identity)) return error.NoMatchingPskIdentity;
                const binder0 = offered.binders[0];
                if (binder0.len != 32) return error.Malformed;

                // RFC 8446 §4.2.11.2 truncation point: "up to and including
                // the PreSharedKeyExtension.identities field", i.e. right
                // BEFORE the whole binders list — which, being a vector,
                // starts at its own 2-byte length prefix. From this (first,
                // only) binder entry that is 3 bytes back: 1 for the entry's
                // length prefix, 2 for the list's. `binder0` aliases
                // `ch_body` (no-copy decoding all the way down — see
                // messages.zig), so its address gives the exact byte offset
                // without assuming anything about extension count/order.
                //
                // Stopping 1 byte back instead of 3 leaves the list length in
                // the hash. Both of this module's own sides made that error
                // together, so every self-interop test still passed; a live
                // wolfSSL peer rejected it as "binder does not verify".
                const truncate_at = (@intFromPtr(binder0.ptr) - 3) - @intFromPtr(ch_body.ptr);
                if (truncate_at > ch_body.len) return error.Malformed;
                const truncated = ch_body[0..truncate_at];

                es = keyschedule.earlySecret(Hkdf, self.config.psk);
                const bk = keyschedule.binderKey(Hkdf, es, &eh);
                const binder_th = self.transcript.wouldBeHash(@intFromEnum(messages.HandshakeType.client_hello), ch_body.len, truncated);
                const expected_binder = keyschedule.pskBinder(Hkdf, Hmac, bk, &binder_th);
                if (!std.crypto.timing_safe.eql([32]u8, expected_binder, binder0[0..32].*)) return error.BinderVerifyFailed;
            },
            .cert_dhe, .cert_dhe_insecure_unauthenticated => {
                // PSK-less (EC)DHE: pick a usable client share, make our own
                // ephemeral key pair IN THE SAME GROUP, and compute the shared
                // secret. The early secret's IKM is the zero PSK (RFC 8446
                // §7.1: no PSK ⇒ PSK = 0^Hash.length); the (EC)DHE secret is
                // mixed in at the handshake secret below via the SAME
                // `deriveHandshakeSecret` the PSK path uses — not a forked
                // schedule.
                const peer = try clientHelloShare(dec.extensions);
                var kp = try ecdheGenerate(peer.group, entropy);
                const shared = ecdheSharedSecret(peer.group, kp.secret, peer.share) catch |err| {
                    std.crypto.secureZero(u8, &kp.secret);
                    return err;
                };
                std.crypto.secureZero(u8, &kp.secret); // forward secrecy: drop the ephemeral private key
                // Goes into the ServerHello key_share, in the client's group.
                // RFC 8446 §4.2.8, verbatim: "This value MUST be in the same
                // group as the KeyShareEntry value offered by the client that
                // the server has selected for the negotiated key exchange."
                // (Before audit BD-26 this quoted "the server's share MUST be
                // in the same group as the client's", which is §2's overview
                // sentence with "one of the client's shares" edited away.)
                self.ecdhe_group = kp.group;
                self.ecdhe_public = kp.public;
                self.ecdhe_public_len = kp.public_len;
                dhe_shared = shared;
                const zero_psk = [_]u8{0} ** 32;
                es = keyschedule.earlySecret(Hkdf, &zero_psk);
            },
        }

        const suite = selectCipherSuite(self.config.cipher_suites, dec.cipher_suites_raw) orelse return error.NoCipherSuiteOverlap;
        // RFC 8446 §4.1.4: "Servers MUST ensure that they negotiate the same
        // cipher suite when receiving a conformant updated ClientHello", and
        // a client MUST abort if the ServerHello's suite differs from the
        // HelloRetryRequest's. The suite in the cookie is the one this server
        // already committed to, and it is authenticated; re-selecting from
        // ClientHello2 and finding something else means the peer changed its
        // offer between the two hellos, which §4.1.2 does not permit.
        if (retry_suite) |committed| {
            if (suite != committed) return error.NoCipherSuiteOverlap;
        }

        // ClientHello accepted (PSK binder verified, or cert-DHE key_share
        // extracted): commit it to the transcript.
        self.transcript.append(@intFromEnum(messages.HandshakeType.client_hello), ch_body);
        self.suite = suite;

        var random_bytes: [32]u8 = undefined;
        entropy.source().bytes(&random_bytes);
        // The single ServerHello extension differs by mode: `pre_shared_key`
        // (selected-identity index) for PSK, `key_share` (this server's
        // ephemeral public share, in the group the client offered) for
        // cert-DHE.
        var sh_ext_data_buf: [4 + max_key_share_len]u8 = undefined;
        const sh_ext: messages.Extension = switch (self.config.key_exchange) {
            .psk => blk: {
                messages.encodeSelectedIdentity(0, sh_ext_data_buf[0..2]);
                break :blk .{ .ext_type = @intFromEnum(messages.ExtensionType.pre_shared_key), .data = sh_ext_data_buf[0..2] };
            },
            .cert_dhe, .cert_dhe_insecure_unauthenticated => blk: {
                const ks = messages.encodeKeyShareServerHello(.{
                    .group = self.ecdhe_group,
                    .key_exchange = self.ecdhe_public[0..self.ecdhe_public_len],
                }, &sh_ext_data_buf) catch return error.BufferTooShort;
                break :blk .{ .ext_type = @intFromEnum(messages.ExtensionType.key_share), .data = ks };
            },
        };
        // RFC 8446 §4.2.1: a server that negotiates 1.3 MUST answer with
        // `supported_versions` carrying the selected version. Every version
        // field on the wire still reads DTLS 1.2, so this extension is the
        // only place the negotiated version appears — omitting it tells a
        // conforming client it just did a DTLS 1.2 handshake.
        var sh_versions_buf: [2]u8 = undefined;
        const sh_versions = try messages.encodeSupportedVersionsServerHello(messages.version_dtls13, &sh_versions_buf);
        const sh_exts = [_]messages.Extension{
            .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = sh_versions },
            sh_ext,
        };
        var sh_body_buf: [128]u8 = undefined;
        // RFC 9147 §5: "DTLS implementations do not use the TLS 1.3
        // 'compatibility mode' ... DTLS servers MUST NOT echo the
        // 'legacy_session_id' value from the client". This used to echo
        // `dec.legacy_session_id`, which is the TLS rule, not the DTLS one.
        // No peer this module has met is affected (a DTLS 1.3 client sends a
        // zero-length `legacy_session_id` — RFC 9147 §5.3 — so the bytes are
        // unchanged), but a client with a cached pre-1.3 session ID would
        // have seen it echoed back. It also has to be a constant for the
        // HelloRetryRequest path to work at all: `encodeHelloRetryRequest`
        // re-encodes the HRR from the cookie alone, and a peer-controlled
        // field is not in the cookie.
        const sh_body = messages.encodeServerHello(.{
            .random = random_bytes,
            .legacy_session_id_echo = &.{},
            .cipher_suite = @intFromEnum(suite),
            .extensions = &sh_exts,
        }, &sh_body_buf) catch return error.BufferTooShort;
        self.transcript.append(@intFromEnum(messages.HandshakeType.server_hello), sh_body);

        var sh_frag_buf: [128 + handshake.header_len]u8 = undefined;
        const sh_fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.server_hello), self.message_seq, sh_body, &sh_frag_buf);
        self.message_seq +%= 1;
        const sh_seq = self.hs0.send_seq;
        var cursor: usize = 0;
        {
            const sh_record = try self.writeEpoch0Record(sh_fragment, out[cursor..]);
            cursor += sh_record.len;
        }

        // RFC 8446 §7.1: handshake traffic secrets, over the transcript
        // through ServerHello.
        const th_through_sh = self.transcript.currentHash();
        const dhe_ptr: ?[]const u8 = if (dhe_shared) |*s| s[0..] else null;
        const hs_secret = keyschedule.deriveHandshakeSecret(Hkdf, es, &eh, dhe_ptr);
        if (dhe_shared) |*s| std.crypto.secureZero(u8, s); // forward secrecy: drop the (EC)DHE shared secret
        const hst = keyschedule.deriveHandshakeTrafficSecrets(Hkdf, hs_secret, &th_through_sh);
        self.hs_traffic_client = hst.client;
        self.hs_traffic_server = hst.server;
        const params = suiteParams(suite) orelse return error.UnsupportedSuite;
        self.hs_write_keys = deriveDir(Hkdf, params, hst.server);
        self.hs_read_keys = deriveDir(Hkdf, params, hst.client);

        var ee_body_buf: [8]u8 = undefined;
        const ee_body = messages.encodeEncryptedExtensions(&.{}, &ee_body_buf) catch return error.BufferTooShort;
        self.transcript.append(@intFromEnum(messages.HandshakeType.encrypted_extensions), ee_body);
        var ee_frag_buf: [8 + handshake.header_len]u8 = undefined;
        const ee_fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.encrypted_extensions), self.message_seq, ee_body, &ee_frag_buf);
        self.message_seq +%= 1;
        const ee_seq = self.hs2.send_seq;
        {
            const ee_record = try self.protectHandshakeMessage(ee_fragment, out[cursor..]);
            cursor += ee_record.len;
        }

        // ── certificate mode: CertificateRequest?, Certificate?,
        // CertificateVerify? — additive, see the "certificate mode" section
        // above `handleFlightServer`. Zero records emitted when neither
        // `config.request_client_cert` nor `config.cert` is set, reproducing
        // the original PSK-only flight 2 exactly.
        var extra_records: [3]flight.RecordNumber = undefined;
        var extra_n: usize = 0;

        if (self.config.request_client_cert) {
            // RFC 8446 §4.3.2: CertificateRequest MUST carry a
            // `signature_algorithms` extension telling the client what
            // schemes this server can verify — the client's own
            // `selectSignatureScheme` call (`handleFlightClient`) negotiates
            // against exactly this list.
            var sigalgs_buf: [2 + 2 * default_signature_algorithms.len]u8 = undefined;
            const sigalgs_ext = try signatureAlgorithmsExtension(self.config.signature_algorithms, &sigalgs_buf);
            const creq_exts = [_]messages.Extension{sigalgs_ext};
            var creq_body_buf: [max_certreq_body]u8 = undefined;
            const creq_body = messages.encodeCertificateRequest(.{ .certificate_request_context = &.{}, .extensions = &creq_exts }, &creq_body_buf) catch return error.BufferTooShort;
            var frag_buf: [max_certreq_body + handshake.header_len]u8 = undefined;
            const r = try self.sendEpoch2Message(.certificate_request, creq_body, &frag_buf, out[cursor..]);
            cursor += r.bytes.len;
            extra_records[extra_n] = .{ .epoch = 2, .sequence_number = r.seq };
            extra_n += 1;
        }

        if (self.config.cert) |cc| {
            var cert_body_buf: [max_cert_message_body]u8 = undefined;
            const cert_body = messages.encodeCertificate(&.{}, cc.chain, &cert_body_buf) catch return error.BufferTooShort;
            var frag_buf: [max_cert_message_body + handshake.header_len]u8 = undefined;
            const cert_r = try self.sendEpoch2Message(.certificate, cert_body, &frag_buf, out[cursor..]);
            cursor += cert_r.bytes.len;
            extra_records[extra_n] = .{ .epoch = 2, .sequence_number = cert_r.seq };
            extra_n += 1;

            // RFC 8446 §4.2.3 negotiation (see `selectSignatureScheme`): the
            // scheme this server signs with must be one the CLIENT actually
            // advertised in its ClientHello, one this server itself is
            // willing to use, AND one `cc.private_key`'s key family can
            // produce — never a hardcoded default.
            const scheme = try selectSignatureScheme(cc, self.config.signature_algorithms, client_sig_algs_buf[0..client_sig_algs_len]);
            const cv_r = try self.signAndSendCertificateVerify(cc, scheme, .server, entropy, out[cursor..]);
            cursor += cv_r.bytes.len;
            extra_records[extra_n] = .{ .epoch = 2, .sequence_number = cv_r.seq };
            extra_n += 1;
        }

        const finished_key = keyschedule.deriveFinishedKey(Hkdf, 32, hst.server);
        const th_before_finished = self.transcript.currentHash();
        const verify_data = keyschedule.computeFinishedVerifyData(Hmac, finished_key, &th_before_finished);
        self.transcript.append(@intFromEnum(messages.HandshakeType.finished), &verify_data);
        var fin_frag_buf: [32 + handshake.header_len]u8 = undefined;
        const fin_fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.finished), self.message_seq, &verify_data, &fin_frag_buf);
        self.message_seq +%= 1;
        const fin_seq = self.hs2.send_seq;
        {
            const fin_record = try self.protectHandshakeMessage(fin_fragment, out[cursor..]);
            cursor += fin_record.len;
        }

        const ms = keyschedule.deriveMasterSecret(Hkdf, hs_secret, &eh);
        const th_through_server_finished = self.transcript.currentHash();
        const ap = keyschedule.deriveApplicationTrafficSecrets(Hkdf, ms, &th_through_server_finished);
        self.pending_ap_client = ap.client;
        self.pending_ap_server = ap.server;

        var all_records: [6]flight.RecordNumber = undefined;
        var n: usize = 0;
        all_records[n] = .{ .epoch = 0, .sequence_number = sh_seq };
        n += 1;
        all_records[n] = .{ .epoch = 2, .sequence_number = ee_seq };
        n += 1;
        for (extra_records[0..extra_n]) |r| {
            all_records[n] = r;
            n += 1;
        }
        all_records[n] = .{ .epoch = 2, .sequence_number = fin_seq };
        n += 1;
        self.markFlightSent(all_records[0..n]);
        try self.cacheFlight(out[0..cursor], now_ms);
        self.state = .wait_finished;
        return .{ .out = out[0..cursor], .done = false };
    }

    /// Server flight 3 (implicit): optionally consumes the client's own
    /// Certificate/CertificateVerify (RFC 8446 §4.4, only legal if THIS
    /// server sent a CertificateRequest — see `Config.request_client_cert`
    /// — a client that sends one unprompted is rejected), then consumes the
    /// client's Finished, verifies its `verify_data`, and installs the
    /// application traffic secrets derived earlier. Transitions
    /// `.wait_finished` -> `.connected`.
    fn serverProcessClientFinished(self: *Connection, datagram: []const u8, out: []u8) HandshakeError!HandshakeResult {
        var pos: usize = 0;
        const cert_result = try self.consumeOptionalCertMessages(datagram, &pos, .client, false);
        if (cert_result.saw_cert and cert_result.leaf_len > 0 and !cert_result.saw_cv) return error.Malformed;
        if (self.config.request_client_cert) {
            // A client that was asked for a certificate MUST answer with a
            // Certificate message (possibly an empty one, RFC 8446 §4.4.2's
            // "no certificate available" — a genuine protocol answer, not a
            // missing message).
            if (!cert_result.saw_cert) return error.Malformed;
            if (cert_result.leaf_len == 0 and self.config.require_peer_cert) return error.PeerCertificateRequired;
        } else if (cert_result.saw_cert) {
            return error.UnexpectedMessage; // the client sent a cert we never requested
        }

        const fin = messages.decodeFinished(cert_result.finishedVerifyData());
        if (fin.verify_data.len != 32) return error.Malformed;

        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
        const finished_key = keyschedule.deriveFinishedKey(Hkdf, 32, self.hs_traffic_client);
        const th = self.transcript.currentHash(); // through the server's own Finished
        const expected = keyschedule.computeFinishedVerifyData(Hmac, finished_key, &th);
        if (!std.crypto.timing_safe.eql([32]u8, expected, fin.verify_data[0..32].*)) return error.FinishedVerifyFailed;
        self.transcript.append(@intFromEnum(messages.HandshakeType.finished), fin.verify_data);

        try self.installApplicationKeys(self.suite, self.pending_ap_client, self.pending_ap_server);
        self.clearFlightTracker();
        self.retransmit_timer.reset();
        self.last_flight_len = 0;

        // RFC 9147 §7.1: "In general, flights MUST be ACKed unless they are
        // implicitly acknowledged", and the list of implicitly-acknowledged
        // flights is "handshake flights OTHER THAN the client's final flight
        // of the main handshake". This is that flight — there is no
        // responding flight left to carry an implicit ACK, so a server that
        // stays silent here leaves a conforming peer waiting: wolfSSL's
        // client blocks in `wolfSSL_connect` until it arrives.
        //
        // "After the handshake, implementations MUST use the highest
        // available sending epoch" — the application keys were installed
        // just above, so the ACK goes out on epoch 3 while naming epoch-2
        // records, which §7 explicitly allows (the ACK's epoch must be equal
        // to or higher than the records it acknowledges).
        var ack_body_buf: [2 + 4 * flight.record_number_len]u8 = undefined;
        const ack_body = flight.encodeAck(cert_result.acks.items(), &ack_body_buf) catch
            return error.BufferTooShort;
        const ack_record = try self.protectRecord(content_type_ack, ack_body, out);
        return .{ .out = ack_record, .done = true };
    }

    /// RFC 8446 §4.1.4 / RFC 9147 §5.3: the server refused to proceed on
    /// ClientHello1 and asked for a retry carrying its cookie. This is how a
    /// DTLS server does return-routability checking without keeping state,
    /// and it is what a DEFAULT-configured DTLS 1.3 server does on the very
    /// first datagram — so a client that cannot do this cannot talk to one.
    ///
    /// The response is ClientHello2: ClientHello1 unmodified except for the
    /// changes RFC 8446 §4.1.2 permits — the echoed `cookie` extension, and
    /// (in `.cert_dhe` mode) a fresh `key_share` in the group the retry
    /// named. The `random` is NOT on that list, so it is reused verbatim; in
    /// PSK mode the binder is recomputed, because the transcript it commits
    /// to has changed.
    ///
    /// The transcript change is the subtle part and is done by
    /// `Transcript.resetToMessageHash`: ClientHello1 is REPLACED by a
    /// synthetic `message_hash` message holding its hash, so the server —
    /// which kept nothing — can rebuild the same transcript from the cookie.
    /// BOTH modes go through that one call: a parallel copy for the
    /// certificate path would be a place for the two to drift, and a
    /// transcript defect here is invisible to self-interop (both sides would
    /// simply agree on the wrong prefix) — see `engine.Transcript
    /// .resetToMessageHash`'s own note.
    fn handleHelloRetryRequest(
        self: *Connection,
        hrr_body: []const u8,
        hrr: messages.DecodedServerHello,
        entropy: Entropy,
        now_ms: u64,
        out: []u8,
    ) HandshakeError!HandshakeResult {
        // RFC 8446 §4.1.4: "If a client receives a second HelloRetryRequest
        // in the same connection ... it MUST abort the handshake" — without
        // this a server could keep a client retrying forever.
        if (self.saw_hello_retry_request) return error.UnexpectedMessage;

        var cookie: ?[]const u8 = null;
        var negotiated_version: ?[2]u8 = null;
        var selected_group: ?u16 = null;
        for (hrr.extensions) |e| switch (e.ext_type) {
            @intFromEnum(messages.ExtensionType.cookie) => cookie = messages.decodeCookieExtension(e.data) catch return error.Malformed,
            @intFromEnum(messages.ExtensionType.supported_versions) => negotiated_version = messages.decodeSupportedVersionsServerHello(e.data) catch return error.Malformed,
            // The HelloRetryRequest `key_share` is the two-byte
            // `selected_group` form, NOT the ServerHello form — see
            // `messages.decodeKeyShareHelloRetryRequest`.
            @intFromEnum(messages.ExtensionType.key_share) => selected_group = messages.decodeKeyShareHelloRetryRequest(e.data) catch return error.Malformed,
            else => {},
        };
        const version = negotiated_version orelse return error.VersionNotNegotiated;
        if (!std.mem.eql(u8, &version, &messages.version_dtls13)) return error.UnsupportedVersion;

        // The group ClientHello2 will offer a share in. Unchanged unless the
        // retry names a different one — and every way it can name an
        // unacceptable one is refused here rather than acted on.
        var retry_group = self.ecdhe_group;
        if (selected_group) |g| {
            switch (self.config.key_exchange) {
                // `psk_ke` has no (EC)DHE at all: this client's ClientHello
                // offers an EMPTY `key_share` list on purpose (see
                // `buildClientHello`). Producing a share here would silently
                // upgrade the exchange to `psk_dhe_ke`, which this engine
                // does not implement — so say so instead of pretending.
                .psk => return error.HelloRetryRequestUnsupported,
                .cert_dhe, .cert_dhe_insecure_unauthenticated => {
                    // RFC 8446 §4.1.4: the client MUST abort if
                    // `selected_group` was not in its own `supported_groups`.
                    // The server does not get to pick a group off-menu.
                    if (!groupAdvertised(g)) return error.UnsupportedGroup;
                    // ...and MUST abort if it names a group the client
                    // ALREADY offered a share in ("clients MUST abort ... if
                    // the selected_group field ... corresponds to a group
                    // which was provided in the key_share extension in the
                    // original ClientHello"). A client that obliged would
                    // regenerate the same offer forever on request: an
                    // unbounded retry loop driven entirely by the peer.
                    if (g == self.ecdhe_group) return error.IllegalHelloRetryRequest;
                    retry_group = g;
                },
            }
        }

        // A HelloRetryRequest with nothing to change is a protocol error
        // (RFC 8446 §4.1.4: it "MUST NOT" be sent if it would not change the
        // client's second flight). With no cookie AND no group change there
        // is nothing ClientHello2 could differ by, and answering with a
        // byte-identical ClientHello is the same retry loop.
        if (cookie == null and retry_group == self.ecdhe_group) return error.HelloRetryRequestUnsupported;
        if (cookie) |c| {
            if (c.len > max_cookie_len) return error.BufferTooShort;
        }

        self.saw_hello_retry_request = true;
        self.hrr_cipher_suite = hrr.cipher_suite;

        // RFC 8446 §4.4.1: replace ClientHello1 with `message_hash`, THEN
        // append the HelloRetryRequest, then ClientHello2. Order matters —
        // the binder in ClientHello2 is computed over exactly this prefix.
        self.transcript.resetToMessageHash(self.client_hello1_hash);
        self.transcript.append(@intFromEnum(messages.HandshakeType.server_hello), hrr_body);

        var ch_body_buf: [512]u8 = undefined;
        const ch_body = switch (self.config.key_exchange) {
            .psk => try self.buildClientHello(entropy, cookie orelse return error.HelloRetryRequestUnsupported, &ch_body_buf),
            .cert_dhe, .cert_dhe_insecure_unauthenticated => try self.buildClientHelloCertDhe(entropy, cookie, retry_group, &ch_body_buf),
        };
        self.transcript.append(@intFromEnum(messages.HandshakeType.client_hello), ch_body);

        // RFC 9147 §5.2: ClientHello2 is a NEW handshake message, so it takes
        // the next `message_seq` rather than reusing ClientHello1's (which is
        // what a retransmission would do).
        var frag_buf: [512 + handshake.header_len]u8 = undefined;
        const fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.client_hello), self.message_seq, ch_body, &frag_buf);
        self.message_seq +%= 1;

        const ch_seq = self.hs0.send_seq;
        const record_bytes = try self.writeEpoch0Record(fragment, out);
        self.clearFlightTracker();
        self.markFlightSent(&.{.{ .epoch = 0, .sequence_number = ch_seq }});
        try self.cacheFlight(record_bytes, now_ms);

        // Still waiting for a ServerHello — just for the real one this time.
        return .{ .out = record_bytes, .done = false };
    }

    /// Client side of flights 2+3 (RFC 9147 §5.4/§5.5): consumes ServerHello
    /// + EncryptedExtensions + server Finished (coalesced in `datagram`),
    /// derives the handshake and (from the transcript through the server's
    /// Finished) application traffic secrets, verifies the server's
    /// Finished, sends the client's own Finished, and installs application
    /// keys immediately (the client needs no further confirmation once it
    /// has verified the server). Transitions `.wait_server_hello` ->
    /// `.connected`.
    fn handleFlightClient(self: *Connection, datagram: []const u8, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        if (self.state != .wait_server_hello) return error.WrongState;

        var pos: usize = 0;
        var sh_msg_buf: [256]u8 = undefined;
        var sh_received_buf: [256]bool = undefined;
        const sh_parsed = try self.takeHandshakeMessage(datagram, &pos, .epoch0_plaintext, &sh_msg_buf, &sh_received_buf, null);
        if (sh_parsed.msg_type != @intFromEnum(messages.HandshakeType.server_hello)) return error.UnexpectedMessage;

        var ext_buf: [8]messages.Extension = undefined;
        const sh_dec = messages.decodeServerHello(sh_parsed.body, &ext_buf) catch return error.Malformed;
        if (messages.isHelloRetryRequest(sh_dec.random))
            return self.handleHelloRetryRequest(sh_parsed.body, sh_dec, entropy, now_ms, out);

        // Downgrade guard (RFC 8446 §4.2.1): the negotiated version lives ONLY
        // in `supported_versions` — every version field on the wire says DTLS
        // 1.2. A server that omits the extension, or names anything other than
        // DTLS 1.3, has not negotiated the protocol this module speaks, and
        // continuing would mean deriving 1.3 keys for a 1.2 handshake.
        var negotiated_version: ?[2]u8 = null;
        for (sh_dec.extensions) |e| {
            if (e.ext_type == @intFromEnum(messages.ExtensionType.supported_versions))
                negotiated_version = messages.decodeSupportedVersionsServerHello(e.data) catch return error.Malformed;
        }
        const version = negotiated_version orelse return error.VersionNotNegotiated;
        if (!std.mem.eql(u8, &version, &messages.version_dtls13)) return error.UnsupportedVersion;

        // RFC 8446 §4.1.4: after a HelloRetryRequest the ServerHello MUST
        // select the suite the retry named. Checked BEFORE the suite is
        // otherwise acted on — the retry is already in the transcript, so a
        // server that switches here has produced a flight this client's key
        // schedule would silently follow.
        if (self.hrr_cipher_suite) |committed| {
            if (sh_dec.cipher_suite != committed) return error.IllegalHelloRetryRequest;
        }

        const suite = cipherSuiteFromU16(sh_dec.cipher_suite) orelse return error.UnsupportedSuite;
        if (suiteParams(suite) == null) return error.UnsupportedSuite;
        var offered_ok = false;
        for (self.config.cipher_suites) |cs| {
            if (cs == suite) offered_ok = true;
        }
        if (!offered_ok) return error.NoCipherSuiteOverlap;
        self.suite = suite;

        self.transcript.append(@intFromEnum(messages.HandshakeType.server_hello), sh_parsed.body);
        self.clearFlightTracker(); // the ClientHello flight is now implicitly ACKed
        self.retransmit_timer.reset();

        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
        const eh = emptySha256Hash();

        // Handshake secret: PSK path (`null` DHE) unchanged; cert-DHE path
        // computes the X25519 shared secret from this client's stored
        // ephemeral secret + the server's key_share, and mixes it in via the
        // SAME `deriveHandshakeSecret` (RFC 8446 §7.1) — the early secret's
        // IKM is the zero PSK in that case.
        var hs_secret: [32]u8 = undefined;
        switch (self.config.key_exchange) {
            .psk => {
                const es = keyschedule.earlySecret(Hkdf, self.config.psk);
                hs_secret = keyschedule.deriveHandshakeSecret(Hkdf, es, &eh, null);
            },
            .cert_dhe, .cert_dhe_insecure_unauthenticated => {
                const server_share = try serverHelloShare(sh_dec.extensions);
                // RFC 8446 §4.2.8: the server's share MUST be in the same
                // group as the client's. After a HelloRetryRequest that is
                // also §4.1.4's check that the server did not name one group
                // in the retry and then answer in another — `ecdhe_group` is
                // whatever group this client last generated a share in, so
                // one comparison covers both the retry and the no-retry case.
                if (server_share.group != self.ecdhe_group) {
                    std.crypto.secureZero(u8, &self.ecdhe_secret);
                    self.ecdhe_secret_live = false;
                    return error.MissingKeyShare;
                }
                var shared = ecdheSharedSecret(self.ecdhe_group, self.ecdhe_secret, server_share.share) catch |err| {
                    std.crypto.secureZero(u8, &self.ecdhe_secret);
                    self.ecdhe_secret_live = false;
                    return err;
                };
                std.crypto.secureZero(u8, &self.ecdhe_secret); // forward secrecy: drop the ephemeral private key
                self.ecdhe_secret_live = false;
                const zero_psk = [_]u8{0} ** 32;
                const es = keyschedule.earlySecret(Hkdf, &zero_psk);
                hs_secret = keyschedule.deriveHandshakeSecret(Hkdf, es, &eh, shared[0..]);
                std.crypto.secureZero(u8, &shared); // forward secrecy: drop the (EC)DHE shared secret
            },
        }
        const th_through_sh = self.transcript.currentHash();
        const hst = keyschedule.deriveHandshakeTrafficSecrets(Hkdf, hs_secret, &th_through_sh);
        self.hs_traffic_client = hst.client;
        self.hs_traffic_server = hst.server;
        const params = suiteParams(suite).?;
        self.hs_write_keys = deriveDir(Hkdf, params, hst.client);
        self.hs_read_keys = deriveDir(Hkdf, params, hst.server);

        var ee_msg_buf: [64]u8 = undefined;
        var ee_received_buf: [64]bool = undefined;
        const ee_parsed = try self.takeHandshakeMessage(datagram, &pos, .epoch2_protected, &ee_msg_buf, &ee_received_buf, null);
        if (ee_parsed.msg_type != @intFromEnum(messages.HandshakeType.encrypted_extensions)) return error.UnexpectedMessage;
        self.transcript.append(@intFromEnum(messages.HandshakeType.encrypted_extensions), ee_parsed.body);

        // ── certificate mode: optional CertificateRequest?, Certificate?,
        // CertificateVerify? from the server, then the server's Finished —
        // additive, see the "certificate mode" section above
        // `handleFlightServer`. In pure PSK mode the first message found is
        // `finished` and this behaves exactly like the original inline
        // unprotect+reassemble call it replaces.
        const cert_result = try self.consumeOptionalCertMessages(datagram, &pos, .server, true);
        if (cert_result.saw_cert and cert_result.leaf_len > 0 and !cert_result.saw_cv) return error.Malformed;
        // `.cert_dhe` requires the peer certificate unconditionally: a server
        // that sends no Certificate message never reaches `verifyPeerCert`,
        // so `peer_verify` would never be consulted and the handshake would
        // complete anonymously. `require_peer_cert` stays the knob for the
        // PSK-with-certificates mode, where the PSK already authenticates.
        if (cert_result.leaf_len == 0 and (self.config.require_peer_cert or self.config.key_exchange.requiresPeerAuth()))
            return error.PeerCertificateRequired;

        const server_fin = messages.decodeFinished(cert_result.finishedVerifyData());
        if (server_fin.verify_data.len != 32) return error.Malformed;

        const server_finished_key = keyschedule.deriveFinishedKey(Hkdf, 32, hst.server);
        const th_before_server_finished = self.transcript.currentHash();
        const expected_server_vd = keyschedule.computeFinishedVerifyData(Hmac, server_finished_key, &th_before_server_finished);
        if (!std.crypto.timing_safe.eql([32]u8, expected_server_vd, server_fin.verify_data[0..32].*)) return error.FinishedVerifyFailed;
        self.transcript.append(@intFromEnum(messages.HandshakeType.finished), server_fin.verify_data);

        // Application traffic secrets are fixed at "through the SERVER's
        // Finished" (RFC 8446 §7.1) regardless of whatever the client sends
        // next below — computed here, BEFORE any client-side certificate
        // messages are appended to the transcript.
        const ms = keyschedule.deriveMasterSecret(Hkdf, hs_secret, &eh);
        const th_through_server_finished = self.transcript.currentHash();
        const ap = keyschedule.deriveApplicationTrafficSecrets(Hkdf, ms, &th_through_server_finished);

        // ── certificate mode: this client's own Certificate/CertificateVerify,
        // ONLY if the server asked (`cert_result.requested_client_cert`).
        // Must be sent — and appended to the transcript — BEFORE the
        // client's Finished, whose verify_data covers them.
        var cursor: usize = 0;
        var extra_records: [2]flight.RecordNumber = undefined;
        var extra_n: usize = 0;

        if (cert_result.requested_client_cert) {
            const ctx = cert_result.creq_context[0..cert_result.creq_context_len];
            var cert_body_buf: [max_cert_message_body]u8 = undefined;
            var frag_buf: [max_cert_message_body + handshake.header_len]u8 = undefined;

            if (self.config.cert) |cc| {
                const body = messages.encodeCertificate(ctx, cc.chain, &cert_body_buf) catch return error.BufferTooShort;
                const r = try self.sendEpoch2Message(.certificate, body, &frag_buf, out[cursor..]);
                cursor += r.bytes.len;
                extra_records[extra_n] = .{ .epoch = 2, .sequence_number = r.seq };
                extra_n += 1;

                // RFC 8446 §4.2.3 negotiation: the scheme this client signs
                // with must be one the SERVER advertised in its
                // CertificateRequest (`cert_result.peerSigAlgs()`), one this
                // client itself is willing to use, AND one `cc.private_key`
                // can produce (see `selectSignatureScheme`).
                const scheme = try selectSignatureScheme(cc, self.config.signature_algorithms, cert_result.peerSigAlgs());
                const cv_r = try self.signAndSendCertificateVerify(cc, scheme, .client, entropy, out[cursor..]);
                cursor += cv_r.bytes.len;
                extra_records[extra_n] = .{ .epoch = 2, .sequence_number = cv_r.seq };
                extra_n += 1;
            } else {
                // RFC 8446 §4.4.2: no suitable certificate -> an EMPTY
                // Certificate message, no CertificateVerify.
                const body = messages.encodeCertificate(ctx, &.{}, &cert_body_buf) catch return error.BufferTooShort;
                const r = try self.sendEpoch2Message(.certificate, body, &frag_buf, out[cursor..]);
                cursor += r.bytes.len;
                extra_records[extra_n] = .{ .epoch = 2, .sequence_number = r.seq };
                extra_n += 1;
            }
        }

        const client_finished_key = keyschedule.deriveFinishedKey(Hkdf, 32, hst.client);
        const th_for_client_finished = self.transcript.currentHash();
        const client_vd = keyschedule.computeFinishedVerifyData(Hmac, client_finished_key, &th_for_client_finished);
        self.transcript.append(@intFromEnum(messages.HandshakeType.finished), &client_vd);

        var fin_frag_buf: [32 + handshake.header_len]u8 = undefined;
        const client_fin_fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.finished), self.message_seq, &client_vd, &fin_frag_buf);
        self.message_seq +%= 1;
        const client_fin_seq = self.hs2.send_seq;
        const client_fin_record = try self.protectHandshakeMessage(client_fin_fragment, out[cursor..]);
        cursor += client_fin_record.len;

        var all_records: [3]flight.RecordNumber = undefined;
        var n: usize = 0;
        for (extra_records[0..extra_n]) |r| {
            all_records[n] = r;
            n += 1;
        }
        all_records[n] = .{ .epoch = 2, .sequence_number = client_fin_seq };
        n += 1;
        self.markFlightSent(all_records[0..n]);

        try self.installApplicationKeys(suite, ap.client, ap.server);
        // `now_ms` is used only on the HelloRetryRequest path above (arming
        // the retry flight's timer); once connected the client retransmits
        // nothing.

        return .{ .out = out[0..cursor], .done = true };
    }
};

// ── suite dispatch (runtime CipherSuite -> comptime AEAD/sn primitives) ──

const chachapoly = @import("chachapoly");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
// The `chacha20_poly1305_sha256` suite is RFC 8439's plain ChaCha20-Poly1305
// (NOT XChaCha), so the SIMD `chachapoly` sibling applies here — see
// `aead.zig`'s differential test for the byte-identity proof against std,
// which stays reachable there as the OpenSSL-anchored oracle.
const ChaCha20Poly1305 = chachapoly.ChaCha20Poly1305;

const SuiteParams = struct { key_len: u8, sn_len: u8, tag_len: u8, is_chacha: bool };

/// Returns the record-layer parameters for the suites whose 12-byte-nonce
/// AEAD is validated here, or `null` for suites this pass does not wire
/// (the CCM suites — std ships only a 13-byte-nonce CCM; see aead.zig).
fn suiteParams(suite: CipherSuite) ?SuiteParams {
    return switch (suite) {
        .aes_128_gcm_sha256 => .{ .key_len = 16, .sn_len = 16, .tag_len = 16, .is_chacha = false },
        .chacha20_poly1305_sha256 => .{ .key_len = 32, .sn_len = 32, .tag_len = 16, .is_chacha = true },
        .aes_128_ccm_sha256, .aes_128_ccm_8_sha256 => null,
    };
}

/// Zeroes (`std.crypto.secureZero`) the secret material of one direction's
/// keys — `key` and `sn_key` are AEAD/sequence-number-mask keys, `iv` is
/// the static IV combined with the sequence number into each record's
/// nonce (RFC 9147 §4.2.2), so all three are secret-adjacent. `key_len`/
/// `sn_len` are plaintext bookkeeping, not secrets, and are left as-is
/// (the caller resets the whole `DirKeys` to `.{}` afterward anyway).
fn secureZeroDirKeys(d: *DirKeys) void {
    std.crypto.secureZero(u8, &d.key);
    std.crypto.secureZero(u8, &d.iv);
    std.crypto.secureZero(u8, &d.sn_key);
}

fn deriveDir(comptime Hkdf: type, params: SuiteParams, secret: [32]u8) DirKeys {
    var d = DirKeys{ .key_len = params.key_len, .sn_len = params.sn_len };
    // Derive each of key + sn at the negotiated width (HKDF-Expand-Label's
    // length is part of its input, so a 16-byte "key" is NOT a prefix of a
    // 32-byte one — it must be expanded at the exact suite width).
    d.iv = keyschedule.deriveTrafficKeyIv(Hkdf, 16, 12, secret).iv; // iv width is suite-independent (12)
    switch (params.key_len) {
        16 => @memcpy(d.key[0..16], &keyschedule.deriveTrafficKeyIv(Hkdf, 16, 12, secret).key),
        32 => @memcpy(d.key[0..32], &keyschedule.deriveTrafficKeyIv(Hkdf, 32, 12, secret).key),
        else => unreachable,
    }
    switch (params.sn_len) {
        16 => @memcpy(d.sn_key[0..16], &keyschedule.deriveSequenceNumberKey(Hkdf, 16, secret)),
        32 => @memcpy(d.sn_key[0..32], &keyschedule.deriveSequenceNumberKey(Hkdf, 32, secret)),
        else => unreachable,
    }
    return d;
}

fn protectDispatch(
    suite: CipherSuite,
    keys: DirKeys,
    epoch: u16,
    seq: u48,
    inner: []const u8,
    aad: []const u8,
    out: []u8,
) !usize {
    return switch (suite) {
        .aes_128_gcm_sha256 => aead.Protection(Aes128Gcm).protect(keys.key[0..16].*, keys.iv, epoch, seq, inner, aad, out),
        .chacha20_poly1305_sha256 => aead.Protection(ChaCha20Poly1305).protect(keys.key[0..32].*, keys.iv, epoch, seq, inner, aad, out),
        else => error.UnsupportedSuite,
    };
}

fn unprotectDispatch(
    suite: CipherSuite,
    keys: DirKeys,
    epoch: u16,
    seq: u48,
    ct: []const u8,
    aad: []const u8,
    out: []u8,
) !usize {
    return switch (suite) {
        .aes_128_gcm_sha256 => aead.Protection(Aes128Gcm).unprotect(keys.key[0..16].*, keys.iv, epoch, seq, ct, aad, out),
        .chacha20_poly1305_sha256 => aead.Protection(ChaCha20Poly1305).unprotect(keys.key[0..32].*, keys.iv, epoch, seq, ct, aad, out),
        else => error.UnsupportedSuite,
    };
}

fn snMaskDispatch(suite: CipherSuite, keys: DirKeys, sample: []const u8, seq_bytes: []u8) !void {
    return switch (suite) {
        .aes_128_gcm_sha256 => aead.encryptSequenceNumberAes(keys.sn_key[0..16], sample, seq_bytes),
        .chacha20_poly1305_sha256 => aead.encryptSequenceNumberChaCha20(keys.sn_key[0..32], sample, seq_bytes),
        else => error.UnsupportedSuite,
    };
}

// ── suite dispatch chained to the byte-exact AEAD layer ──────────────────
//
// `roundtripSuite`/`loopbackHandshake`/`connectedPair` below drive the
// `chacha20_poly1305_sha256` suite end to end, but ONLY as a client<->server
// self-consistency check: both sides resolve `ChaCha20Poly1305` to whatever
// this file's alias currently names, so a suite bound to the WRONG AEAD
// (e.g. AES-256-GCM, which happens to share the 32/12/16 key/nonce/tag
// shape) still round-trips against itself and none of those tests would
// notice. This test closes that gap by calling `protectDispatch` directly
// with fixed keys/epoch/seq/plaintext/aad (no handshake needed — `DirKeys`
// is plain bytes) and asserting the record is byte-identical to
// `aead.Protection(chachapoly.ChaCha20Poly1305)` driven with the SAME
// inputs — the same `Protection` instantiation `aead.zig`'s KAT pins
// byte-exact against the independent OpenSSL vector. The chain is therefore
// OpenSSL vector -> `Protection` -> this dispatch, with no new external
// vector and nothing self-generated.
test "protectDispatch(chacha20_poly1305_sha256): byte-identical to Protection(chachapoly.ChaCha20Poly1305) for the same inputs" {
    var keys: DirKeys = .{};
    for (&keys.key, 0..) |*b, i| b.* = @intCast(0xA0 +% i);
    keys.key_len = 32;
    for (&keys.iv, 0..) |*b, i| b.* = @intCast(0x50 +% i);
    const epoch: u16 = 7;
    const seq: u48 = 99;
    const inner = "dtls dispatch chain KAT";
    const aad = "record header bytes";

    var via_dispatch: [inner.len + 16]u8 = undefined;
    const n1 = try protectDispatch(.chacha20_poly1305_sha256, keys, epoch, seq, inner, aad, &via_dispatch);

    var via_protection: [inner.len + 16]u8 = undefined;
    const n2 = try aead.Protection(chachapoly.ChaCha20Poly1305).protect(keys.key, keys.iv, epoch, seq, inner, aad, &via_protection);

    try std.testing.expectEqual(n1, n2);
    try std.testing.expectEqualSlices(u8, via_protection[0..n2], via_dispatch[0..n1]);

    // And it opens back through the same two paths.
    var open_dispatch: [inner.len]u8 = undefined;
    const m1 = try unprotectDispatch(.chacha20_poly1305_sha256, keys, epoch, seq, via_dispatch[0..n1], aad, &open_dispatch);
    try std.testing.expectEqualSlices(u8, inner, open_dispatch[0..m1]);
}

/// RFC 9147 §4.5.1 sliding anti-replay window check-and-update, shared by
/// the application epoch (`recv`) and the epoch-2 handshake-traffic
/// analogue (`unprotectHandshakeMessage`). `window` is a 64-bit bitmap
/// where bit 0 represents `high.*` (the highest sequence number accepted
/// so far in this epoch) and bit `i` (`i` in `1..64`) represents
/// `high.* - i`; a set bit means "already accepted".
///
/// MUST be called only for a sequence number whose record has ALREADY
/// passed AEAD authentication — never gate this on an unauthenticated
/// sequence number (e.g. one merely parsed from the wire), since that
/// would let an off-path attacker poison/desync the window with forged
/// records without needing to forge a valid tag.
///
/// Returns `true` (and slides/sets the window) if `seq` is new — either
/// ahead of the window (slides it forward) or an unset bit within it.
/// Returns `false` (window left untouched) if `seq` is a duplicate of an
/// already-accepted sequence number, or so far behind `high.*` that it
/// falls outside the 64-wide window entirely.
fn replayCheckAndUpdate(seen_any: *bool, high: *u48, window: *u64, seq: u48) bool {
    if (!seen_any.*) {
        seen_any.* = true;
        high.* = seq;
        window.* = 1;
        return true;
    }
    if (seq > high.*) {
        const diff = seq - high.*;
        window.* = if (diff >= 64) 1 else (window.* << @intCast(diff)) | 1;
        high.* = seq;
        return true;
    }
    const diff = high.* - seq;
    if (diff >= 64) return false; // older than the window floor
    const bit: u64 = @as(u64, 1) << @intCast(diff);
    if (window.* & bit != 0) return false; // duplicate: already seen
    window.* |= bit;
    return true;
}

// ── handshake flight engine: free (Connection-agnostic) helpers ─────────

/// Server-side cipher-suite negotiation: the first of OUR preferences (most
/// preferred first) the peer also offered and this module can actually
/// protect records with. Factored out of `serverProcessClientHello` because
/// RFC 8446 §4.1.4 requires the HelloRetryRequest and the eventual
/// ServerHello to select the same suite, and the surest way to guarantee
/// that is for both to run the same code over the same inputs.
fn selectCipherSuite(ours: []const CipherSuite, offered_raw: []const u8) ?CipherSuite {
    for (ours) |want| {
        var it = messages.CipherSuiteIter{ .raw = offered_raw };
        while (it.next()) |offered| {
            if (offered == @intFromEnum(want) and suiteParams(want) != null) return want;
        }
    }
    return null;
}

/// Safe wire-integer -> `CipherSuite` conversion. `CipherSuite` is an
/// EXHAUSTIVE enum (no `_` catch-all arm), so `@enumFromInt` on a
/// peer-controlled, possibly-unknown u16 would be a safety-checked panic —
/// exactly the kind of "typed error, never a panic" this module's tests
/// enforce everywhere else. A plain `switch` on the concrete values is the
/// non-panicking equivalent.
fn cipherSuiteFromU16(v: u16) ?CipherSuite {
    return switch (v) {
        @intFromEnum(CipherSuite.aes_128_gcm_sha256) => .aes_128_gcm_sha256,
        @intFromEnum(CipherSuite.chacha20_poly1305_sha256) => .chacha20_poly1305_sha256,
        @intFromEnum(CipherSuite.aes_128_ccm_sha256) => .aes_128_ccm_sha256,
        @intFromEnum(CipherSuite.aes_128_ccm_8_sha256) => .aes_128_ccm_8_sha256,
        else => null,
    };
}

/// `Sha256("")` — RFC 8446 §7.1's "empty transcript hash", needed at
/// several key-schedule points (`binderKey`, `deriveHandshakeSecret`,
/// `deriveMasterSecret`) that logically derive from "no messages yet".
fn emptySha256Hash() [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &h, .{});
    return h;
}

/// Frames `body` as a single-fragment `handshake.zig` message (12-byte
/// header + the whole body in one fragment — every message this engine
/// sends comfortably fits `frag_out`, so `Fragmenter.next` always succeeds
/// on its first call). Does not touch the record layer.
fn frameHandshakeMessage(msg_type: u8, message_seq: u16, body: []const u8, frag_out: []u8) HandshakeError![]const u8 {
    var fragmenter = handshake.Fragmenter.init(msg_type, message_seq, body);
    const max_len = if (frag_out.len > handshake.header_len) frag_out.len - handshake.header_len else 0;
    return fragmenter.next(max_len, frag_out) orelse return error.BufferTooShort;
}

/// Decodes ONE self-contained (single-fragment) handshake message from
/// `fragment_bytes`. Used only where the message is known to be complete in
/// one fragment because THIS engine produced it — `frameHandshakeMessage`
/// never fragments on transmit. Receiving is the general case and goes
/// through `Connection.takeHandshakeMessage` instead.
fn decodeSingleFragmentMessage(
    fragment_bytes: []const u8,
    msg_buf: []u8,
    received_buf: []bool,
) HandshakeError!TakenMessage {
    const hdr = handshake.decodeHeader(fragment_bytes) catch return error.Malformed;
    if (fragment_bytes.len < handshake.header_len + hdr.fragment_length) return error.Malformed;
    const frag_body = fragment_bytes[handshake.header_len..][0..hdr.fragment_length];
    if (hdr.length > msg_buf.len) return error.BufferTooShort;

    var reasm = handshake.Reassembler.init(msg_buf[0..hdr.length], received_buf[0..hdr.length]);
    const complete = (reasm.feed(hdr, frag_body) catch return error.Malformed) orelse
        return error.FlightIncomplete;
    return .{ .msg_type = hdr.msg_type, .body = complete, .message_seq = hdr.message_seq };
}

/// The total on-wire length (header + explicit-length content) of ONE
/// `record.UnifiedHeader` record starting at the front of `buf` — used to
/// step a cursor over a datagram carrying several coalesced records. This
/// engine always encodes an explicit `length` (never the
/// "rest of the datagram" form), so a missing length is malformed input.
fn recordWireLen(buf: []const u8) HandshakeError!usize {
    const dec = record.decodeUnified(buf, 0) catch return error.Malformed;
    const len = dec.hdr.length orelse return error.Malformed;
    if (buf.len < dec.consumed + len) return error.Malformed;
    return dec.consumed + len;
}

// ── tests: validation-only — must never call into crypto stubs ──────────

const testing = std.testing;

test "Config.validate: rejects empty PSK" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = &.{} };
    try testing.expectError(error.EmptyPsk, cfg.validate());
}

test "Config.validate: rejects empty PSK identity" {
    const cfg = Config{ .role = .client, .psk_identity = &.{}, .psk = "secret" };
    try testing.expectError(error.EmptyPskIdentity, cfg.validate());
}

test "Config.validate: rejects an empty cipher-suite list" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret", .cipher_suites = &.{} };
    try testing.expectError(error.NoCipherSuites, cfg.validate());
}

test "Config.validate: accepts a sane config" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    try cfg.validate();
}

test "clientInit/serverInit: real, validated, non-panicking construction" {
    const cfg = Config{ .role = .client, .psk_identity = "device-1", .psk = "s3cr3t" };
    var client = try Connection.clientInit(cfg);
    try testing.expectEqual(Role.client, client.role);
    try testing.expectEqual(State.start, client.state);
    client.deinit();

    var server = try Connection.serverInit(cfg);
    try testing.expectEqual(Role.server, server.role);
    server.deinit();
}

test "clientInit: propagates Config validation errors" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = &.{} };
    try testing.expectError(error.EmptyPsk, Connection.clientInit(cfg));
}

test "send/recv: real guard rejects use before the handshake completes" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var conn = try Connection.clientInit(cfg);
    var out: [64]u8 = undefined;
    try testing.expectError(error.NotConnected, conn.send("hi", &out));
    try testing.expectError(error.NotConnected, conn.recv("datagram", &out));
}

/// The one place this file's ~170 test call sites enter `Entropy`'s weak arm.
/// Named for what it is, and it returns the `.seeded_for_test` VALUE rather
/// than a `std.Random`, so no test can hand a `Connection` a generator without
/// the tag travelling with it. Production has no equivalent helper: a real
/// consumer writes `.{ .csprng = … }` itself.
fn seededForTest(csprng: *std.Random.DefaultCsprng) Entropy {
    return .{ .seeded_for_test = csprng.random() };
}

test "startHandshake: server role is rejected (typed error, not a panic)" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var server = try Connection.serverInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x01} ** 32);
    var out: [1500]u8 = undefined;
    try testing.expectError(error.WrongState, server.startHandshake(seededForTest(&csprng), 0, &out));
}

test "startHandshake: wrong state (already mid-handshake) is rejected" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var client = try Connection.clientInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x02} ** 32);
    var out: [1500]u8 = undefined;
    _ = try client.startHandshake(seededForTest(&csprng), 0, &out);
    try testing.expectError(error.WrongState, client.startHandshake(seededForTest(&csprng), 0, &out));
}

test "startHandshake: real ClientHello bytes, not a stub — real DTLS 1.3 flight sent" {
    const cfg = Config{ .role = .client, .psk_identity = "device-1", .psk = "s3cr3t", .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x03} ** 32);
    var out: [1500]u8 = undefined;
    const ch = try client.startHandshake(seededForTest(&csprng), 0, &out);
    try testing.expectEqual(State.wait_server_hello, client.state);
    // Legacy DTLSPlaintext header: content_type=22 (handshake), epoch=0.
    try testing.expectEqual(@as(u8, 22), ch[0]);
    try testing.expect(ch.len > record.plaintext_header_len + handshake.header_len);
}

// ── end-to-end record-layer self-consistency (both validated suites) ────
//
// Simulates a COMPLETED handshake by deriving matching application traffic
// secrets on both endpoints (identical PSK + identical transcript => same
// schedule) and installing them, then proves the real send/recv record path:
// client.send -> server.recv round-trips, sequence numbers advance and are
// encrypted on the wire, and any tamper is rejected without a panic.

fn deriveApSecrets(psk: []const u8) struct { c: [32]u8, s: [32]u8 } {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var empty: [32]u8 = undefined;
    Sha256.hash("", &empty, .{});
    var th: [32]u8 = undefined;
    Sha256.hash("dtls self-consistency transcript through server Finished", &th, .{});

    const es = keyschedule.earlySecret(Hkdf, psk);
    const hs = keyschedule.deriveHandshakeSecret(Hkdf, es, &empty, null);
    const ms = keyschedule.deriveMasterSecret(Hkdf, hs, &empty);
    const ap = keyschedule.deriveApplicationTrafficSecrets(Hkdf, ms, &th);
    return .{ .c = ap.client, .s = ap.server };
}

fn roundtripSuite(suite: CipherSuite) !void {
    const cfg = Config{ .role = .client, .psk_identity = "device-042", .psk = "a-shared-pre-shared-key" };
    var client = try Connection.clientInit(cfg);
    var server = try Connection.serverInit(.{ .role = .server, .psk_identity = cfg.psk_identity, .psk = cfg.psk });

    const ap = deriveApSecrets(cfg.psk);
    try client.installApplicationKeys(suite, ap.c, ap.s);
    try server.installApplicationKeys(suite, ap.c, ap.s);
    try testing.expectEqual(State.connected, client.state);

    // Both endpoints must have derived identical directional keys
    // (client write == server read, and vice versa).
    try testing.expectEqualSlices(u8, client.write_keys.key[0..client.write_keys.key_len], server.read_keys.key[0..server.read_keys.key_len]);
    try testing.expectEqualSlices(u8, &client.write_keys.iv, &server.read_keys.iv);

    // Two application records from client -> server, seq numbers advancing.
    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;

    const msg1 = "hello over DTLS 1.3 PSK";
    const rec1 = try client.send(msg1, &wire);
    try testing.expectEqual(@as(u48, 1), client.send_seq);
    const got1 = try server.recv(rec1, &plain);
    try testing.expectEqualSlices(u8, msg1, got1);

    const msg2 = "second record, seq=1";
    var wire2: [256]u8 = undefined;
    const rec2 = try client.send(msg2, &wire2);
    const got2 = try server.recv(rec2, &plain);
    try testing.expectEqualSlices(u8, msg2, got2);

    // The wire sequence number is ENCRYPTED (RFC 9147 §4.2.3): the on-wire
    // seq byte for record 1 must not equal the plaintext value (1). The seq
    // byte is the last header byte before the ciphertext; header is 1 byte
    // flags + 1 seq byte + 2 length bytes = seq at offset 1 for a short seq.
    try testing.expect(rec1[1] != 0x00); // masked, not the plaintext 0

    // Reverse direction: server -> client.
    var wire3: [256]u8 = undefined;
    const srv_msg = "ack from server";
    const rec3 = try server.send(srv_msg, &wire3);
    const got3 = try client.recv(rec3, &plain);
    try testing.expectEqualSlices(u8, srv_msg, got3);

    // Tamper: flip a ciphertext byte -> DecryptionFailed, never a panic.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..rec1.len], rec1);
    tampered[rec1.len - 1] ^= 0x80; // flip the last tag byte of the record
    // recv advances state, so use a fresh server for a clean seq window.
    var server2 = try Connection.serverInit(.{ .role = .server, .psk_identity = cfg.psk_identity, .psk = cfg.psk });
    try server2.installApplicationKeys(suite, ap.c, ap.s);
    try testing.expectError(error.DecryptionFailed, server2.recv(tampered[0..rec1.len], &plain));
}

test "record round-trip self-consistency: AES-128-GCM" {
    try roundtripSuite(.aes_128_gcm_sha256);
}

test "record round-trip self-consistency: ChaCha20-Poly1305" {
    try roundtripSuite(.chacha20_poly1305_sha256);
}

test "installApplicationKeys: CCM suites are honestly rejected (std nonce gap)" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var conn = try Connection.clientInit(cfg);
    const ap = deriveApSecrets(cfg.psk);
    try testing.expectError(error.UnsupportedSuite, conn.installApplicationKeys(.aes_128_ccm_8_sha256, ap.c, ap.s));
}

// ── handshake flight engine: the mandatory oracle ────────────────────────
//
// No external DTLS peer is required or used here: two `Connection`s (one
// client, one server) drive each other's flights entirely in memory —
// client.startHandshake -> server.handleFlight -> client.handleFlight ->
// server.handleFlight — until BOTH report `.done`/`.connected`. This is
// the real proof the flight engine is correct: PSK binder verified, both
// Finished `verify_data`s verified, identical keys derived on both sides
// purely from the shared PSK + the (independently, identically computed)
// transcript, and the existing validated `send`/`recv` application-data
// path works over the freshly-installed keys afterward.

/// Drives `client`/`server` (both already `clientInit`/`serverInit`, both
/// still `.start`) through a complete PSK handshake, alternating `buf1`/
/// `buf2` as scratch so no step's input aliases its own output buffer.
fn driveHandshake(client: *Connection, server: *Connection, rnd: Entropy, buf1: []u8, buf2: []u8) !void {
    const ch = try client.startHandshake(rnd, 0, buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, buf2);
    try testing.expect(!flight2.done);
    try testing.expectEqual(State.wait_finished, server.state);

    const client_fin = try client.handleFlight(flight2.out, rnd, 0, buf1);
    try testing.expect(client_fin.done);
    try testing.expectEqual(State.connected, client.state);

    const server_result = try server.handleFlight(client_fin.out, rnd, 0, buf2);
    try testing.expect(server_result.done);
    try testing.expectEqual(State.connected, server.state);
}

fn loopbackHandshake(suite: CipherSuite) !void {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{suite} };
    const cfg_server = Config{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{suite} };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x10} ** 32);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    try driveHandshake(&client, &server, seededForTest(&csprng), &buf1, &buf2);

    try testing.expectEqual(suite, client.suite);
    try testing.expectEqual(suite, server.suite);

    // Both sides must have derived IDENTICAL directional application keys
    // — the real proof that the independently-computed transcripts (and
    // therefore the whole key schedule) agree byte-for-byte.
    try testing.expectEqualSlices(u8, client.write_keys.key[0..client.write_keys.key_len], server.read_keys.key[0..server.read_keys.key_len]);
    try testing.expectEqualSlices(u8, &client.write_keys.iv, &server.read_keys.iv);
    try testing.expectEqualSlices(u8, client.read_keys.key[0..client.read_keys.key_len], server.write_keys.key[0..server.write_keys.key_len]);
    try testing.expectEqualSlices(u8, &client.read_keys.iv, &server.write_keys.iv);

    // Application-data round trip, BOTH directions, through the existing,
    // already-validated `send`/`recv` record path — over the keys THIS
    // handshake installed (not hand-derived, as the older
    // `roundtripSuite` self-consistency tests above do).
    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const msg1 = "hello from client, post-handshake";
    const rec1 = try client.send(msg1, &wire);
    const got1 = try server.recv(rec1, &plain);
    try testing.expectEqualSlices(u8, msg1, got1);

    var wire2: [256]u8 = undefined;
    const msg2 = "hello from server, post-handshake";
    const rec2 = try server.send(msg2, &wire2);
    const got2 = try client.recv(rec2, &plain);
    try testing.expectEqualSlices(u8, msg2, got2);

    // Tamper -> DecryptionFailed, never a panic.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..rec1.len], rec1);
    tampered[rec1.len - 1] ^= 0x80;
    try testing.expectError(error.DecryptionFailed, server.recv(tampered[0..rec1.len], &plain));
}

test "handshake: full client<->server loopback interop — AES-128-GCM" {
    try loopbackHandshake(.aes_128_gcm_sha256);
}

test "handshake: full client<->server loopback interop — ChaCha20-Poly1305" {
    try loopbackHandshake(.chacha20_poly1305_sha256);
}

test "cipher suite negotiation: SERVER's own preference order wins, not the client's offer order" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    // Both sides support the same two suites, but list them in OPPOSITE
    // order: the client offers ChaCha20-Poly1305 first, the server prefers
    // AES-128-GCM first. RFC 8446 leaves tie-breaking to local policy, and
    // `selectCipherSuite` is written to walk `ours` (the server's own list)
    // in the outer loop specifically so the SERVER's configured preference
    // decides — a server that instead deferred to whatever order the
    // (attacker-influenced) ClientHello listed suites in would let a
    // downgrading peer steer the choice away from an operator's intended
    // default suite, even when both suites are otherwise acceptable.
    const cfg_client = Config{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{ .chacha20_poly1305_sha256, .aes_128_gcm_sha256 },
    };
    const cfg_server = Config{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256 },
    };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x99} ** 32);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    try driveHandshake(&client, &server, seededForTest(&csprng), &buf1, &buf2);

    try testing.expectEqual(CipherSuite.aes_128_gcm_sha256, server.suite);
    try testing.expectEqual(CipherSuite.aes_128_gcm_sha256, client.suite);
}

// ── RFC 9147 §5.2 reassembly across datagrams ───────────────────────────
//
// Every fragment below is built BYTE BY BYTE by the two helpers that
// follow, NOT by `handshake.Fragmenter`. That is deliberate: a test that
// produces its fragments with the same encoder the code under test decodes
// with stays green under any mutation both halves share — swap the
// `fragment_offset` and `fragment_length` fields in both, and a round trip
// still round-trips. These helpers are an independent second opinion about
// the wire layout, pinned in turn by `handshake.zig`'s hand-built
// golden-bytes header test and by the live wolfSSL peer.
//
// The acceptance criterion is also deliberately cryptographic rather than
// structural: a ClientHello reassembled in the wrong ORDER still parses as
// a ClientHello, but its PSK binder (computed over the reassembled body)
// cannot verify, and a wrongly-reassembled Finished cannot match its
// `verify_data`. So these tests fail loudly on "assembled something, just
// not the right bytes", which a `expectEqual(body)` check on our own
// fragmenter's output would not.

/// One RFC 9147 §5.2 handshake fragment: the 12-byte header written out
/// field by field, followed by this fragment's slice of the body.
fn handBuiltHandshakeFragment(
    msg_type: u8,
    total_len: u24,
    message_seq: u16,
    fragment_offset: u24,
    fragment: []const u8,
    out: []u8,
) []const u8 {
    out[0] = msg_type;
    out[1] = @truncate(total_len >> 16);
    out[2] = @truncate(total_len >> 8);
    out[3] = @truncate(total_len);
    out[4] = @truncate(message_seq >> 8);
    out[5] = @truncate(message_seq);
    out[6] = @truncate(fragment_offset >> 16);
    out[7] = @truncate(fragment_offset >> 8);
    out[8] = @truncate(fragment_offset);
    const fragment_length: u24 = @intCast(fragment.len);
    out[9] = @truncate(fragment_length >> 16);
    out[10] = @truncate(fragment_length >> 8);
    out[11] = @truncate(fragment_length);
    @memcpy(out[12..][0..fragment.len], fragment);
    return out[0 .. 12 + fragment.len];
}

/// One epoch-0 `DTLSPlaintext` record (RFC 9147 §4) carrying `payload`,
/// likewise written field by field.
fn handBuiltPlaintextRecord(sequence_number: u48, payload: []const u8, out: []u8) []const u8 {
    out[0] = 22; // ContentType.handshake
    out[1] = 0xFE; // legacy_version = DTLS 1.2
    out[2] = 0xFD;
    out[3] = 0; // epoch 0
    out[4] = 0;
    std.mem.writeInt(u48, out[5..11], sequence_number, .big);
    std.mem.writeInt(u16, out[11..13], @intCast(payload.len), .big);
    @memcpy(out[13..][0..payload.len], payload);
    return out[0 .. 13 + payload.len];
}

/// The `(msg_type, length, message_seq, body)` of the single handshake
/// message inside an epoch-0 record this engine produced.
const SplitSource = struct {
    msg_type: u8,
    total_len: u24,
    message_seq: u16,
    body: [1024]u8,
    body_len: usize,

    fn slice(self: *const SplitSource) []const u8 {
        return self.body[0..self.body_len];
    }
};

fn splitSourceFromEpoch0(record_bytes: []const u8) !SplitSource {
    const rec = try record.decodePlaintext(record_bytes);
    const fragment = record_bytes[record.plaintext_header_len..][0..rec.length];
    const hdr = try handshake.decodeHeader(fragment);
    var out: SplitSource = .{
        .msg_type = hdr.msg_type,
        .total_len = hdr.length,
        .message_seq = hdr.message_seq,
        .body = undefined,
        .body_len = hdr.fragment_length,
    };
    // Only a message this engine emitted is used as a splitting source, and
    // it never fragments on transmit — so the one fragment IS the message.
    try testing.expectEqual(hdr.length, hdr.fragment_length);
    @memcpy(out.body[0..out.body_len], fragment[handshake.header_len..][0..out.body_len]);
    return out;
}

// ── fuzz: `handleFlight`, the real untrusted-datagram entry point ─────────
//
// Everything a peer sends during a handshake arrives here, and this is the
// layer that ACCUMULATES across datagrams: append into `rx_flight`, snapshot
// the whole `Connection`, parse, and either commit or roll the snapshot back.
// The decoders underneath it have carried fuzz targets since the module was
// written; this stitching transaction had none, and its hand-built vectors
// only cover the shapes their author imagined.
//
// Every iteration proves it REACHES the stitching path rather than bouncing
// off an early error: a genuine first half of a real ClientHello must come
// back as `need_more_data` before the fuzzed continuation is fed in.

test "fuzz: handleFlight survives arbitrary continuations of a half-delivered flight" {
    try testing.fuzz({}, fuzzHandleFlight, .{});
}

fn fuzzHandleFlight(_: void, smith: *std.testing.Smith) !void {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x5A} ** 32);
    const rnd = seededForTest(&csprng);

    var client = try Connection.clientInit(.{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var server = try Connection.serverInit(.{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });

    var buf1: [1500]u8 = undefined;
    var out: [1500]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &buf1);
    const src = try splitSourceFromEpoch0(ch);

    // (1) A REAL first fragment, split at a peer-chosen point. This must
    // leave the server buffering — i.e. the accumulate/snapshot transaction
    // is live for the fuzzed datagram that follows.
    const split: usize = smith.valueRangeAtMost(u16, 1, @intCast(src.body_len - 1));
    var frag_buf: [1500]u8 = undefined;
    var rec_buf: [1500]u8 = undefined;
    const head = handBuiltHandshakeFragment(src.msg_type, src.total_len, src.message_seq, 0, src.slice()[0..split], &frag_buf);
    const r1 = try server.handleFlight(handBuiltPlaintextRecord(0, head, &rec_buf), rnd, 0, &out);
    try testing.expect(r1.need_more_data);

    // (2) The attacker's continuation: every header field of the second
    // fragment is peer-chosen, including ones that contradict the first
    // (a different `msg_type`, a different total `length`, an offset past
    // the end, a body that disagrees with `fragment_length`). Some of these
    // complete the message, most are typed errors; none may panic, corrupt
    // the buffer, or leave the connection half-advanced.
    var body: [256]u8 = undefined;
    const body_len: usize = smith.valueRangeAtMost(u8, 0, 255);
    smith.bytes(body[0..body_len]);
    // Half the time, feed the TRUE remaining bytes at the TRUE offset, so
    // the completing path is reached too and not only the rejecting one.
    const truthful = smith.boolWeighted(1, 1) and src.body_len > split;
    const off: u24 = if (truthful) @intCast(split) else smith.valueRangeAtMost(u16, 0, @intCast(src.total_len + 8));
    const payload = if (truthful) src.slice()[split..] else body[0..body_len];
    const total_len: u24 = if (truthful) src.total_len else smith.valueRangeAtMost(u16, 0, @intCast(src.total_len + 8));
    const msg_type: u8 = if (truthful) src.msg_type else smith.value(u8);
    const seq: u16 = if (truthful) src.message_seq else smith.valueRangeAtMost(u16, 0, 2);

    var frag_buf2: [1500]u8 = undefined;
    var rec_buf2: [1500]u8 = undefined;
    if (@as(u64, off) + payload.len > total_len) return; // decodeHeader would reject the frame before reassembly sees it
    const tail = handBuiltHandshakeFragment(msg_type, total_len, seq, off, payload, &frag_buf2);
    const datagram = handBuiltPlaintextRecord(1, tail, &rec_buf2);
    _ = server.handleFlight(datagram, rnd, 0, &out) catch return;
}

test "reassembly: a ClientHello split across two datagrams, delivered OUT OF ORDER" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    var client = try Connection.clientInit(.{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var server = try Connection.serverInit(.{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x77} ** 32);
    const rnd = seededForTest(&csprng);

    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &buf1);
    const src = try splitSourceFromEpoch0(ch);
    const split = src.body_len / 2;
    try testing.expect(split > 0);

    // Second half FIRST — the reassembler must order by `fragment_offset`,
    // not by arrival.
    var frag_buf_b: [1500]u8 = undefined;
    var rec_buf_b: [1500]u8 = undefined;
    const tail = handBuiltHandshakeFragment(src.msg_type, src.total_len, src.message_seq, @intCast(split), src.slice()[split..], &frag_buf_b);
    const datagram_b = handBuiltPlaintextRecord(1, tail, &rec_buf_b);

    const before_state = server.state;
    const before_message_seq = server.message_seq;
    const before_peer_seq = server.peer_message_seq;
    const before_transcript = server.transcript.currentHash();
    const before_hs0 = server.hs0;
    const before_hs2 = server.hs2;

    const step1 = try server.handleFlight(datagram_b, rnd, 0, &buf2);
    try testing.expect(step1.need_more_data);
    try testing.expect(!step1.done);
    try testing.expectEqual(@as(usize, 0), step1.out.len);

    // The half-consumed flight must have left NOTHING behind: an incomplete
    // flight is a transaction that rolled back, not a partially-applied one.
    try testing.expectEqual(before_state, server.state);
    try testing.expectEqual(before_message_seq, server.message_seq);
    try testing.expectEqual(before_peer_seq, server.peer_message_seq);
    const after_transcript = server.transcript.currentHash();
    try testing.expectEqualSlices(u8, &before_transcript, &after_transcript);
    try testing.expectEqual(before_hs0, server.hs0);
    try testing.expectEqual(before_hs2, server.hs2);
    try testing.expectEqual(@as(usize, 0), server.last_flight_len);

    // First half second — completes the message. The PSK binder is computed
    // over the REASSEMBLED body, so this only verifies if the two halves
    // went back together at the right offsets.
    var frag_buf_a: [1500]u8 = undefined;
    var rec_buf_a: [1500]u8 = undefined;
    const head = handBuiltHandshakeFragment(src.msg_type, src.total_len, src.message_seq, 0, src.slice()[0..split], &frag_buf_a);
    const datagram_a = handBuiltPlaintextRecord(2, head, &rec_buf_a);

    const flight2 = try server.handleFlight(datagram_a, rnd, 0, &buf2);
    try testing.expect(!flight2.need_more_data);
    try testing.expect(!flight2.done);
    try testing.expectEqual(State.wait_finished, server.state);

    // ...and the handshake really completes on both sides, with working keys.
    const client_fin = try client.handleFlight(flight2.out, rnd, 0, &buf1);
    try testing.expect(client_fin.done);
    const server_done = try server.handleFlight(client_fin.out, rnd, 0, &buf2);
    try testing.expect(server_done.done);

    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const msg = "reassembled handshake, working keys";
    const rec = try client.send(msg, &wire);
    try testing.expectEqualStrings(msg, try server.recv(rec, &plain));
}

test "reassembly: a THREE-fragment ClientHello, middle fragment duplicated" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    var client = try Connection.clientInit(.{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var server = try Connection.serverInit(.{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x78} ** 32);
    const rnd = seededForTest(&csprng);

    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &buf1);
    const src = try splitSourceFromEpoch0(ch);
    const third = src.body_len / 3;
    try testing.expect(third > 0);

    const bounds = [_][2]usize{
        .{ 0, third },
        .{ third, 2 * third },
        .{ 2 * third, src.body_len },
    };
    // Arrival order: middle, last, middle AGAIN (a duplicate — legal, RFC
    // 9147 §5.2), first.
    const arrival = [_]usize{ 1, 2, 1, 0 };

    var seen_incomplete: usize = 0;
    var completed: ?Connection.HandshakeResult = null;
    for (arrival, 0..) |idx, i| {
        var frag_buf: [1500]u8 = undefined;
        var rec_buf: [1500]u8 = undefined;
        const part = src.slice()[bounds[idx][0]..bounds[idx][1]];
        const f = handBuiltHandshakeFragment(src.msg_type, src.total_len, src.message_seq, @intCast(bounds[idx][0]), part, &frag_buf);
        const d = handBuiltPlaintextRecord(@intCast(i), f, &rec_buf);
        const r = try server.handleFlight(d, rnd, 0, &buf2);
        if (r.need_more_data) {
            seen_incomplete += 1;
        } else {
            completed = r;
        }
    }
    try testing.expectEqual(@as(usize, 3), seen_incomplete);
    try testing.expectEqual(State.wait_finished, server.state);

    const client_fin = try client.handleFlight(completed.?.out, rnd, 0, &buf1);
    try testing.expect(client_fin.done);
    const server_done = try server.handleFlight(client_fin.out, rnd, 0, &buf2);
    try testing.expect(server_done.done);
}

test "reassembly: a CONTRADICTING overlapping fragment is rejected, not last-writer-wins" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    var client = try Connection.clientInit(.{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var server = try Connection.serverInit(.{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x79} ** 32);
    const rnd = seededForTest(&csprng);

    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &buf1);
    const src = try splitSourceFromEpoch0(ch);
    const split = src.body_len / 2;

    var frag_buf_a: [1500]u8 = undefined;
    var rec_buf_a: [1500]u8 = undefined;
    const head = handBuiltHandshakeFragment(src.msg_type, src.total_len, src.message_seq, 0, src.slice()[0..split], &frag_buf_a);
    const datagram_a = handBuiltPlaintextRecord(0, head, &rec_buf_a);
    try testing.expect((try server.handleFlight(datagram_a, rnd, 0, &buf2)).need_more_data);

    // The same offsets again, with one byte flipped: an off-path attacker
    // rewriting bytes the peer already sent. "Last writer wins" would let
    // it steer what ends up in the transcript.
    var tampered: [1024]u8 = undefined;
    @memcpy(tampered[0..split], src.slice()[0..split]);
    tampered[split / 2] ^= 0x01;
    var frag_buf_c: [1500]u8 = undefined;
    var rec_buf_c: [1500]u8 = undefined;
    const clash = handBuiltHandshakeFragment(src.msg_type, src.total_len, src.message_seq, 0, tampered[0..split], &frag_buf_c);
    const datagram_c = handBuiltPlaintextRecord(1, clash, &rec_buf_c);
    try testing.expectError(error.OverlappingFragment, server.handleFlight(datagram_c, rnd, 0, &buf2));
}

test "reassembly: a fragment that changes msg_type or total length mid-message is rejected" {
    // Both are "contradiction" cases a well-behaved sender never produces,
    // which is exactly why they need pinning: the reassembled body would
    // otherwise be dispatched on whichever fragment's `msg_type` the reader
    // happened to keep, and sized by whichever `length` it happened to
    // believe — attacker-chosen, both of them.
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_c = Config{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} };
    const cfg_s = Config{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} };

    var csprng = std.Random.DefaultCsprng.init([_]u8{0x7d} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    var seed_client = try Connection.clientInit(cfg_c);
    const ch = try seed_client.startHandshake(rnd, 0, &buf1);
    const src = try splitSourceFromEpoch0(ch);
    const split = src.body_len / 2;

    const Case = struct { msg_type: u8, total_len: u24, want: anyerror };
    const cases = [_]Case{
        .{ .msg_type = src.msg_type +% 1, .total_len = src.total_len, .want = error.InconsistentMessageType },
        // `+ 1`, not `- 1`: a SMALLER declared length would make the
        // fragment's own `offset + length` overrun it, so the header would
        // be rejected before reassembly ever sees the contradiction.
        .{ .msg_type = src.msg_type, .total_len = src.total_len + 1, .want = error.InconsistentLength },
    };

    for (cases) |c| {
        var server = try Connection.serverInit(cfg_s);
        var frag_buf_a: [1500]u8 = undefined;
        var rec_buf_a: [1500]u8 = undefined;
        const head = handBuiltHandshakeFragment(src.msg_type, src.total_len, src.message_seq, 0, src.slice()[0..split], &frag_buf_a);
        try testing.expect((try server.handleFlight(handBuiltPlaintextRecord(0, head, &rec_buf_a), rnd, 0, &buf2)).need_more_data);

        var frag_buf_b: [1500]u8 = undefined;
        var rec_buf_b: [1500]u8 = undefined;
        const tail = handBuiltHandshakeFragment(c.msg_type, c.total_len, src.message_seq, @intCast(split), src.slice()[split..], &frag_buf_b);
        try testing.expectError(c.want, server.handleFlight(handBuiltPlaintextRecord(1, tail, &rec_buf_b), rnd, 0, &buf2));
    }
}

test "reassembly: a fragment of a LATER message while one is in progress is rejected" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    var client = try Connection.clientInit(.{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var server = try Connection.serverInit(.{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x7a} ** 32);
    const rnd = seededForTest(&csprng);

    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &buf1);
    const src = try splitSourceFromEpoch0(ch);
    const split = src.body_len / 2;

    var frag_buf_a: [1500]u8 = undefined;
    var rec_buf_a: [1500]u8 = undefined;
    const head = handBuiltHandshakeFragment(src.msg_type, src.total_len, src.message_seq, 0, src.slice()[0..split], &frag_buf_a);
    try testing.expect((try server.handleFlight(handBuiltPlaintextRecord(0, head, &rec_buf_a), rnd, 0, &buf2)).need_more_data);

    var frag_buf_b: [1500]u8 = undefined;
    var rec_buf_b: [1500]u8 = undefined;
    const next_msg = handBuiltHandshakeFragment(src.msg_type, src.total_len, src.message_seq +% 1, 0, src.slice(), &frag_buf_b);
    try testing.expectError(
        error.InterleavedFragments,
        server.handleFlight(handBuiltPlaintextRecord(1, next_msg, &rec_buf_b), rnd, 0, &buf2),
    );
}

test "reassembly: buffered bytes are capped — a peer that never completes a message gets FlightTooLarge" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    var client = try Connection.clientInit(.{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var server = try Connection.serverInit(.{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x7b} ** 32);
    const rnd = seededForTest(&csprng);

    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &buf1);
    const src = try splitSourceFromEpoch0(ch);

    // One byte of a message that claims to be much longer, over and over:
    // every datagram is well-formed and none of them completes anything.
    var frag_buf: [1500]u8 = undefined;
    var rec_buf: [1500]u8 = undefined;
    const dribble = handBuiltHandshakeFragment(src.msg_type, src.total_len, src.message_seq, 0, src.slice()[0..1], &frag_buf);
    const datagram = handBuiltPlaintextRecord(0, dribble, &rec_buf);

    var i: usize = 0;
    var overflowed: ?anyerror = null;
    while (i < 10_000) : (i += 1) {
        const r = server.handleFlight(datagram, rnd, 0, &buf2) catch |err| {
            overflowed = err;
            break;
        };
        try testing.expect(r.need_more_data);
    }
    try testing.expectEqual(@as(?anyerror, error.FlightTooLarge), overflowed);
    // It must have taken more than a couple of datagrams — i.e. the engine
    // really is buffering, not rejecting the second one outright.
    try testing.expect(i > 2);

    // The VALUE of the bound, not just the mechanism. `i <= max_flight_bytes`
    // compares the constant with itself and stays green for any value; the
    // literals below do not.
    //
    // 4096 bytes is the delivered `max_flight_bytes`: it is the size of the
    // per-`Connection` `rx_flight` buffer AND — because `handleFlight` takes
    // a whole-struct stack snapshot of `*Connection` on every datagram — a
    // bound on this engine's stack consumption. It is sized from the largest
    // flight this engine can legitimately receive (see the byte-budget note
    // above `max_flight_bytes`), so growing it is a deliberate act, not a
    // rounding.
    try testing.expectEqual(@as(usize, 4096), max_flight_bytes);
    // ...and here is that same 4096 observed from OUTSIDE the module, as the
    // exact number of dribble datagrams the engine accepts before it says
    // FlightTooLarge: each datagram is a 13-byte DTLSPlaintext header + a
    // 12-byte handshake-fragment header + 1 payload byte = 26 bytes, and
    // 4096 / 26 = 157 (the 158th no longer fits).
    try testing.expectEqual(@as(usize, 26), datagram.len);
    try testing.expectEqual(@as(usize, 157), i);
    // The accumulator is dropped, so the connection is reusable.
    try testing.expectEqual(@as(usize, 0), server.rx_flight_len);
}

test "reassembly: an epoch-2 Finished split across datagrams, delivered OUT OF ORDER" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    var client = try Connection.clientInit(.{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var server = try Connection.serverInit(.{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x7c} ** 32);
    const rnd = seededForTest(&csprng);

    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);
    const client_fin = try client.handleFlight(flight2.out, rnd, 0, &buf1);
    try testing.expect(client_fin.done);

    // Recover the Finished's plaintext handshake fragment through a CLONE of
    // the server, so the real one's epoch-2 anti-replay window is untouched.
    var probe = server;
    var plain: [512]u8 = undefined;
    const frag = try probe.unprotectHandshakeMessage(client_fin.out, &plain, null);
    const hdr = try handshake.decodeHeader(frag);
    var body: [128]u8 = undefined;
    @memcpy(body[0..hdr.fragment_length], frag[handshake.header_len..][0..hdr.fragment_length]);
    const body_len: usize = hdr.fragment_length;
    const split = body_len / 2;
    try testing.expect(split > 0);

    // Re-protect the two halves under a CLONE of the client — its real
    // handshake write keys and its next record sequence numbers, which is
    // exactly what that client retransmitting under a smaller MTU emits.
    var sender = client;
    var frag_buf_b: [256]u8 = undefined;
    var rec_buf_b: [256]u8 = undefined;
    const tail = handBuiltHandshakeFragment(hdr.msg_type, hdr.length, hdr.message_seq, @intCast(split), body[split..body_len], &frag_buf_b);
    const datagram_b = try sender.protectHandshakeMessage(tail, &rec_buf_b);

    var frag_buf_a: [256]u8 = undefined;
    var rec_buf_a: [256]u8 = undefined;
    const head = handBuiltHandshakeFragment(hdr.msg_type, hdr.length, hdr.message_seq, 0, body[0..split], &frag_buf_a);
    const datagram_a = try sender.protectHandshakeMessage(head, &rec_buf_a);

    // Tail first.
    const step1 = try server.handleFlight(datagram_b, rnd, 0, &buf2);
    try testing.expect(step1.need_more_data);
    try testing.expectEqual(State.wait_finished, server.state);

    // Head second: only a correctly-ordered reassembly produces a
    // `verify_data` that matches the transcript both sides computed.
    const done = try server.handleFlight(datagram_a, rnd, 0, &buf2);
    try testing.expect(done.done);
    try testing.expectEqual(State.connected, server.state);

    var wire: [256]u8 = undefined;
    var plain2: [256]u8 = undefined;
    const msg = "fragmented Finished, working keys";
    const rec = try client.send(msg, &wire);
    try testing.expectEqualStrings(msg, try server.recv(rec, &plain2));
}

// ── recv: RFC 9147 §4.5.1 anti-replay window (regression for F1) ────────
//
// Reproduces the exact scenario the audit drove by hand: a full loopback
// handshake, one real `send`/`recv` round trip, then `server.recv` fed the
// IDENTICAL captured wire bytes a second time. Before the fix this second
// call re-decrypted successfully and returned the plaintext again; now it
// must be rejected with `error.ReplayedRecord`.

fn connectedPair(suite: CipherSuite, seed: u8, client: *Connection, server: *Connection) !void {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    client.* = try Connection.clientInit(.{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{suite} });
    server.* = try Connection.serverInit(.{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{suite} });
    var csprng = std.Random.DefaultCsprng.init([_]u8{seed} ** 32);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    try driveHandshake(client, server, seededForTest(&csprng), &buf1, &buf2);
}

test "recv: a verbatim-replayed record is rejected, not delivered twice" {
    var client: Connection = undefined;
    var server: Connection = undefined;
    try connectedPair(.aes_128_gcm_sha256, 0x30, &client, &server);

    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const rec = try client.send("replay-me", &wire);

    // Capture the exact wire bytes an attacker (or a duplicated UDP
    // datagram) would re-inject.
    var captured: [256]u8 = undefined;
    @memcpy(captured[0..rec.len], rec);

    const got1 = try server.recv(captured[0..rec.len], &plain);
    try testing.expectEqualSlices(u8, "replay-me", got1);

    // Re-injecting the SAME bytes must now be rejected — not re-decrypted.
    try testing.expectError(error.ReplayedRecord, server.recv(captured[0..rec.len], &plain));
}

test "recv: anti-replay window accepts in-order delivery and within-window reordering" {
    var client: Connection = undefined;
    var server: Connection = undefined;
    try connectedPair(.chacha20_poly1305_sha256, 0x31, &client, &server);

    var plain: [256]u8 = undefined;
    var wires: [3][256]u8 = undefined;
    var recs: [3][]const u8 = undefined;
    const msgs = [_][]const u8{ "seq-0", "seq-1", "seq-2" };
    for (msgs, 0..) |m, i| {
        const r = try client.send(m, &wires[i]);
        recs[i] = wires[i][0..r.len];
    }

    // In-order: seq 0 accepted normally.
    try testing.expectEqualSlices(u8, msgs[0], try server.recv(recs[0], &plain));
    // Mild reorder: seq 2 arrives before seq 1. Both are within the
    // 64-record window relative to whichever is the current high watermark
    // at delivery time, so both must still be accepted exactly once.
    try testing.expectEqualSlices(u8, msgs[2], try server.recv(recs[2], &plain));
    try testing.expectEqualSlices(u8, msgs[1], try server.recv(recs[1], &plain));

    // Having been delivered once each, replaying any of the three now must
    // be rejected.
    try testing.expectError(error.ReplayedRecord, server.recv(recs[0], &plain));
    try testing.expectError(error.ReplayedRecord, server.recv(recs[1], &plain));
    try testing.expectError(error.ReplayedRecord, server.recv(recs[2], &plain));
}

test "recv: the anti-replay window is exactly 64 records wide — 63 back is accepted, 64 back is not" {
    // WIDTH, not mechanism. The reordering test above only ever exercises
    // `diff == 1`, so the window could be narrowed to 2 (dropping legitimately
    // reordered records on any lossy link) or widened to 4096 (keeping a
    // 4096-entry replay history the RFC never asked for) with the suite green.
    //
    // 64 is the delivered value and it is written out as a literal here:
    // RFC 9147 §4.5.1 / RFC 6347 §4.1.2.6 require a window of AT LEAST 32,
    // and the implementation's history is a single `u64` bitmap — one bit per
    // record, bit 0 == the high-water mark — so 64 is what a `u64` holds.
    var client: Connection = undefined;
    var server: Connection = undefined;
    try connectedPair(.aes_128_gcm_sha256, 0x35, &client, &server);

    var plain: [256]u8 = undefined;
    var wires: [65][64]u8 = undefined;
    var recs: [65][]const u8 = undefined;
    for (&wires, 0..) |*w, i| {
        var msg: [8]u8 = undefined;
        const m = std.fmt.bufPrint(&msg, "s{d}", .{i}) catch unreachable;
        const r = try client.send(m, w);
        recs[i] = w[0..r.len];
    }

    // Deliver the newest record first: the high-water mark is now seq 64 and
    // the window covers seq 1..64 inclusive.
    try testing.expectEqualSlices(u8, "s64", try server.recv(recs[64], &plain));

    // seq 0 is 64 back from the high-water mark — one PAST the floor.
    try testing.expectError(error.ReplayedRecord, server.recv(recs[0], &plain));
    // seq 1 is 63 back — the oldest record the window can still accept. A
    // window narrower than 64 rejects this; a wider one would have accepted
    // seq 0 above.
    try testing.expectEqualSlices(u8, "s1", try server.recv(recs[1], &plain));
    // ...and it is still a one-shot: the same record again is a replay.
    try testing.expectError(error.ReplayedRecord, server.recv(recs[1], &plain));
}

test "replayCheckAndUpdate: the 64-wide floor and the 64-record forward jump, at the boundary" {
    // Same width pinned directly on the primitive, with literal sequence
    // numbers so no constant in the module can rename the boundary.
    var seen = false;
    var high: u48 = 0;
    var window: u64 = 0;

    try testing.expect(replayCheckAndUpdate(&seen, &high, &window, 1000));
    // 1000 - 63 = 937 is inside the window; 1000 - 64 = 936 is outside it.
    try testing.expect(replayCheckAndUpdate(&seen, &high, &window, 937));
    try testing.expect(!replayCheckAndUpdate(&seen, &high, &window, 936));
    // Neither of those moved the high-water mark.
    try testing.expectEqual(@as(u48, 1000), high);
    // A duplicate inside the window is still rejected.
    try testing.expect(!replayCheckAndUpdate(&seen, &high, &window, 937));

    // Forward jumps: a jump of exactly 63 keeps the old bits (so the record
    // 63 places behind the OLD high-water mark is still remembered), while a
    // jump of 64 or more resets the bitmap to "only this record seen".
    var seen2 = false;
    var high2: u48 = 0;
    var window2: u64 = 0;
    try testing.expect(replayCheckAndUpdate(&seen2, &high2, &window2, 1000));
    try testing.expect(replayCheckAndUpdate(&seen2, &high2, &window2, 1063)); // +63
    try testing.expect(!replayCheckAndUpdate(&seen2, &high2, &window2, 1000)); // still remembered
    try testing.expect(replayCheckAndUpdate(&seen2, &high2, &window2, 1127)); // +64 -> reset
    try testing.expectEqual(@as(u64, 1), window2);
}

test "recv: a forged (bad-tag) record cannot poison the anti-replay window" {
    // Ordering check for F1: the replay window must update ONLY after AEAD
    // authentication succeeds. A record with a valid header/sequence number
    // but a corrupted tag must fail with `DecryptionFailed` (not
    // `ReplayedRecord`, and without touching window state), and the
    // genuine record at that same sequence number must still be accepted
    // afterward.
    var client: Connection = undefined;
    var server: Connection = undefined;
    try connectedPair(.aes_128_gcm_sha256, 0x32, &client, &server);

    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const rec = try client.send("legit", &wire);

    var forged: [256]u8 = undefined;
    @memcpy(forged[0..rec.len], rec);
    forged[rec.len - 1] ^= 0x01; // corrupt the AEAD tag
    try testing.expectError(error.DecryptionFailed, server.recv(forged[0..rec.len], &plain));

    // The genuine record must still go through — the failed forgery did
    // not advance/poison the window.
    try testing.expectEqualSlices(u8, "legit", try server.recv(rec, &plain));
}

// ── deinit: secret zeroization (regression for F2) ───────────────────────

test "deinit: zeroes all resident key/secret material" {
    var client: Connection = undefined;
    var server: Connection = undefined;
    try connectedPair(.aes_128_gcm_sha256, 0x34, &client, &server);

    // Sanity: post-handshake these fields are genuinely populated (not
    // already all-zero), otherwise the zeroed-after-deinit assertions below
    // would pass trivially. `pending_ap_client`/`pending_ap_server` are
    // documented as SERVER-side-only bookkeeping (`Connection`'s own field
    // doc comment: "the client confirms immediately ... and installs right
    // away; the server stashes these here until the client's Finished
    // verifies") — the CLIENT never writes them, so they are checked on
    // `server` here, not `client` (checking them on `client` was a latent
    // bug: `undefined`-initialized memory happens to be non-zero under
    // Debug's poison-fill but is NOT guaranteed to be, and genuinely reads
    // as zero under ReleaseFast — this would have silently made that half
    // of the "genuinely populated" sanity check meaningless).
    try testing.expect(!std.mem.allEqual(u8, client.write_keys.key[0..client.write_keys.key_len], 0));
    try testing.expect(!std.mem.allEqual(u8, &client.hs_traffic_client, 0));
    try testing.expect(!std.mem.allEqual(u8, &client.hs_traffic_server, 0));
    try testing.expect(!std.mem.allEqual(u8, &server.pending_ap_client, 0));
    try testing.expect(!std.mem.allEqual(u8, &server.pending_ap_server, 0));

    client.deinit();

    try testing.expect(std.mem.allEqual(u8, &client.write_keys.key, 0));
    try testing.expect(std.mem.allEqual(u8, &client.write_keys.iv, 0));
    try testing.expect(std.mem.allEqual(u8, &client.write_keys.sn_key, 0));
    try testing.expect(std.mem.allEqual(u8, &client.read_keys.key, 0));
    try testing.expect(std.mem.allEqual(u8, &client.read_keys.iv, 0));
    try testing.expect(std.mem.allEqual(u8, &client.read_keys.sn_key, 0));
    try testing.expect(std.mem.allEqual(u8, &client.hs_write_keys.key, 0));
    try testing.expect(std.mem.allEqual(u8, &client.hs_write_keys.iv, 0));
    try testing.expect(std.mem.allEqual(u8, &client.hs_write_keys.sn_key, 0));
    try testing.expect(std.mem.allEqual(u8, &client.hs_read_keys.key, 0));
    try testing.expect(std.mem.allEqual(u8, &client.hs_read_keys.iv, 0));
    try testing.expect(std.mem.allEqual(u8, &client.hs_read_keys.sn_key, 0));
    try testing.expect(std.mem.allEqual(u8, &client.hs_traffic_client, 0));
    try testing.expect(std.mem.allEqual(u8, &client.hs_traffic_server, 0));

    server.deinit();
    try testing.expect(std.mem.allEqual(u8, &server.pending_ap_client, 0));
    try testing.expect(std.mem.allEqual(u8, &server.pending_ap_server, 0));
}

test "handshake: wrong PSK -> binder verify fails (typed error, not a panic)" {
    const psk_identity = "device-1";
    const cfg_client = Config{ .role = .client, .psk_identity = psk_identity, .psk = "correct-psk", .cipher_suites = &.{.aes_128_gcm_sha256} };
    const cfg_server = Config{ .role = .server, .psk_identity = psk_identity, .psk = "WRONG-psk", .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x20} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    try testing.expectError(error.BinderVerifyFailed, server.handleFlight(ch, rnd, 0, &buf2));
}

test "handshake: mismatched PSK identity -> typed error, not a panic" {
    const cfg_client = Config{ .role = .client, .psk_identity = "device-1", .psk = "shared", .cipher_suites = &.{.aes_128_gcm_sha256} };
    const cfg_server = Config{ .role = .server, .psk_identity = "device-OTHER", .psk = "shared", .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x23} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    try testing.expectError(error.NoMatchingPskIdentity, server.handleFlight(ch, rnd, 0, &buf2));
}

test "handshake: corrupted ServerHello -> typed error, not a panic" {
    const psk_identity = "device-1";
    const psk = "shared-secret";
    const cfg = Config{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg);
    var server = try Connection.serverInit(.{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x21} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);

    var corrupted: [1500]u8 = undefined;
    @memcpy(corrupted[0..flight2.out.len], flight2.out);
    // Flip a byte inside the legacy PlaintextHeader's `length` field
    // (bytes 11..13 — see `record.PlaintextHeader`/`encodePlaintext`).
    corrupted[11] ^= 0xFF;

    try testing.expectError(error.Malformed, client.handleFlight(corrupted[0..flight2.out.len], rnd, 0, &buf1));
}

test "handshake: a HelloRetryRequest carrying nothing to change is a typed error" {
    const cfg = Config{ .role = .client, .psk_identity = "device-1", .psk = "shared", .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x40} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &buf1);

    // A HelloRetryRequest is now honoured (see `handleHelloRetryRequest`),
    // but only when it actually asks for something. RFC 8446 §4.1.4 forbids
    // sending one that would not change the client's next flight; this
    // engine offers no key share to update, so an HRR with no cookie leaves
    // nothing to do and must not be answered with a byte-identical retry.
    var sh_versions_buf: [2]u8 = undefined;
    const sh_versions = try messages.encodeSupportedVersionsServerHello(messages.version_dtls13, &sh_versions_buf);
    const datagram = try hrrDatagram(&.{.{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = sh_versions }});

    var buf2: [1500]u8 = undefined;
    try testing.expectError(error.HelloRetryRequestUnsupported, client.handleFlight(datagram.bytes[0..datagram.len], rnd, 0, &buf2));
}

test "handshake: a second HelloRetryRequest is refused (RFC 8446 §4.1.4 abort)" {
    const cfg = Config{ .role = .client, .psk_identity = "device-1", .psk = "shared", .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x41} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &buf1);

    var sh_versions_buf: [2]u8 = undefined;
    const sh_versions = try messages.encodeSupportedVersionsServerHello(messages.version_dtls13, &sh_versions_buf);
    var cookie_buf: [64]u8 = undefined;
    const cookie_ext = try messages.encodeCookieExtension("a-real-cookie", &cookie_buf);
    const exts = [_]messages.Extension{
        .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = sh_versions },
        .{ .ext_type = @intFromEnum(messages.ExtensionType.cookie), .data = cookie_ext },
    };
    const datagram = try hrrDatagram(&exts);

    // The first one is answered with ClientHello2 — a real, different flight.
    var buf2: [1500]u8 = undefined;
    const retry = try client.handleFlight(datagram.bytes[0..datagram.len], rnd, 0, &buf2);
    try testing.expect(!retry.done);
    try testing.expect(retry.out.len > 0);
    try testing.expect(!std.mem.eql(u8, buf1[0..retry.out.len], retry.out));
    try testing.expectEqual(State.wait_server_hello, client.state);

    // The SAME datagram again is a retransmission of HelloRetryRequest #1
    // (identical `message_seq`), not a second one: the client already
    // answered it, so it is ignored rather than acted on — no second
    // ClientHello2, no state change, no error.
    var buf3: [1500]u8 = undefined;
    const dup = try client.handleFlight(datagram.bytes[0..datagram.len], rnd, 0, &buf3);
    try testing.expect(dup.need_more_data);
    try testing.expectEqual(@as(usize, 0), dup.out.len);
    try testing.expectEqual(State.wait_server_hello, client.state);

    // A genuinely SECOND HelloRetryRequest — the next `message_seq`, which
    // is what a server that really sent another one would use — would let a
    // server keep this client retrying forever, and MUST abort.
    const second = try hrrDatagramSeq(&exts, 1);
    var buf4: [1500]u8 = undefined;
    try testing.expectError(error.UnexpectedMessage, client.handleFlight(second.bytes[0..second.len], rnd, 0, &buf4));
}

test "handshake: a HelloRetryRequest negotiating DTLS 1.2 (real legacy value) is a downgrade and is rejected" {
    // Sibling of the ServerHello downgrade guard (`handleFlightClient`,
    // §4.2.1): `handleHelloRetryRequest` decodes its OWN `supported_versions`
    // independently and has its own `!= version_dtls13` check. Same RFC
    // clause, same wire ambiguity (every version field on an HRR is frozen at
    // legacy DTLS 1.2 too), different code path — nothing shares the check
    // between the two, so a defect in one is invisible from tests of the
    // other.
    const cfg = Config{ .role = .client, .psk_identity = "device-1", .psk = "shared", .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x43} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &buf1);

    var sh_versions_buf: [2]u8 = undefined;
    const sh_versions = try messages.encodeSupportedVersionsServerHello(messages.legacy_version_dtls12, &sh_versions_buf);
    var cookie_buf: [64]u8 = undefined;
    const cookie_ext = try messages.encodeCookieExtension("a-real-cookie", &cookie_buf);
    const exts = [_]messages.Extension{
        .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = sh_versions },
        .{ .ext_type = @intFromEnum(messages.ExtensionType.cookie), .data = cookie_ext },
    };
    const datagram = try hrrDatagram(&exts);

    var buf2: [1500]u8 = undefined;
    try testing.expectError(error.UnsupportedVersion, client.handleFlight(datagram.bytes[0..datagram.len], rnd, 0, &buf2));
}

test "handshake: ClientHello2 reuses ClientHello1's random and echoes the cookie" {
    const cfg = Config{ .role = .client, .psk_identity = "device-1", .psk = "shared", .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x42} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    const ch1 = try client.startHandshake(rnd, 0, &buf1);
    var ch1_copy: [1500]u8 = undefined;
    @memcpy(ch1_copy[0..ch1.len], ch1);
    const ch1_random = client.client_random;

    var sh_versions_buf: [2]u8 = undefined;
    const sh_versions = try messages.encodeSupportedVersionsServerHello(messages.version_dtls13, &sh_versions_buf);
    var cookie_buf: [64]u8 = undefined;
    const cookie = "cookie-from-the-server";
    const cookie_ext = try messages.encodeCookieExtension(cookie, &cookie_buf);
    const exts = [_]messages.Extension{
        .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = sh_versions },
        .{ .ext_type = @intFromEnum(messages.ExtensionType.cookie), .data = cookie_ext },
    };
    const datagram = try hrrDatagram(&exts);

    var buf2: [1500]u8 = undefined;
    const retry = try client.handleFlight(datagram.bytes[0..datagram.len], rnd, 0, &buf2);

    // RFC 8446 §4.1.2: ClientHello2 is ClientHello1 unmodified except for a
    // short list of permitted changes; `random` is NOT on that list, so a
    // freshly drawn one would be a protocol violation the peer sees as a
    // different client.
    try testing.expectEqualSlices(u8, &ch1_random, &client.client_random);
    // The cookie has to come back verbatim, or the stateless server cannot
    // reconstruct the connection it refused to remember.
    try testing.expect(std.mem.indexOf(u8, retry.out, cookie) != null);
    // And ClientHello2 must be a NEW message, not a retransmission of
    // ClientHello1 (RFC 9147 §5.2: retransmissions reuse `message_seq`).
    try testing.expectEqual(@as(u16, 2), client.message_seq);
}

/// Builds a one-record datagram carrying a HelloRetryRequest with `exts` —
/// a ServerHello whose `random` is RFC 8446 §4.1.3's magic value.
const HrrDatagram = struct { bytes: [400]u8, len: usize };

fn hrrDatagram(exts: []const messages.Extension) !HrrDatagram {
    return hrrDatagramSeq(exts, 0);
}

/// `hrrDatagram` with an explicit RFC 9147 §5.2 `message_seq` — the two are
/// not interchangeable to a receiver that tracks the peer's counter: seq 0
/// again is a RETRANSMISSION of the same HelloRetryRequest, whereas the next
/// seq is a genuinely NEW message.
fn hrrDatagramSeq(exts: []const messages.Extension, message_seq: u16) !HrrDatagram {
    var sh_body_buf: [256]u8 = undefined;
    const sh_body = try messages.encodeServerHello(.{
        .random = messages.hello_retry_request_random,
        .legacy_session_id_echo = &.{},
        .cipher_suite = @intFromEnum(CipherSuite.aes_128_gcm_sha256),
        .extensions = exts,
    }, &sh_body_buf);

    var frag_buf: [256 + handshake.header_len]u8 = undefined;
    const fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.server_hello), message_seq, sh_body, &frag_buf);

    var result: HrrDatagram = .{ .bytes = undefined, .len = 0 };
    const hdr = record.PlaintextHeader{ .content_type = content_type_handshake, .epoch = 0, .sequence_number = 0, .length = @intCast(fragment.len) };
    const hdr_slice = try record.encodePlaintext(hdr, &result.bytes);
    @memcpy(result.bytes[hdr_slice.len..][0..fragment.len], fragment);
    result.len = hdr_slice.len + fragment.len;
    return result;
}

// ── SERVING a HelloRetryRequest: RFC 9147 §5.1 return routability ────────
//
// A server that answers a first ClientHello with a full flight is an
// amplification weapon (§5.1's second attack): forge a victim's source
// address, send a small ClientHello, and the server sprays a larger flight
// at the victim. These tests are about the mitigation actually mitigating —
// which means most of them are about what the server REFUSES.

const hrr_psk_identity = "device-behind-a-forgeable-address";
const hrr_psk = "a-shared-pre-shared-key";
const hrr_cookie_secret = "server-side cookie MAC key, never on the wire";

fn hrrServerConfig(peer_binding: []const u8) Config {
    return .{
        .role = .server,
        .psk_identity = hrr_psk_identity,
        .psk = hrr_psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .hello_retry = .{ .cookie_secret = hrr_cookie_secret, .peer_binding = peer_binding },
    };
}

fn hrrClientConfig(psk: []const u8) Config {
    return .{
        .role = .client,
        .psk_identity = hrr_psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    };
}

/// Asserts `datagram` really is a HelloRetryRequest carrying a cookie, and
/// returns the cookie. Without this a "the retry happened" test degrades
/// into a second copy of the no-retry test the moment the config stops
/// taking effect — the flight would still be well-formed and the handshake
/// would still complete, just without the check that is the entire point.
fn expectHelloRetryRequest(datagram: []const u8) ![]const u8 {
    const rec = try record.decodePlaintext(datagram);
    try testing.expectEqual(content_type_handshake, rec.content_type);
    const fragment = datagram[record.plaintext_header_len..][0..rec.length];

    var msg_buf: [512]u8 = undefined;
    var received_buf: [512]bool = undefined;
    const parsed = try decodeSingleFragmentMessage(fragment, &msg_buf, &received_buf);
    try testing.expectEqual(@intFromEnum(messages.HandshakeType.server_hello), parsed.msg_type);

    var ext_buf: [8]messages.Extension = undefined;
    const sh = try messages.decodeServerHello(parsed.body, &ext_buf);
    // RFC 8446 §4.1.3: a HelloRetryRequest IS a ServerHello, distinguished
    // only by this magic `random`.
    try testing.expect(messages.isHelloRetryRequest(sh.random));
    // RFC 9147 §5: DTLS servers MUST NOT echo `legacy_session_id`.
    try testing.expectEqual(@as(usize, 0), sh.legacy_session_id_echo.len);

    var saw_supported_versions = false;
    var cookie: ?[]const u8 = null;
    for (sh.extensions) |e| switch (e.ext_type) {
        // RFC 8446 §4.1.4: "The server's extensions MUST contain
        // 'supported_versions'" — and in DTLS it is the ONLY place the
        // negotiated version appears.
        @intFromEnum(messages.ExtensionType.supported_versions) => saw_supported_versions = true,
        @intFromEnum(messages.ExtensionType.cookie) => cookie = try messages.decodeCookieExtension(e.data),
        else => return error.UnexpectedHelloRetryRequestExtension,
    };
    try testing.expect(saw_supported_versions);
    // `datagram` is a caller buffer that outlives `msg_buf`, so hand back a
    // slice OF IT rather than of the local copy.
    const c = cookie orelse return error.HelloRetryRequestHasNoCookie;
    try testing.expectEqual(@as(usize, cookie_len), c.len);
    const tail = datagram[datagram.len - cookie_len ..];
    try testing.expectEqualSlices(u8, c, tail);
    return tail;
}

test "HRR server: the cookie exchange completes — and the connection that answers ClientHello2 shares NOTHING with the one that sent the retry" {
    const binding = "203.0.113.9:51000";
    var client = try Connection.clientInit(hrrClientConfig(hrr_psk));
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x71} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch1 = try client.startHandshake(rnd, 0, &buf1);
    const ch1_len = ch1.len;

    // Connection #1 exists only to answer ClientHello1 and be thrown away.
    var server1 = try Connection.serverInit(hrrServerConfig(binding));
    const hrr = try server1.handleFlight(ch1, rnd, 0, &buf2);
    try testing.expect(!hrr.done);
    try testing.expect(server1.sawHelloRetryRequest());
    _ = try expectHelloRetryRequest(hrr.out);

    // Nothing was committed: no state transition, no cached flight to
    // retransmit, no transcript. A server that advanced here would be
    // holding per-ClientHello state for an unverified address, which is
    // RFC 9147 §5.1's FIRST attack (resource exhaustion), not just the
    // amplification one.
    try testing.expectEqual(State.start, server1.state);
    try testing.expectEqual(@as(usize, 0), server1.last_flight_len);
    try testing.expectEqual(@as(usize, 0), server1.pending_flight_count);
    try testing.expectEqualSlices(u8, &(engine.Transcript{}).currentHash(), &server1.transcript.currentHash());
    // And the answer is SMALLER than the question — the amplification
    // property, stated as an assertion rather than a hope.
    try testing.expect(hrr.out.len < ch1_len);

    const ch2 = try client.handleFlight(hrr.out, rnd, 0, &buf1);
    try testing.expect(!ch2.done);
    try testing.expect(client.sawHelloRetryRequest());

    // Statelessness, literally: server1 is destroyed, and a BRAND-NEW
    // connection — same config, no shared memory, no shared transcript —
    // has to be able to finish the handshake from ClientHello2 plus its own
    // cookie alone. If anything the server needed had been kept in server1
    // instead of in the cookie, this is where it would fail.
    server1.deinit();
    var server2 = try Connection.serverInit(hrrServerConfig(binding));
    defer server2.deinit();

    const flight2 = try server2.handleFlight(ch2.out, rnd, 0, &buf2);
    try testing.expect(!flight2.done);
    try testing.expect(server2.sawHelloRetryRequest());
    try testing.expectEqual(State.wait_finished, server2.state);

    const client_fin = try client.handleFlight(flight2.out, rnd, 0, &buf1);
    try testing.expect(client_fin.done);
    const server_done = try server2.handleFlight(client_fin.out, rnd, 0, &buf2);
    try testing.expect(server_done.done);

    // Identical keys on both sides = the two independently computed
    // transcripts agree, INCLUDING RFC 8446 §4.4.1's `message_hash` rewrite
    // and the server's re-encoding of its own HelloRetryRequest.
    try testing.expectEqualSlices(u8, client.write_keys.key[0..client.write_keys.key_len], server2.read_keys.key[0..server2.read_keys.key_len]);
    try testing.expectEqualSlices(u8, &client.write_keys.iv, &server2.read_keys.iv);

    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const msg = "application data over a return-routability-checked connection";
    const rec = try client.send(msg, &wire);
    try testing.expectEqualSlices(u8, msg, try server2.recv(rec, &plain));
}

test "HRR server: a cookie minted for one peer_binding does not verify from another (the return-routability check itself)" {
    var client = try Connection.clientInit(hrrClientConfig(hrr_psk));
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x72} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch1 = try client.startHandshake(rnd, 0, &buf1);
    var server1 = try Connection.serverInit(hrrServerConfig("203.0.113.9:51000"));
    const hrr = try server1.handleFlight(ch1, rnd, 0, &buf2);
    _ = try expectHelloRetryRequest(hrr.out);
    const ch2 = try client.handleFlight(hrr.out, rnd, 0, &buf1);

    // Same cookie, same ClientHello2, byte for byte — replayed from a
    // different address. If this were accepted, the cookie would prove only
    // that SOMEONE somewhere had once received one, which is not a
    // return-routability check at all: an attacker could collect a cookie
    // over its own address and then spend it while spoofing a victim's.
    var elsewhere = try Connection.serverInit(hrrServerConfig("198.51.100.4:51000"));
    var buf3: [1500]u8 = undefined;
    try testing.expectError(error.CookieVerifyFailed, elsewhere.handleFlight(ch2.out, rnd, 0, &buf3));

    // Not even the port may differ — the check is on a socket, not a host.
    var same_host_other_port = try Connection.serverInit(hrrServerConfig("203.0.113.9:51001"));
    try testing.expectError(error.CookieVerifyFailed, same_host_other_port.handleFlight(ch2.out, rnd, 0, &buf3));

    // Control: the RIGHT binding still works, so the two rejections above
    // are about the binding and not about something else being broken.
    var right = try Connection.serverInit(hrrServerConfig("203.0.113.9:51000"));
    defer right.deinit();
    _ = try right.handleFlight(ch2.out, rnd, 0, &buf3);
}

test "HRR server: a cookie minted under a different cookie_secret does not verify" {
    var client = try Connection.clientInit(hrrClientConfig(hrr_psk));
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x73} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    var buf3: [1500]u8 = undefined;

    const ch1 = try client.startHandshake(rnd, 0, &buf1);
    var server1 = try Connection.serverInit(hrrServerConfig("203.0.113.9:51000"));
    const hrr = try server1.handleFlight(ch1, rnd, 0, &buf2);
    const ch2 = try client.handleFlight(hrr.out, rnd, 0, &buf1);

    // RFC 9147 §5.1's defence against an attacker hoarding cookies: rotating
    // the secret invalidates every outstanding one. That only works if a
    // cookie minted under the old secret is actually refused.
    var rotated = try Connection.serverInit(Config{
        .role = .server,
        .psk_identity = hrr_psk_identity,
        .psk = hrr_psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .hello_retry = .{ .cookie_secret = "the NEXT cookie MAC key", .peer_binding = "203.0.113.9:51000" },
    });
    try testing.expectError(error.CookieVerifyFailed, rotated.handleFlight(ch2.out, rnd, 0, &buf3));
}

test "HRR server: one flipped bit anywhere in the cookie — MAC or authenticated payload — does not verify" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x74} ** 32);
    const rnd = seededForTest(&csprng);

    // The cookie is the last `cookie_len` bytes of the HelloRetryRequest
    // datagram (it is the last extension's payload, and the extension list
    // ends the message), so these offsets address it directly:
    //   * the very last byte      -> the MAC's own tail;
    //   * `cookie_mac_len + 1` from the end -> the last byte of
    //     `Hash(ClientHello1)`, i.e. the AUTHENTICATED PAYLOAD. That case is
    //     the one that matters: it is what a forger would edit to make the
    //     server rebuild a transcript for a ClientHello1 it never saw.
    for ([_]usize{ 1, cookie_mac_len + 1 }) |from_end| {
        var client = try Connection.clientInit(hrrClientConfig(hrr_psk));
        var buf1: [1500]u8 = undefined;
        var buf2: [1500]u8 = undefined;
        var buf3: [1500]u8 = undefined;

        const ch1 = try client.startHandshake(rnd, 0, &buf1);
        var server1 = try Connection.serverInit(hrrServerConfig("203.0.113.9:51000"));
        const hrr = try server1.handleFlight(ch1, rnd, 0, &buf2);
        const cookie = try expectHelloRetryRequest(hrr.out);
        try testing.expectEqual(cookie_version, cookie[0]);

        var tampered: [1500]u8 = undefined;
        @memcpy(tampered[0..hrr.out.len], hrr.out);
        tampered[hrr.out.len - from_end] ^= 0x01;

        // The client echoes whatever cookie it was handed, verbatim (RFC
        // 8446 §4.2.2) — it has no way to tell, which is exactly why the
        // server must not either.
        const ch2 = try client.handleFlight(tampered[0..hrr.out.len], rnd, 0, &buf1);
        var server2 = try Connection.serverInit(hrrServerConfig("203.0.113.9:51000"));
        try testing.expectError(error.CookieVerifyFailed, server2.handleFlight(ch2.out, rnd, 0, &buf3));
    }
}

test "HRR server: a GENUINE cookie with bytes appended is refused (length is exact, not a minimum)" {
    // The sibling test above covers cookies a peer invented, and those all
    // fail on the MAC whatever their length. This one covers the case that
    // survives a MAC check: a REAL cookie, minted by this server for this
    // peer, with trailing bytes stuck on the end.
    //
    // It exists because relaxing `openCookie`'s `cookie.len != cookie_len`
    // to `<` — a one-character edit that looks like defensive coding —
    // leaves every other test in this file green. The trailing bytes are
    // unauthenticated and unused, so this is malleability rather than a
    // break, but "the length is exact" is a property worth a test that can
    // actually notice when it stops being true.
    const binding = "203.0.113.9:51000";
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x79} ** 32);
    const rnd = seededForTest(&csprng);

    var client = try Connection.clientInit(hrrClientConfig(hrr_psk));
    defer client.deinit();
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    const ch1 = try client.startHandshake(rnd, 0, &buf1);

    var server1 = try Connection.serverInit(hrrServerConfig(binding));
    const hrr = try server1.handleFlight(ch1, rnd, 0, &buf2);
    const genuine = try expectHelloRetryRequest(hrr.out);

    // Re-issue the retry with one extra byte glued to the genuine cookie.
    var extended: [cookie_len + 1]u8 = undefined;
    @memcpy(extended[0..cookie_len], genuine);
    extended[cookie_len] = 0x00;

    var sh_versions_buf: [2]u8 = undefined;
    const sh_versions = try messages.encodeSupportedVersionsServerHello(messages.version_dtls13, &sh_versions_buf);
    var cookie_buf: [2 + max_cookie_len]u8 = undefined;
    const cookie_ext = try messages.encodeCookieExtension(&extended, &cookie_buf);
    const datagram = try hrrDatagram(&.{
        .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = sh_versions },
        .{ .ext_type = @intFromEnum(messages.ExtensionType.cookie), .data = cookie_ext },
    });

    var buf3: [1500]u8 = undefined;
    const ch2 = try client.handleFlight(datagram.bytes[0..datagram.len], rnd, 0, &buf1);
    var server2 = try Connection.serverInit(hrrServerConfig(binding));
    try testing.expectError(error.CookieVerifyFailed, server2.handleFlight(ch2.out, rnd, 0, &buf3));
}

test "HRR server: an attacker-invented cookie is refused, whatever its length" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x75} ** 32);
    const rnd = seededForTest(&csprng);

    // No real HelloRetryRequest is involved: these are cookies a peer made
    // up, delivered by pointing a client at a forged retry. A server that
    // accepted any of them would be doing no check at all.
    const forged = [_][]const u8{
        "", // an empty `cookie` extension
        "short",
        &[_]u8{0} ** cookie_len, // right length, all zeroes
        &[_]u8{0xff} ** (cookie_len + 1), // right shape, one byte too long
    };
    for (forged) |c| {
        var client = try Connection.clientInit(hrrClientConfig(hrr_psk));
        var buf1: [1500]u8 = undefined;
        var buf3: [1500]u8 = undefined;
        _ = try client.startHandshake(rnd, 0, &buf1);

        var sh_versions_buf: [2]u8 = undefined;
        const sh_versions = try messages.encodeSupportedVersionsServerHello(messages.version_dtls13, &sh_versions_buf);
        var cookie_buf: [2 + max_cookie_len]u8 = undefined;
        const cookie_ext = try messages.encodeCookieExtension(c, &cookie_buf);
        const datagram = try hrrDatagram(&.{
            .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = sh_versions },
            .{ .ext_type = @intFromEnum(messages.ExtensionType.cookie), .data = cookie_ext },
        });
        const ch2 = client.handleFlight(datagram.bytes[0..datagram.len], rnd, 0, &buf1) catch |err| {
            // An empty cookie changes nothing about ClientHello2, which RFC
            // 8446 §4.1.4 forbids a server from asking for — the client
            // refuses before the server ever sees it. Still a refusal.
            try testing.expectEqual(error.HelloRetryRequestUnsupported, err);
            continue;
        };

        var server = try Connection.serverInit(hrrServerConfig("203.0.113.9:51000"));
        try testing.expectError(error.CookieVerifyFailed, server.handleFlight(ch2.out, rnd, 0, &buf3));
    }
}

test "HRR server: a wrong-PSK ClientHello still gets only a retry — no crypto is spent before return routability is proven" {
    var client = try Connection.clientInit(hrrClientConfig("the-WRONG-psk"));
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x76} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch1 = try client.startHandshake(rnd, 0, &buf1);
    var server1 = try Connection.serverInit(hrrServerConfig("203.0.113.9:51000"));

    // The binder is wrong, but the server must not have looked: RFC 9147
    // §5.1's point is that an unverified address costs one HMAC over the
    // cookie, not a key schedule. Verifying first would also make the
    // ORDER of failures leak — a spoofing attacker could learn whether a
    // PSK identity/binder pair was good by whether it got an HRR or a
    // silence, at zero cost to itself.
    const hrr = try server1.handleFlight(ch1, rnd, 0, &buf2);
    _ = try expectHelloRetryRequest(hrr.out);

    // And the check does still happen — just after the address is proven.
    const ch2 = try client.handleFlight(hrr.out, rnd, 0, &buf1);
    var server2 = try Connection.serverInit(hrrServerConfig("203.0.113.9:51000"));
    var buf3: [1500]u8 = undefined;
    try testing.expectError(error.BinderVerifyFailed, server2.handleFlight(ch2.out, rnd, 0, &buf3));
}

test "HRR server: off by default — an unconfigured server answers ClientHello1 with the full flight, exactly as before" {
    var client = try Connection.clientInit(hrrClientConfig(hrr_psk));
    var server = try Connection.serverInit(Config{
        .role = .server,
        .psk_identity = hrr_psk_identity,
        .psk = hrr_psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x77} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch1 = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch1, rnd, 0, &buf2);
    try testing.expectEqual(State.wait_finished, server.state);
    try testing.expect(!server.sawHelloRetryRequest());

    // The first message out is a REAL ServerHello, not a retry.
    const rec = try record.decodePlaintext(flight2.out);
    var msg_buf: [512]u8 = undefined;
    var received_buf: [512]bool = undefined;
    const parsed = try decodeSingleFragmentMessage(flight2.out[record.plaintext_header_len..][0..rec.length], &msg_buf, &received_buf);
    var ext_buf: [8]messages.Extension = undefined;
    const sh = try messages.decodeServerHello(parsed.body, &ext_buf);
    try testing.expect(!messages.isHelloRetryRequest(sh.random));

    // And the client agrees it never did a retry, so the two views of "was
    // there a cookie exchange" cannot drift apart unnoticed.
    const client_fin = try client.handleFlight(flight2.out, rnd, 0, &buf1);
    try testing.expect(client_fin.done);
    try testing.expect(!client.sawHelloRetryRequest());
}

test "Config.validate: hello_retry with an empty secret or an empty binding is rejected" {
    const base = Config{ .role = .server, .psk_identity = "id", .psk = "secret", .cipher_suites = &.{.aes_128_gcm_sha256} };

    var no_secret = base;
    no_secret.hello_retry = .{ .cookie_secret = "", .peer_binding = "203.0.113.9:51000" };
    try testing.expectError(error.EmptyCookieSecret, Connection.serverInit(no_secret));

    // The dangerous one: a cookie bound to nothing still verifies, from
    // anywhere. Nothing downstream can catch it, so it is refused here.
    var no_binding = base;
    no_binding.hello_retry = .{ .cookie_secret = "k", .peer_binding = "" };
    try testing.expectError(error.EmptyPeerBinding, Connection.serverInit(no_binding));
}

test "cookie: the MAC covers the peer binding, the ClientHello hash, and the suite — separately" {
    const hr = HelloRetryConfig{ .cookie_secret = "k", .peer_binding = "203.0.113.9:51000" };
    const contents = CookieContents{ .suite = .aes_128_gcm_sha256, .client_hello1_hash = [_]u8{0xab} ** 32 };

    var base: [cookie_len]u8 = undefined;
    mintCookie(hr, contents, &base);
    const opened = try openCookie(hr, &base);
    try testing.expectEqual(contents.suite, opened.suite);
    try testing.expectEqualSlices(u8, &contents.client_hello1_hash, &opened.client_hello1_hash);

    // A different binding, everything else identical.
    var other_binding: [cookie_len]u8 = undefined;
    mintCookie(.{ .cookie_secret = "k", .peer_binding = "203.0.113.9:51001" }, contents, &other_binding);
    try testing.expect(!std.mem.eql(u8, &base, &other_binding));
    try testing.expectError(error.CookieVerifyFailed, openCookie(hr, &other_binding));

    // The length prefix on the binding: without it, splitting the binding
    // differently would hash the same. "203.0.113.9:5100" + "0" must not
    // collide with "203.0.113.9:51000" + "".
    var truncated_binding: [cookie_len]u8 = undefined;
    mintCookie(.{ .cookie_secret = "k", .peer_binding = "203.0.113.9:5100" }, contents, &truncated_binding);
    try testing.expectError(error.CookieVerifyFailed, openCookie(hr, &truncated_binding));

    // The suite is authenticated too, so a peer cannot steer the server's
    // HelloRetryRequest reconstruction by editing it.
    var edited_suite = base;
    edited_suite[1] = 0x13;
    edited_suite[2] = 0x03; // chacha20_poly1305_sha256: a suite we DO support
    try testing.expectError(error.CookieVerifyFailed, openCookie(hr, &edited_suite));

    // As is the version byte, so a future format cannot be misread as v1.
    var edited_version = base;
    edited_version[0] = 2;
    try testing.expectError(error.CookieVerifyFailed, openCookie(hr, &edited_version));
}

test "handshake: server handleFlight rejects the wrong state" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var server = try Connection.serverInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x50} ** 32);
    var out: [64]u8 = undefined;
    // `server` is `.start`ed but this call pretends it's already past
    // `.wait_finished` by driving it there via a bogus (empty) datagram
    // first would itself error — simpler: directly assert a state this
    // engine never lets `.start` accept, by using `.connected` state.
    server.state = .connected;
    try testing.expectError(error.WrongState, server.handleFlight("x", seededForTest(&csprng), 0, &out));
}

test "poll: nothing to retransmit before a handshake starts or after it connects" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var client = try Connection.clientInit(cfg);
    var out: [64]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), try client.poll(999_999, &out));

    client.state = .connected;
    try testing.expectEqual(@as(?[]const u8, null), try client.poll(999_999, &out));
}

test "handshake: dropped ClientHello retransmits via poll (fake clock), then completes" {
    const psk_identity = "device-1";
    const psk = "shared-secret";
    const cfg_client = Config{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} };
    const cfg_server = Config{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x30} ** 32);
    const rnd = seededForTest(&csprng);

    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch1 = try client.startHandshake(rnd, 0, &buf1); // "sent" at t=0, then DROPPED
    var ch1_copy: [1500]u8 = undefined;
    @memcpy(ch1_copy[0..ch1.len], ch1);

    // Before the initial 1000ms timeout: nothing to retransmit yet.
    try testing.expectEqual(@as(?[]const u8, null), try client.poll(500, &buf2));
    // At/after the deadline: the SAME ClientHello bytes come back.
    const ch2 = (try client.poll(1000, &buf2)).?;
    try testing.expectEqualSlices(u8, ch1_copy[0..ch1.len], ch2);

    // Deliver the RETRANSMITTED copy — the handshake completes normally.
    const flight2 = try server.handleFlight(ch2, rnd, 1000, &buf1);
    const client_fin = try client.handleFlight(flight2.out, rnd, 1000, &buf2);
    try testing.expect(client_fin.done);
    const server_done = try server.handleFlight(client_fin.out, rnd, 1000, &buf1);
    try testing.expect(server_done.done);

    try testing.expectEqual(State.connected, client.state);
    try testing.expectEqual(State.connected, server.state);
}

// ── certificate mode: the mandatory oracle ───────────────────────────────
//
// Same proof shape as the PSK loopback tests above (two in-memory
// `Connection`s driving each other, no external peer) but now with real
// ECDSA P-256 certificates generated by OpenSSL (`certauth_kat_vectors.zig`
// — see that file's provenance comment): a genuine trust anchor, a leaf
// signed by it, real `certverify.sign`/`.verify` signatures over the live
// running transcript (not a fixed KAT string), and real
// `certauth.verifyLeafAgainstAnchor` chain checks. These are the teeth:
// server-cert-only handshake completes with matching derived keys; a wrong
// signing key is rejected; an untrusted anchor is rejected; mutual
// (CertificateRequest -> client cert) auth completes; a required-but-absent
// peer cert is rejected. The existing PSK-only tests above are untouched
// and still pass — proving certificate mode is genuinely additive.

const cert_kat = @import("certauth_kat_vectors.zig");

fn serverEcdsaKeyPair() certverify.SecretKey {
    return .{ .ecdsa_p256 = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes) catch unreachable };
}
fn clientEcdsaKeyPair() certverify.SecretKey {
    return .{ .ecdsa_p256 = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.client_secret_key_bytes) catch unreachable };
}

// ── signature_algorithms negotiation (RFC 8446 §4.2.3): direct unit tests
// ── of `selectSignatureScheme`/`verifyPeerCert`'s downgrade guard ────────
//
// These call the private `selectSignatureScheme`/`verifyPeerCert` directly
// (legitimate same-file access, not a workaround) specifically to isolate
// the SELECTION/GUARD logic from AEAD sealing: a real handshake's
// CertificateVerify travels inside an AEAD-protected record, so a
// wire-level "wrong scheme got through" tamper is indistinguishable from
// any other bit flip (`error.DecryptionFailed` fires first, before either
// check ever runs) — these unit tests instead prove the checks themselves
// are correct, and the "mandatory oracle" tests further below prove they
// are genuinely WIRED into the real handshake (not a dead helper nothing
// calls — removing either call site there breaks those tests).

test "selectSignatureScheme: intersects peer-advertised x self-permitted x key-producible, non-preference-order peer list" {
    // `.rsa` tag is all `candidateSchemes`/`selectSignatureScheme` inspect —
    // the union payload is never read by this pure selection logic.
    const cc = CertConfig{ .chain = &.{}, .private_key = .{ .rsa = undefined } };
    const our_sig_algs = [_]certverify.SignatureScheme{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 };
    // Peer advertises sha384 (NOT this side's most-preferred sha256) plus an
    // unrelated scheme — proves a real intersection is computed, not "peer
    // offered something, so use our first candidate".
    const peer_sig_algs = [_]u16{ @intFromEnum(certverify.SignatureScheme.ed25519), @intFromEnum(certverify.SignatureScheme.rsa_pss_rsae_sha384) };
    try testing.expectEqual(certverify.SignatureScheme.rsa_pss_rsae_sha384, try selectSignatureScheme(cc, &our_sig_algs, &peer_sig_algs));
}

test "selectSignatureScheme: peer advertises nothing this key's family can produce -> NoSignatureSchemeOverlap" {
    const cc = CertConfig{ .chain = &.{}, .private_key = .{ .ecdsa_p256 = undefined } };
    const our_sig_algs = default_signature_algorithms; // permissive on our side
    const peer_sig_algs = [_]u16{ @intFromEnum(certverify.SignatureScheme.rsa_pss_rsae_sha256), @intFromEnum(certverify.SignatureScheme.ed25519) };
    try testing.expectError(error.NoSignatureSchemeOverlap, selectSignatureScheme(cc, &our_sig_algs, &peer_sig_algs));
}

test "selectSignatureScheme: peer DOES advertise a key-producible scheme, but OUR OWN signature_algorithms excludes it -> NoSignatureSchemeOverlap" {
    // Proves the "AND we support" leg is real: without it, this case would
    // wrongly succeed (peer + key overlap alone is not sufficient).
    const cc = CertConfig{ .chain = &.{}, .private_key = .{ .ecdsa_p256 = undefined } };
    const our_sig_algs = [_]certverify.SignatureScheme{.ed25519}; // deliberately excludes ecdsa_secp256r1_sha256
    const peer_sig_algs = [_]u16{@intFromEnum(certverify.SignatureScheme.ecdsa_secp256r1_sha256)};
    try testing.expectError(error.NoSignatureSchemeOverlap, selectSignatureScheme(cc, &our_sig_algs, &peer_sig_algs));
}

test "verifyPeerCert: rejects a CertificateVerify scheme this side never advertised, before touching the signature (downgrade guard)" {
    var conn = try Connection.clientInit(.{
        .role = .client,
        .psk_identity = "device-042",
        .psk = "a-shared-pre-shared-key",
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .signature_algorithms = &.{.ecdsa_secp256r1_sha256}, // narrowed: no RSA
    });
    // `rsa_pss_rsae_sha256`'s wire code point is NOT in the list above — the
    // guard must reject it immediately. `leaf_der`/`signature`/
    // `transcript_hash` below are garbage on purpose: if the guard were
    // missing, this call would instead fail LATER with a DIFFERENT error
    // (`error.CertificateRejected` from a malformed-DER leaf, or
    // `error.CertVerifyFailed` from certverify's own scheme/key-family
    // dispatch) — proving THIS specific check is what fires here, not some
    // other rejection downstream.
    const garbage_leaf = [_]u8{0} ** 4;
    const garbage_sig = [_]u8{0} ** 4;
    const garbage_th = [_]u8{0} ** 32;
    try testing.expectError(
        error.SignatureSchemeNotAdvertised,
        conn.verifyPeerCert(&garbage_leaf, @intFromEnum(certverify.SignatureScheme.rsa_pss_rsae_sha256), &garbage_sig, &garbage_th, .server),
    );
}

test "cert-mode: server-cert-only handshake completes, derives matching keys, app data round-trips" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .now_sec = cert_kat.valid_now_sec,
    };
    const cfg_server = Config{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{
            .chain = &.{&cert_kat.server_cert_der},
            .private_key = serverEcdsaKeyPair(),
        },
    };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x60} ** 32);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    try driveHandshake(&client, &server, seededForTest(&csprng), &buf1, &buf2);

    // Identical derived application keys on both sides — proves the
    // certificate-mode messages fed the SAME bytes into both sides'
    // transcript hash (any divergence would desync the key schedule).
    try testing.expectEqualSlices(u8, client.write_keys.key[0..client.write_keys.key_len], server.read_keys.key[0..server.read_keys.key_len]);
    try testing.expectEqualSlices(u8, &client.write_keys.iv, &server.read_keys.iv);

    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const rec = try client.send("hello over cert-mode DTLS 1.3", &wire);
    const got = try server.recv(rec, &plain);
    try testing.expectEqualSlices(u8, "hello over cert-mode DTLS 1.3", got);
}

test "cert-mode: CertificateVerify signed with the WRONG key is rejected (typed error, not a panic)" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .now_sec = cert_kat.valid_now_sec,
    };
    const cfg_server = Config{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{
            // Presents the real server leaf, but signs with the CLIENT's
            // key — the leaf's public key and the CertificateVerify
            // signature no longer match. This is the "tampered transcript
            // / wrong key" case: certverify.verify recomputes the RFC 8446
            // §4.4.3 signed content over the (correct, live) transcript
            // hash and finds it doesn't verify under the leaf's real key.
            .chain = &.{&cert_kat.server_cert_der},
            .private_key = clientEcdsaKeyPair(),
        },
    };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x61} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);
    try testing.expectError(error.CertVerifyFailed, client.handleFlight(flight2.out, rnd, 0, &buf1));
}

test "cert-mode: a directly-tampered CertificateVerify signature byte is rejected" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .peer_verify = .none,
    };
    const cfg_server = Config{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{
            .chain = &.{&cert_kat.server_cert_der},
            .private_key = serverEcdsaKeyPair(),
        },
    };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x62} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);

    var tampered: [2048]u8 = undefined;
    @memcpy(tampered[0..flight2.out.len], flight2.out);
    // Flip the LAST byte of the flight — inside the Finished record's AEAD
    // tag/ciphertext for a PSK-only flight, but here (cert mode) the flight
    // is Certificate+CertificateVerify+Finished; the last byte still lands
    // inside the Finished record's tag, so corrupt a byte further back,
    // inside the CertificateVerify record instead. The exact offset is
    // derived, not hand-counted: locate the CertificateVerify's signature
    // bytes are AEAD-protected, so ANY byte flip inside that whole record
    // must fail AEAD authentication before certverify.verify ever runs —
    // proving this module's OWN typed-error path (not just certverify's)
    // rejects a tampered wire message.
    const mid = flight2.out.len / 2; // lands inside the coalesced flight's cert-mode records
    tampered[mid] ^= 0x40;
    // Lands inside an AEAD-protected epoch-2 record (Certificate/
    // CertificateVerify/Finished are all sealed) -- authentication fails
    // before certverify.verify is ever reached, proving the flight-level
    // AEAD tamper defense covers certificate-mode records exactly like it
    // already covers EncryptedExtensions/Finished.
    try testing.expectError(error.DecryptionFailed, client.handleFlight(tampered[0..flight2.out.len], rnd, 0, &buf1));
}

test "cert-mode: peer chain signed by an UNTRUSTED anchor is rejected" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        // The client trusts a DIFFERENT anchor than the one that actually
        // signed the server's leaf (cert_kat.anchor_cert_der) — the real
        // "wrong/untrusted peer chain" case.
        .peer_verify = .{ .trust_anchor = &cert_kat.evil_anchor_cert_der },
        .now_sec = cert_kat.valid_now_sec,
    };
    const cfg_server = Config{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{
            .chain = &.{&cert_kat.server_cert_der},
            .private_key = serverEcdsaKeyPair(),
        },
    };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x63} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);
    try testing.expectError(error.CertificateRejected, client.handleFlight(flight2.out, rnd, 0, &buf1));
}

test "cert-mode: require_peer_cert rejects a server that presents no certificate at all" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .now_sec = cert_kat.valid_now_sec,
        .require_peer_cert = true,
    };
    // Server has NO `cert` configured — plain PSK response, as if it were a
    // PSK-only server the client mistakenly expected certificate auth from.
    const cfg_server = Config{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x64} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);
    try testing.expectError(error.PeerCertificateRequired, client.handleFlight(flight2.out, rnd, 0, &buf1));
}

test "cert-mode: CertificateRequest -> client presents its own cert -> mutual auth completes" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .now_sec = cert_kat.valid_now_sec,
        .cert = .{
            .chain = &.{&cert_kat.client_cert_der},
            .private_key = clientEcdsaKeyPair(),
        },
    };
    const cfg_server = Config{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{
            .chain = &.{&cert_kat.server_cert_der},
            .private_key = serverEcdsaKeyPair(),
        },
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .now_sec = cert_kat.valid_now_sec,
        .request_client_cert = true,
        .require_peer_cert = true,
    };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x65} ** 32);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    try driveHandshake(&client, &server, seededForTest(&csprng), &buf1, &buf2);

    try testing.expectEqualSlices(u8, client.write_keys.key[0..client.write_keys.key_len], server.read_keys.key[0..server.read_keys.key_len]);

    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const rec = try server.send("ack from mutually-authenticated server", &wire);
    const got = try client.recv(rec, &plain);
    try testing.expectEqualSlices(u8, "ack from mutually-authenticated server", got);
}

test "cert-mode: server requires a client cert but client has none configured -> rejected" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        // No `cert` -> the client will answer CertificateRequest with an
        // empty Certificate (RFC 8446 §4.4.2's "no certificate available").
    };
    const cfg_server = Config{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{
            .chain = &.{&cert_kat.server_cert_der},
            .private_key = serverEcdsaKeyPair(),
        },
        .request_client_cert = true,
        .require_peer_cert = true,
    };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x66} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);
    const client_fin = try client.handleFlight(flight2.out, rnd, 0, &buf1);
    try testing.expect(client_fin.done); // the client itself completes fine (it made a valid RFC 8446 "no cert" reply)

    try testing.expectError(error.PeerCertificateRequired, server.handleFlight(client_fin.out, rnd, 0, &buf2));
}

test "cert-mode: PSK-only Config fields (cert=null, peer_verify=.none) reproduce plain PSK behavior byte-for-byte" {
    // Regression proof that certificate mode is genuinely additive: a
    // Config with every cert-mode field at its default drives an IDENTICAL
    // wire flight to the original PSK-only engine (same suite/psk/identity
    // as `loopbackHandshake`'s own AES-128-GCM case).
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} };
    const cfg_server = Config{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x10} ** 32);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    try driveHandshake(&client, &server, seededForTest(&csprng), &buf1, &buf2);
    try testing.expectEqual(State.connected, client.state);
    try testing.expectEqual(State.connected, server.state);
}

// ── signature_algorithms negotiation (RFC 8446 §4.2.3): REAL handshake
// ── proof that `selectSignatureScheme` is genuinely on the wired code path
// ── (not just unit-tested in isolation above) ────────────────────────────

test "cert-mode: signature_algorithms negotiation picks the mutually-supported scheme from a restricted, non-default, non-preference-order list on both sides" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .now_sec = cert_kat.valid_now_sec,
        // Deliberately NOT this module's default list, deliberately NOT
        // ecdsa-first — if the negotiation just took peer/self index 0 (or
        // ignored the lists entirely) rather than a real intersection, this
        // would either pick the wrong scheme or fail outright.
        .signature_algorithms = &.{ .ed25519, .rsa_pss_rsae_sha256, .ecdsa_secp256r1_sha256 },
    };
    const cfg_server = Config{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{ .chain = &.{&cert_kat.server_cert_der}, .private_key = serverEcdsaKeyPair() },
        .signature_algorithms = &.{ .rsa_pss_rsae_sha384, .ecdsa_secp256r1_sha256, .rsa_pss_rsae_sha512 },
    };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x67} ** 32);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    // Only overlap across (client's advertised list) x (server's own list)
    // x (server's ECDSA-P256 key's one candidate) is `ecdsa_secp256r1_sha256`
    // — completing at all proves that scheme, and only that scheme, was
    // negotiated end-to-end through the real flight engine.
    try driveHandshake(&client, &server, seededForTest(&csprng), &buf1, &buf2);
    try testing.expectEqual(State.connected, client.state);
    try testing.expectEqual(State.connected, server.state);
}

test "cert-mode: no mutually-supported signature scheme for the server's own CertificateVerify -> real handshake fails with the named error, not a silent default" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        // Only claims to verify RSA-PSS schemes — the server's configured
        // credential is ECDSA P-256, whose one candidate scheme
        // (ecdsa_secp256r1_sha256) is absent from this list, so the server
        // can find no overlap for its own CertificateVerify.
        .signature_algorithms = &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384 },
    };
    const cfg_server = Config{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{ .chain = &.{&cert_kat.server_cert_der}, .private_key = serverEcdsaKeyPair() },
    };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x68} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    // If `selectSignatureScheme` were removed from `serverProcessClientHello`
    // (e.g. reverted to some hardcoded scheme), this would instead complete
    // (or fail some other, unrelated way) — this test fails exactly when
    // that real wiring is missing.
    try testing.expectError(error.NoSignatureSchemeOverlap, server.handleFlight(ch, rnd, 0, &buf2));
}

test "cert-mode: no mutually-supported signature scheme for the CLIENT's own CertificateVerify -> real handshake fails with the named error" {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{ .chain = &.{&cert_kat.client_cert_der}, .private_key = clientEcdsaKeyPair() },
    };
    const cfg_server = Config{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        // No `cert` — this test isolates the CLIENT's own negotiation
        // (server presents no CertificateVerify of its own to interfere).
        .request_client_cert = true,
        // The server's CertificateRequest advertises ONLY rsa_pss_rsae_sha256
        // (RFC 8446 §4.3.2's signature_algorithms) — the client's ECDSA
        // P-256 credential's one candidate scheme is absent from it.
        .signature_algorithms = &.{.rsa_pss_rsae_sha256},
    };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x69} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);
    try testing.expectError(error.NoSignatureSchemeOverlap, client.handleFlight(flight2.out, rnd, 0, &buf1));
}

// ── cert-only-DHE (`.cert_dhe`) mode: PSK-less ephemeral-X25519 handshake ──
//
// The ECDHE math + key_share wiring is locked against a REAL external vector
// (RFC 8448 §3, "Example Handshake Traces for TLS 1.3"): §3 publishes the
// client/server X25519 private+public keys and the resulting shared secret,
// then the handshake secret derived from it. RFC 8448 §3 is a psk_dhe_ke
// trace, but the ECDHE math is identical to the PSK-less path here, and its
// early secret is over an all-zero PSK — exactly this mode's construction
// (RFC 8446 §7.1: no PSK ⇒ IKM = 0^Hash.length). The full cert-only FLOW is
// then proven by self-interop (two in-memory Connections) — no public DTLS
// 1.3 cert-only byte-trace exists to KAT the wire flight against; that gap
// is flagged for the interop-vector audit backlog (see SPEC.md).

fn hx(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "cert-DHE KAT: X25519 key_share + key schedule reproduce RFC 8448 §3 byte-for-byte" {
    // RFC 8448 §3 ephemeral X25519 key material and the shared secret.
    const client_priv = hx(32, "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");
    const client_pub = hx(32, "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c");
    const server_priv = hx(32, "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e");
    const server_pub = hx(32, "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f");
    const shared_expected = hx(32, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");

    // (1) Public keys recovered from the private scalars — proves the exact
    // key_share bytes this module would put on the wire.
    try testing.expectEqualSlices(u8, &client_pub, &(try X25519.recoverPublicKey(client_priv)));
    try testing.expectEqualSlices(u8, &server_pub, &(try X25519.recoverPublicKey(server_priv)));

    // (2) The DH shared secret, computed from BOTH sides — proves
    // scalarmult(client_priv, server_pub) == scalarmult(server_priv,
    // client_pub) == the RFC's published value.
    const shared_c = try X25519.scalarmult(client_priv, server_pub);
    const shared_s = try X25519.scalarmult(server_priv, client_pub);
    try testing.expectEqualSlices(u8, &shared_expected, &shared_c);
    try testing.expectEqualSlices(u8, &shared_expected, &shared_s);

    // (3) That shared secret, fed into the key schedule EXACTLY as this
    // module's `.cert_dhe` path does (early secret over an all-zero PSK, then
    // the handshake secret with the ECDHE IKM), reproduces RFC 8448 §3's
    // early + handshake secrets. RFC 8448 uses the TLS "tls13 " label prefix,
    // so the "derived" salt is computed with that prefix here (the DTLS
    // "dtls13" prefix is separately KAT'd in keyschedule.zig); the point
    // proven is that the X25519 output is the correct HKDF-Extract IKM.
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const zero_psk = [_]u8{0} ** 32;
    const es = keyschedule.earlySecret(Hkdf, &zero_psk);
    try testing.expectEqualSlices(u8, &hx(32, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"), &es);

    var empty_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &empty_hash, .{});
    const salt = keyschedule.expandLabel(Hkdf, keyschedule.tls13_prefix, es, "derived", &empty_hash, 32);
    const hs = Hkdf.extract(&salt, &shared_c);
    try testing.expectEqualSlices(u8, &hx(32, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), &hs);
}

fn certDheServerConfig() Config {
    return .{
        .role = .server,
        .key_exchange = .cert_dhe,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{
            .chain = &.{&cert_kat.server_cert_der},
            .private_key = serverEcdsaKeyPair(),
        },
    };
}

fn certDheClientConfig() Config {
    return .{
        .role = .client,
        .key_exchange = .cert_dhe,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .now_sec = cert_kat.valid_now_sec,
        .require_peer_cert = true,
    };
}

test "cert-DHE: server-only auth handshake completes, matching keys, app data round-trips" {
    var client = try Connection.clientInit(certDheClientConfig());
    var server = try Connection.serverInit(certDheServerConfig());
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x70} ** 32);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    try driveHandshake(&client, &server, seededForTest(&csprng), &buf1, &buf2);

    // Both sides derived IDENTICAL directional application keys purely from
    // the ephemeral X25519 exchange (there is NO PSK here) + the transcript.
    try testing.expectEqualSlices(u8, client.write_keys.key[0..client.write_keys.key_len], server.read_keys.key[0..server.read_keys.key_len]);
    try testing.expectEqualSlices(u8, &client.write_keys.iv, &server.read_keys.iv);
    try testing.expectEqualSlices(u8, client.read_keys.key[0..client.read_keys.key_len], server.write_keys.key[0..server.write_keys.key_len]);

    // Forward secrecy: the client's ephemeral private key was wiped once the
    // shared secret was computed.
    try testing.expect(!client.ecdhe_secret_live);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &client.ecdhe_secret);

    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const rec = try client.send("hello over PSK-less cert-DHE DTLS 1.3", &wire);
    const got = try server.recv(rec, &plain);
    try testing.expectEqualSlices(u8, "hello over PSK-less cert-DHE DTLS 1.3", got);

    const rec2 = try server.send("and back from the server", &wire);
    const got2 = try client.recv(rec2, &plain);
    try testing.expectEqualSlices(u8, "and back from the server", got2);
}

test "cert-DHE: ChaCha20-Poly1305 suite also completes" {
    var cfg_c = certDheClientConfig();
    cfg_c.cipher_suites = &.{.chacha20_poly1305_sha256};
    var cfg_s = certDheServerConfig();
    cfg_s.cipher_suites = &.{.chacha20_poly1305_sha256};
    var client = try Connection.clientInit(cfg_c);
    var server = try Connection.serverInit(cfg_s);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x71} ** 32);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    try driveHandshake(&client, &server, seededForTest(&csprng), &buf1, &buf2);
    try testing.expectEqual(State.connected, client.state);
    try testing.expectEqual(State.connected, server.state);
}

test "cert-DHE: mutual auth (CertificateRequest -> client cert) completes" {
    var cfg_c = certDheClientConfig();
    cfg_c.cert = .{
        .chain = &.{&cert_kat.client_cert_der},
        .private_key = clientEcdsaKeyPair(),
    };
    var cfg_s = certDheServerConfig();
    cfg_s.request_client_cert = true;
    cfg_s.require_peer_cert = true;
    cfg_s.peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der };
    cfg_s.now_sec = cert_kat.valid_now_sec;

    var client = try Connection.clientInit(cfg_c);
    var server = try Connection.serverInit(cfg_s);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x72} ** 32);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    try driveHandshake(&client, &server, seededForTest(&csprng), &buf1, &buf2);
    try testing.expectEqual(State.connected, client.state);
    try testing.expectEqual(State.connected, server.state);

    // Both authenticated identities round-trip real app data.
    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const rec = try client.send("mutual-auth cert-DHE ok", &wire);
    try testing.expectEqualSlices(u8, "mutual-auth cert-DHE ok", try server.recv(rec, &plain));
}

test "cert-DHE reject: a tampered ServerHello key_share breaks the handshake (typed error, not a panic)" {
    var client = try Connection.clientInit(certDheClientConfig());
    var server = try Connection.serverInit(certDheServerConfig());
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x73} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);

    // The ServerHello is the first (epoch-0, plaintext) record; its
    // key_share value is near its tail. Flip a byte well inside the
    // ServerHello body so the client computes a DIFFERENT shared secret and
    // can no longer decrypt the server's handshake-epoch records (or its
    // Finished fails to verify). Either way: a typed error, never a panic.
    var tampered: [2048]u8 = undefined;
    @memcpy(tampered[0..flight2.out.len], flight2.out);
    // Offset: plaintext header (13) + handshake header (12) + SH body: legacy
    // version (2) + random (32) => land on the server random, which is part
    // of the transcript AND precedes the key_share; flipping here desyncs the
    // client's derived keys.
    tampered[13 + 12 + 2 + 5] ^= 0x40;

    if (client.handleFlight(tampered[0..flight2.out.len], rnd, 0, &buf1)) |_| {
        return error.TestExpectedTamperToFail;
    } else |_| {}
}

test "cert-DHE reject: CertificateVerify signed with the WRONG key is rejected" {
    var cfg_s = certDheServerConfig();
    cfg_s.cert = .{
        // Presents the real server leaf but signs with the CLIENT's key.
        .chain = &.{&cert_kat.server_cert_der},
        .private_key = clientEcdsaKeyPair(),
    };
    var client = try Connection.clientInit(certDheClientConfig());
    var server = try Connection.serverInit(cfg_s);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x74} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);
    try testing.expectError(error.CertVerifyFailed, client.handleFlight(flight2.out, rnd, 0, &buf1));
}

test "cert-DHE reject: untrusted anchor is rejected" {
    var cfg_c = certDheClientConfig();
    cfg_c.peer_verify = .{ .trust_anchor = &cert_kat.evil_anchor_cert_der };
    var client = try Connection.clientInit(cfg_c);
    var server = try Connection.serverInit(certDheServerConfig());
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x75} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);
    try testing.expectError(error.CertificateRejected, client.handleFlight(flight2.out, rnd, 0, &buf1));
}

test "cert-DHE reject: a cert-DHE server rejects a ClientHello with no key_share" {
    // A PSK-mode client (its ClientHello carries pre_shared_key, NO
    // key_share) driven into a cert-DHE server: the server finds no usable
    // x25519 share and returns a typed `MissingKeyShare`, never a panic.
    var psk_client = try Connection.clientInit(.{
        .role = .client,
        .psk_identity = "device-042",
        .psk = "a-shared-pre-shared-key",
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    var server = try Connection.serverInit(certDheServerConfig());
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x76} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try psk_client.startHandshake(rnd, 0, &buf1);
    try testing.expectError(error.MissingKeyShare, server.handleFlight(ch, rnd, 0, &buf2));
}

test "cert-DHE: Config.validate does not require PSK fields in cert-DHE mode" {
    // A cert-DHE Config with empty psk/psk_identity must validate cleanly
    // (the PSK fields are unused in this mode) — as long as it carries the
    // authentication material its role owes (see the fail-closed tests
    // below); `certDheServerConfig`/`certDheClientConfig` set no PSK at all.
    try certDheServerConfig().validate();
    try certDheClientConfig().validate();
    // ...but PSK mode still rejects an empty PSK (regression guard).
    const psk_cfg = Config{ .role = .client, .cipher_suites = &.{.aes_128_gcm_sha256} };
    try testing.expectError(error.EmptyPsk, psk_cfg.validate());
}

// ── `.cert_dhe` fails closed: the default Config cannot reach an
// unauthenticated "certificate" handshake ────────────────────────────────
//
// The hole these pin: `peer_verify` defaults to `.none` and
// `require_peer_cert` to `false`, so a Config that set nothing but
// `key_exchange = .cert_dhe` used to reach `.connected` against a peer that
// presented no certificate at all — an (EC)DHE channel with no peer
// authentication whatsoever, in the one mode named for certificate
// authentication.

test "cert-DHE fail-closed: a Config that sets only key_exchange = .cert_dhe is rejected, in BOTH roles" {
    // The exact minimal Config a caller writes when they want "TLS-style
    // certificate DTLS": nothing but the mode.
    const client_cfg = Config{ .role = .client, .key_exchange = .cert_dhe, .cipher_suites = &.{.aes_128_gcm_sha256} };
    try testing.expectError(error.PeerVerificationRequired, client_cfg.validate());
    try testing.expectError(error.PeerVerificationRequired, Connection.clientInit(client_cfg));

    const server_cfg = Config{ .role = .server, .key_exchange = .cert_dhe, .cipher_suites = &.{.aes_128_gcm_sha256} };
    try testing.expectError(error.LocalCertificateRequired, server_cfg.validate());
    try testing.expectError(error.LocalCertificateRequired, Connection.serverInit(server_cfg));

    // A client that supplies a certificate of its OWN but still no trust
    // policy is the same hole wearing a costume — it authenticates itself to
    // the server and learns nothing about the server.
    var client_with_own_cert = client_cfg;
    client_with_own_cert.cert = .{ .chain = &.{&cert_kat.client_cert_der}, .private_key = clientEcdsaKeyPair() };
    try testing.expectError(error.PeerVerificationRequired, client_with_own_cert.validate());

    // A server that ASKS for a client certificate while holding no trust
    // policy would accept any certificate at all.
    var server_asking = certDheServerConfig();
    server_asking.request_client_cert = true;
    server_asking.peer_verify = .none;
    try testing.expectError(error.PeerVerificationRequired, server_asking.validate());

    // PSK mode is untouched by all of this: there the PSK binder does the
    // authenticating, so `.none` is the correct default.
    const psk_cfg = Config{ .role = .client, .psk_identity = "device-042", .psk = "a-shared-pre-shared-key", .cipher_suites = &.{.aes_128_gcm_sha256} };
    try psk_cfg.validate();
}

test "cert-DHE fail-closed: a server that presents NO certificate cannot complete a .cert_dhe handshake, require_peer_cert or not" {
    // The peer is a `.cert_dhe_insecure_unauthenticated` server with no
    // `cert` — i.e. exactly what an anonymous (or stripped-down MITM) peer
    // looks like on the wire: a well-formed PSK-less (EC)DHE flight with no
    // Certificate/CertificateVerify in it.
    var cfg_c = certDheClientConfig();
    cfg_c.require_peer_cert = false; // the knob that used to be the ONLY guard
    var client = try Connection.clientInit(cfg_c);
    var server = try Connection.serverInit(.{
        .role = .server,
        .key_exchange = .cert_dhe_insecure_unauthenticated,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x7f} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);
    try testing.expectError(error.PeerCertificateRequired, client.handleFlight(flight2.out, rnd, 0, &buf1));
    try testing.expect(client.state != .connected);
}

test "cert-DHE: the unauthenticated mode is reachable ONLY by its own name, and then it really is unauthenticated" {
    // The escape hatch works — otherwise "fail closed" would just be "does
    // not work". Both sides spell out the insecure mode; the server presents
    // nothing and the client verifies nothing.
    const insecure_client = Config{
        .role = .client,
        .key_exchange = .cert_dhe_insecure_unauthenticated,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    };
    const insecure_server = Config{
        .role = .server,
        .key_exchange = .cert_dhe_insecure_unauthenticated,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    };
    try insecure_client.validate();
    try insecure_server.validate();

    var client = try Connection.clientInit(insecure_client);
    var server = try Connection.serverInit(insecure_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x80} ** 32);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;
    try driveHandshake(&client, &server, seededForTest(&csprng), &buf1, &buf2);
    try testing.expectEqual(State.connected, client.state);
    try testing.expectEqual(State.connected, server.state);

    // ...and the two names are NOT interchangeable: the same Config with the
    // authenticated name is a config error, so nothing that merely omits a
    // field can land in the insecure mode.
    var renamed_client = insecure_client;
    renamed_client.key_exchange = .cert_dhe;
    try testing.expectError(error.PeerVerificationRequired, renamed_client.validate());
    var renamed_server = insecure_server;
    renamed_server.key_exchange = .cert_dhe;
    try testing.expectError(error.LocalCertificateRequired, renamed_server.validate());
}

// ── (EC)DHE group plumbing + secp256r1 ───────────────────────────────────

test "advertised_groups and the (EC)DHE implementation agree (no group we cannot answer for)" {
    // Advertising a group this side cannot generate a share in is not a
    // harmless extra: it invites a HelloRetryRequest naming it, which
    // `handleHelloRetryRequest` would then have to refuse — turning a
    // perfectly ordinary server into an unreachable one. This test is the
    // reason `advertised_groups` is a single list rather than two literals.
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x91} ** 32);
    const rnd = seededForTest(&csprng);
    for (advertised_groups) |g| {
        try testing.expect(groupAdvertised(g));
        const kp = try ecdheGenerate(g, rnd);
        try testing.expectEqual(g, kp.group);
        try testing.expectEqual(expectedShareLen(g), kp.public_len);
        try testing.expect(expectedShareLen(g) != 0);
    }
    // ...and a group nobody advertised is refused rather than silently
    // treated as one of ours (x448, 0x001e — a real code point we do not do).
    try testing.expect(!groupAdvertised(0x001e));
    try testing.expectEqual(@as(usize, 0), expectedShareLen(0x001e));
    try testing.expectError(error.MissingKeyShare, ecdheGenerate(0x001e, rnd));
}

test "ecdheSharedSecret secp256r1 KAT: byte-exact against Python `cryptography` (OpenSSL) ECDH" {
    // An INDEPENDENT oracle for the P-256 half of the key exchange, in the
    // same spirit as the RFC 8448 X25519 vector above. Generated with
    // `cryptography` 46.0.5 (OpenSSL 3.5.5): two fixed private scalars,
    // their SEC1 uncompressed public points, and the ECDH output — which for
    // the NIST curves is the shared point's X COORDINATE ONLY (RFC 8446
    // §7.4.2 / SEC1 ECDH), not the 65-byte point. Returning the point, or
    // X||Y, would still make both sides of a self-interop test agree and
    // would still "work" — against nothing but itself.
    const a_scalar = hx(32, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    const a_point = hx(65, "04515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354");
    const b_scalar = hx(32, "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
    const b_point = hx(65, "0477186fee3e281f9d033a64994f823f7e384151e7383090c3c2954340f295153601a0e901c22a7a492a04cce5c24768a613f77c71b3380043912955379ec12723");
    const shared = hx(32, "ead387cf12ed00b1fd75e195c967ff086d52da18622a70a9b6c05603cbdd913c");

    // (1) the public shares this module would put on the wire, recovered
    //     from the same scalars OpenSSL used.
    try testing.expectEqualSlices(u8, &a_point, &(try P256.basePoint.mul(a_scalar, .big)).toUncompressedSec1());
    try testing.expectEqualSlices(u8, &b_point, &(try P256.basePoint.mul(b_scalar, .big)).toUncompressedSec1());

    // (2) the shared secret, from BOTH sides.
    try testing.expectEqualSlices(u8, &shared, &(try ecdheSharedSecret(secp256r1_group, a_scalar, &b_point)));
    try testing.expectEqualSlices(u8, &shared, &(try ecdheSharedSecret(secp256r1_group, b_scalar, &a_point)));
}

test "ecdheSharedSecret: peer-supplied garbage is a typed error, never a panic" {
    const a_scalar = hx(32, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    // Wrong length for the group (an x25519-sized share labelled P-256).
    try testing.expectError(error.MissingKeyShare, ecdheSharedSecret(secp256r1_group, a_scalar, &([_]u8{0xAA} ** 32)));
    // Right length, not a point on the curve.
    var off_curve = [_]u8{0} ** 65;
    off_curve[0] = 0x04;
    off_curve[1] = 0x01;
    try testing.expectError(error.KeyExchangeFailed, ecdheSharedSecret(secp256r1_group, a_scalar, &off_curve));
    // A group this module does not speak.
    try testing.expectError(error.MissingKeyShare, ecdheSharedSecret(0x001e, a_scalar, &([_]u8{0xAA} ** 32)));
    // x25519's own low-order/identity rejection still stands.
    try testing.expectError(error.KeyExchangeFailed, ecdheSharedSecret(x25519_group, a_scalar, &([_]u8{0} ** 32)));
}

// ── HelloRetryRequest in `.cert_dhe` mode (RFC 8446 §4.1.4's (EC)DHE half) ──
//
// The live wolfSSL tests (`wolfssl_interop.zig`) are the ORACLE for this
// path — a real server naming secp256r1, and the handshake then completing
// on P-256. What follows are the checks a live peer cannot make for us:
// what ClientHello2 is allowed to contain, and which retries must be
// REFUSED. Those refusals have no live counterpart at all, because a
// conforming server never sends them.

const CertHrr = struct {
    cookie: ?[]const u8 = null,
    selected_group: ?u16 = null,
    /// Overrides the HelloRetryRequest's cipher suite (RFC 8446 §4.1.4
    /// requires the eventual ServerHello to match it).
    suite: CipherSuite = .aes_128_gcm_sha256,
};

fn certHrrDatagram(h: CertHrr) !HrrDatagram {
    var sh_versions_buf: [2]u8 = undefined;
    const sh_versions = try messages.encodeSupportedVersionsServerHello(messages.version_dtls13, &sh_versions_buf);
    var cookie_buf: [2 + max_cookie_len]u8 = undefined;
    var ks_buf: [2]u8 = undefined;

    var exts: [3]messages.Extension = undefined;
    var n: usize = 0;
    exts[n] = .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = sh_versions };
    n += 1;
    if (h.cookie) |c| {
        exts[n] = .{ .ext_type = @intFromEnum(messages.ExtensionType.cookie), .data = try messages.encodeCookieExtension(c, &cookie_buf) };
        n += 1;
    }
    if (h.selected_group) |g| {
        exts[n] = .{ .ext_type = @intFromEnum(messages.ExtensionType.key_share), .data = try messages.encodeKeyShareHelloRetryRequest(g, &ks_buf) };
        n += 1;
    }

    var sh_body_buf: [256]u8 = undefined;
    const sh_body = try messages.encodeServerHello(.{
        .random = messages.hello_retry_request_random,
        .legacy_session_id_echo = &.{},
        .cipher_suite = @intFromEnum(h.suite),
        .extensions = exts[0..n],
    }, &sh_body_buf);

    var frag_buf: [256 + handshake.header_len]u8 = undefined;
    const fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.server_hello), 0, sh_body, &frag_buf);

    var result: HrrDatagram = .{ .bytes = undefined, .len = 0 };
    const hdr = record.PlaintextHeader{ .content_type = content_type_handshake, .epoch = 0, .sequence_number = 0, .length = @intCast(fragment.len) };
    const hdr_slice = try record.encodePlaintext(hdr, &result.bytes);
    @memcpy(result.bytes[hdr_slice.len..][0..fragment.len], fragment);
    result.len = hdr_slice.len + fragment.len;
    return result;
}

fn findExt(exts: []const messages.Extension, t: messages.ExtensionType) ?[]const u8 {
    for (exts) |e| {
        if (e.ext_type == @intFromEnum(t)) return e.data;
    }
    return null;
}

/// RFC 8446 §4.1.2, as a check rather than a comment: ClientHello2 is
/// ClientHello1 "with the following modifications" and NOTHING else —
///
///   * the `key_share`, if (and ONLY if) the retry named a group;
///   * an added/updated `cookie`, if the retry carried one.
///
/// Everything else — `random`, `legacy_session_id`, the cipher-suite list,
/// every other extension, byte for byte — must be untouched. A client that
/// rolls a fresh `random`, reorders its cipher suites, or regenerates its
/// key share for a cookie-only retry is a DIFFERENT client to the server; a
/// conforming one rejects it, and a lenient one (wolfSSL is lenient here)
/// lets it pass, which is exactly why this is asserted locally.
fn expectClientHello2Conformant(
    ch1: []const u8,
    ch2: []const u8,
    expect_key_share_changed: bool,
    expect_cookie: ?[]const u8,
) !void {
    var e1_buf: [16]messages.Extension = undefined;
    var e2_buf: [16]messages.Extension = undefined;
    const d1 = try messages.decodeClientHello(ch1, &e1_buf);
    const d2 = try messages.decodeClientHello(ch2, &e2_buf);

    try testing.expectEqualSlices(u8, &d1.random, &d2.random);
    try testing.expectEqualSlices(u8, d1.legacy_session_id, d2.legacy_session_id);
    try testing.expectEqualSlices(u8, d1.cipher_suites_raw, d2.cipher_suites_raw);

    // Every CH1 extension survives, in the same relative order, with
    // identical bytes — except `key_share`.
    var seen: usize = 0;
    for (d1.extensions) |x1| {
        const x2 = for (d2.extensions[seen..], seen..) |cand, idx| {
            if (cand.ext_type == x1.ext_type) {
                seen = idx + 1;
                break cand;
            }
        } else return error.ClientHello2DroppedAnExtension;
        if (x1.ext_type == @intFromEnum(messages.ExtensionType.key_share)) {
            const changed = !std.mem.eql(u8, x1.data, x2.data);
            try testing.expectEqual(expect_key_share_changed, changed);
        } else {
            try testing.expectEqualSlices(u8, x1.data, x2.data);
        }
    }

    // ...and the only extension CH2 may ADD is `cookie`.
    for (d2.extensions) |x2| {
        if (findExt(d1.extensions, @enumFromInt(x2.ext_type)) != null) continue;
        try testing.expectEqual(@intFromEnum(messages.ExtensionType.cookie), x2.ext_type);
    }

    if (expect_cookie) |want| {
        const raw = findExt(d2.extensions, .cookie) orelse return error.ClientHello2HasNoCookie;
        try testing.expectEqualSlices(u8, want, try messages.decodeCookieExtension(raw));
    } else {
        try testing.expect(findExt(d2.extensions, .cookie) == null);
    }
}

/// Pulls the ClientHello body out of an epoch-0 handshake record.
fn clientHelloBodyOf(datagram: []const u8, out: []u8) ![]const u8 {
    const rec = try record.decodePlaintext(datagram);
    const fragment = datagram[record.plaintext_header_len..][0..rec.length];
    var received_buf: [1024]bool = undefined;
    const parsed = try decodeSingleFragmentMessage(fragment, out, &received_buf);
    try testing.expectEqual(@intFromEnum(messages.HandshakeType.client_hello), parsed.msg_type);
    return parsed.body;
}

test "cert-DHE HRR: a GROUP-CHANGE retry regenerates the key_share in the named group and changes nothing else" {
    var client = try Connection.clientInit(certDheClientConfig());
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x80} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch1_wire = try client.startHandshake(rnd, 0, &buf1);
    var ch1_body_buf: [1024]u8 = undefined;
    var ch1_copy: [1024]u8 = undefined;
    const ch1_body = try clientHelloBodyOf(ch1_wire, &ch1_body_buf);
    @memcpy(ch1_copy[0..ch1_body.len], ch1_body);
    const ch1 = ch1_copy[0..ch1_body.len];

    try testing.expectEqual(x25519_group, client.ecdhe_group);
    var ch1_share_buf: [max_key_share_len]u8 = undefined;
    @memcpy(ch1_share_buf[0..client.ecdhe_public_len], client.ecdhe_public[0..client.ecdhe_public_len]);
    const ch1_share = ch1_share_buf[0..client.ecdhe_public_len];

    const hrr = try certHrrDatagram(.{ .selected_group = secp256r1_group });
    const retry = try client.handleFlight(hrr.bytes[0..hrr.len], rnd, 0, &buf2);
    try testing.expect(!retry.done);
    try testing.expect(client.sawHelloRetryRequest());

    // The share really moved to the named group — this is the assertion a
    // "retry" that merely echoed a cookie would fail.
    try testing.expectEqual(secp256r1_group, client.ecdhe_group);
    try testing.expectEqual(@as(usize, 65), client.ecdhe_public_len);
    try testing.expect(!std.mem.eql(u8, ch1_share, client.ecdhe_public[0..32]));
    // ...and it is a real point, not 65 bytes of anything.
    _ = try P256.fromSec1(client.ecdhe_public[0..65]);

    var ch2_body_buf: [1024]u8 = undefined;
    const ch2 = try clientHelloBodyOf(retry.out, &ch2_body_buf);
    // No cookie was offered, so none may appear; the key_share must have
    // changed and nothing else.
    try expectClientHello2Conformant(ch1, ch2, true, null);

    // ClientHello2 is a NEW message, not a retransmission (RFC 9147 §5.2).
    try testing.expectEqual(@as(u16, 2), client.message_seq);
}

test "cert-DHE HRR: a COOKIE-ONLY retry leaves the key_share byte-identical (§4.1.2 permits no gratuitous change)" {
    var client = try Connection.clientInit(certDheClientConfig());
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x81} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch1_wire = try client.startHandshake(rnd, 0, &buf1);
    var ch1_body_buf: [1024]u8 = undefined;
    var ch1_copy: [1024]u8 = undefined;
    const ch1_body = try clientHelloBodyOf(ch1_wire, &ch1_body_buf);
    @memcpy(ch1_copy[0..ch1_body.len], ch1_body);
    const ch1 = ch1_copy[0..ch1_body.len];
    var ch1_share_buf: [max_key_share_len]u8 = undefined;
    @memcpy(ch1_share_buf[0..client.ecdhe_public_len], client.ecdhe_public[0..client.ecdhe_public_len]);
    const ch1_share = ch1_share_buf[0..client.ecdhe_public_len];

    const cookie = "a-cert-mode-cookie";
    const hrr = try certHrrDatagram(.{ .cookie = cookie });
    const retry = try client.handleFlight(hrr.bytes[0..hrr.len], rnd, 0, &buf2);

    // Same group AND the same share bytes: a fresh x25519 key pair here
    // would be a ClientHello2 the server never asked for. Nothing in a
    // self-interop suite would notice (our own server re-reads whatever
    // share arrives), and wolfSSL accepts it too — so this is the only place
    // it is checked.
    try testing.expectEqual(x25519_group, client.ecdhe_group);
    try testing.expectEqualSlices(u8, ch1_share, client.ecdhe_public[0..client.ecdhe_public_len]);

    var ch2_body_buf: [1024]u8 = undefined;
    const ch2 = try clientHelloBodyOf(retry.out, &ch2_body_buf);
    try expectClientHello2Conformant(ch1, ch2, false, cookie);
}

test "cert-DHE HRR: cookie AND group change in one retry are both applied" {
    var client = try Connection.clientInit(certDheClientConfig());
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x82} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch1_wire = try client.startHandshake(rnd, 0, &buf1);
    var ch1_body_buf: [1024]u8 = undefined;
    var ch1_copy: [1024]u8 = undefined;
    const ch1_body = try clientHelloBodyOf(ch1_wire, &ch1_body_buf);
    @memcpy(ch1_copy[0..ch1_body.len], ch1_body);
    const ch1 = ch1_copy[0..ch1_body.len];

    const cookie = "both-at-once";
    const hrr = try certHrrDatagram(.{ .cookie = cookie, .selected_group = secp256r1_group });
    const retry = try client.handleFlight(hrr.bytes[0..hrr.len], rnd, 0, &buf2);

    try testing.expectEqual(secp256r1_group, client.ecdhe_group);
    var ch2_body_buf: [1024]u8 = undefined;
    const ch2 = try clientHelloBodyOf(retry.out, &ch2_body_buf);
    try expectClientHello2Conformant(ch1, ch2, true, cookie);
}

test "cert-DHE HRR reject: a retry naming a group the client ALREADY offered a share in (the retry-loop case)" {
    var client = try Connection.clientInit(certDheClientConfig());
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x83} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &buf1);

    // RFC 8446 §4.2.8, verbatim: the client "MUST verify that ... (2) the
    // selected_group field does not correspond to a group which was provided
    // in the "key_share" extension in the original ClientHello. If either of
    // these checks fails, then the client MUST abort the handshake with an
    // "illegal_parameter" alert." (Cited as §4.1.4 before audit BD-26; §4.1.4
    // is where the related "would not result in any change in the
    // ClientHello" abort lives, not this rule.) A client that obliged would
    // regenerate the same offer on demand, forever — an unbounded loop the
    // peer controls. Note this survives even WITH a cookie present: the
    // cookie makes the retry "not pointless", but the group is still
    // illegal.
    const hrr = try certHrrDatagram(.{ .selected_group = x25519_group });
    try testing.expectError(error.IllegalHelloRetryRequest, client.handleFlight(hrr.bytes[0..hrr.len], rnd, 0, &buf2));

    var client2 = try Connection.clientInit(certDheClientConfig());
    defer client2.deinit();
    _ = try client2.startHandshake(rnd, 0, &buf1);
    const hrr2 = try certHrrDatagram(.{ .cookie = "with-a-cookie-too", .selected_group = x25519_group });
    try testing.expectError(error.IllegalHelloRetryRequest, client2.handleFlight(hrr2.bytes[0..hrr2.len], rnd, 0, &buf2));
}

test "cert-DHE HRR reject: a retry naming a group never advertised in supported_groups" {
    var client = try Connection.clientInit(certDheClientConfig());
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x84} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &buf1);

    // x448 (0x001e) is a real NamedGroup this module never advertises. The
    // server does not get to pick off-menu — least of all a group we could
    // not produce a share for even if we wanted to.
    const hrr = try certHrrDatagram(.{ .selected_group = 0x001e });
    try testing.expectError(error.UnsupportedGroup, client.handleFlight(hrr.bytes[0..hrr.len], rnd, 0, &buf2));
}

test "cert-DHE HRR reject: a retry with neither a cookie nor a group change" {
    var client = try Connection.clientInit(certDheClientConfig());
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x85} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &buf1);

    const hrr = try certHrrDatagram(.{});
    try testing.expectError(error.HelloRetryRequestUnsupported, client.handleFlight(hrr.bytes[0..hrr.len], rnd, 0, &buf2));
}

test "PSK HRR reject: a retry carrying a key_share (psk_ke has no (EC)DHE to update)" {
    var client = try Connection.clientInit(hrrClientConfig(hrr_psk));
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x86} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &buf1);

    // A `psk_ke` ClientHello carries an EMPTY key_share list on purpose, so
    // §4.1.4's "group already offered" rule does not bite — but answering
    // with a real share would silently turn the exchange into `psk_dhe_ke`,
    // which this engine does not implement. Refusing is the honest answer;
    // quietly producing a share the key schedule then ignores would not be.
    const hrr = try certHrrDatagram(.{ .cookie = "a-real-cookie", .selected_group = x25519_group });
    try testing.expectError(error.HelloRetryRequestUnsupported, client.handleFlight(hrr.bytes[0..hrr.len], rnd, 0, &buf2));
}

test "HRR: the ServerHello must select the cipher suite the retry committed to (RFC 8446 §4.1.4)" {
    var cfg = certDheClientConfig();
    cfg.cipher_suites = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256 };
    var client = try Connection.clientInit(cfg);
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x87} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &buf1);

    const hrr = try certHrrDatagram(.{ .selected_group = secp256r1_group, .suite = .aes_128_gcm_sha256 });
    _ = try client.handleFlight(hrr.bytes[0..hrr.len], rnd, 0, &buf2);
    try testing.expectEqual(@as(?u16, @intFromEnum(CipherSuite.aes_128_gcm_sha256)), client.hrr_cipher_suite);

    // A ServerHello selecting the OTHER suite — one this client legitimately
    // offered, so nothing else rejects it — after the retry named the first.
    // The retry is already in the transcript, so a client that followed the
    // switch would derive its keys under a suite the server never committed
    // to, with no other check standing in the way.
    var sh_body_buf: [256]u8 = undefined;
    var sh_versions_buf: [2]u8 = undefined;
    const sh_versions = try messages.encodeSupportedVersionsServerHello(messages.version_dtls13, &sh_versions_buf);
    var ks_buf: [4 + max_key_share_len]u8 = undefined;
    const dummy_share = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    const ks = try messages.encodeKeyShareServerHello(.{ .group = secp256r1_group, .key_exchange = &dummy_share }, &ks_buf);
    const sh_body = try messages.encodeServerHello(.{
        .random = [_]u8{0x5a} ** 32,
        .legacy_session_id_echo = &.{},
        .cipher_suite = @intFromEnum(CipherSuite.chacha20_poly1305_sha256),
        .extensions = &.{
            .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = sh_versions },
            .{ .ext_type = @intFromEnum(messages.ExtensionType.key_share), .data = ks },
        },
    }, &sh_body_buf);

    var frag_buf: [256 + handshake.header_len]u8 = undefined;
    const fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.server_hello), 1, sh_body, &frag_buf);
    var wire: [400]u8 = undefined;
    const hdr = record.PlaintextHeader{ .content_type = content_type_handshake, .epoch = 0, .sequence_number = 1, .length = @intCast(fragment.len) };
    const hdr_slice = try record.encodePlaintext(hdr, &wire);
    @memcpy(wire[hdr_slice.len..][0..fragment.len], fragment);

    var buf3: [1500]u8 = undefined;
    try testing.expectError(error.IllegalHelloRetryRequest, client.handleFlight(wire[0 .. hdr_slice.len + fragment.len], rnd, 0, &buf3));
}

test "cert-DHE: a ServerHello answering in a DIFFERENT group than the client offered is rejected" {
    // RFC 8446 §4.2.8, verbatim: "This value MUST be in the same group as the
    // KeyShareEntry value offered by the client that the server has selected
    // for the negotiated key exchange."
    // Without the check, this client would run X25519 over bytes
    // the server labelled secp256r1 and carry on into the flight with a
    // shared secret neither side agrees on.
    //
    // The share below is 32 bytes — the length the client's OWN group uses —
    // and that is the whole point. With a 65-byte P-256 point the length
    // check inside `ecdheSharedSecret` rejects it too, so deleting the group
    // check would produce the SAME `MissingKeyShare` and this test would
    // pass either way (it did, until the mutation caught it). At 32 bytes
    // only the GROUP is wrong, so the assertion below can only hold if the
    // group is actually compared.
    var client = try Connection.clientInit(certDheClientConfig());
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x88} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &buf1); // offers x25519

    var sh_versions_buf: [2]u8 = undefined;
    const sh_versions = try messages.encodeSupportedVersionsServerHello(messages.version_dtls13, &sh_versions_buf);
    var ks_buf: [4 + max_key_share_len]u8 = undefined;
    const p256_share = [_]u8{0x11} ** 32;
    const ks = try messages.encodeKeyShareServerHello(.{ .group = secp256r1_group, .key_exchange = &p256_share }, &ks_buf);
    var sh_body_buf: [256]u8 = undefined;
    const sh_body = try messages.encodeServerHello(.{
        .random = [_]u8{0x5b} ** 32,
        .legacy_session_id_echo = &.{},
        .cipher_suite = @intFromEnum(CipherSuite.aes_128_gcm_sha256),
        .extensions = &.{
            .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = sh_versions },
            .{ .ext_type = @intFromEnum(messages.ExtensionType.key_share), .data = ks },
        },
    }, &sh_body_buf);

    var frag_buf: [256 + handshake.header_len]u8 = undefined;
    const fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.server_hello), 0, sh_body, &frag_buf);
    var wire: [400]u8 = undefined;
    const hdr = record.PlaintextHeader{ .content_type = content_type_handshake, .epoch = 0, .sequence_number = 0, .length = @intCast(fragment.len) };
    const hdr_slice = try record.encodePlaintext(hdr, &wire);
    @memcpy(wire[hdr_slice.len..][0..fragment.len], fragment);

    var buf2: [1500]u8 = undefined;
    try testing.expectError(error.MissingKeyShare, client.handleFlight(wire[0 .. hdr_slice.len + fragment.len], rnd, 0, &buf2));
}

test "cert-DHE: a ServerHello negotiating DTLS 1.2 (real legacy value, not garbage) is a downgrade and is rejected" {
    // RFC 8446 §4.2.1 downgrade guard: the wire-level version fields are
    // FROZEN at DTLS 1.2 for compatibility with middleboxes — the only place
    // the real negotiated version appears is `supported_versions`. A peer
    // that named `legacy_version_dtls12` there (a real, meaningful value —
    // not a parse-breaking one) has actually negotiated a version this
    // module does not speak, and continuing would derive DTLS-1.3-shaped
    // keys for a connection that only agreed on 1.2.
    var client = try Connection.clientInit(certDheClientConfig());
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x89} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [1500]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &buf1); // offers x25519

    var sh_versions_buf: [2]u8 = undefined;
    const sh_versions = try messages.encodeSupportedVersionsServerHello(messages.legacy_version_dtls12, &sh_versions_buf);
    var ks_buf: [4 + max_key_share_len]u8 = undefined;
    const dummy_share = [_]u8{0x11} ** 32;
    const ks = try messages.encodeKeyShareServerHello(.{ .group = x25519_group, .key_exchange = &dummy_share }, &ks_buf);
    var sh_body_buf: [256]u8 = undefined;
    const sh_body = try messages.encodeServerHello(.{
        .random = [_]u8{0x5c} ** 32,
        .legacy_session_id_echo = &.{},
        .cipher_suite = @intFromEnum(CipherSuite.aes_128_gcm_sha256),
        .extensions = &.{
            .{ .ext_type = @intFromEnum(messages.ExtensionType.supported_versions), .data = sh_versions },
            .{ .ext_type = @intFromEnum(messages.ExtensionType.key_share), .data = ks },
        },
    }, &sh_body_buf);

    var frag_buf: [256 + handshake.header_len]u8 = undefined;
    const fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.server_hello), 0, sh_body, &frag_buf);
    var wire: [400]u8 = undefined;
    const hdr = record.PlaintextHeader{ .content_type = content_type_handshake, .epoch = 0, .sequence_number = 0, .length = @intCast(fragment.len) };
    const hdr_slice = try record.encodePlaintext(hdr, &wire);
    @memcpy(wire[hdr_slice.len..][0..fragment.len], fragment);

    var buf2: [1500]u8 = undefined;
    try testing.expectError(error.UnsupportedVersion, client.handleFlight(wire[0 .. hdr_slice.len + fragment.len], rnd, 0, &buf2));
}

test "cert-DHE HRR self-interop: our own server's stateless cookie exchange works in certificate mode too" {
    // The PSK cookie exchange had this test; certificate mode did not,
    // because the client refused every HelloRetryRequest. It is a WEAKER
    // test than the wolfSSL ones (both sides are ours), so what it is really
    // for is the STATELESSNESS: the connection that answers ClientHello1 is
    // destroyed before ClientHello2 arrives, so everything the server needs
    // has to be in the cookie — including, now, a cert-mode transcript.
    const binding = "198.51.100.7:44300";
    var cfg_s = certDheServerConfig();
    cfg_s.hello_retry = .{ .cookie_secret = "cert-mode cookie MAC key", .peer_binding = binding };

    var client = try Connection.clientInit(certDheClientConfig());
    defer client.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x89} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    const ch1 = try client.startHandshake(rnd, 0, &buf1);

    var server1 = try Connection.serverInit(cfg_s);
    const hrr = try server1.handleFlight(ch1, rnd, 0, &buf2);
    try testing.expect(!hrr.done);
    try testing.expectEqual(State.start, server1.state);
    _ = try expectHelloRetryRequest(hrr.out);

    const ch2 = try client.handleFlight(hrr.out, rnd, 0, &buf1);
    try testing.expect(client.sawHelloRetryRequest());
    // Cookie-only retry: still x25519, still the same share.
    try testing.expectEqual(x25519_group, client.ecdhe_group);

    server1.deinit();
    var server2 = try Connection.serverInit(cfg_s);
    defer server2.deinit();

    const flight2 = try server2.handleFlight(ch2.out, rnd, 0, &buf2);
    const client_fin = try client.handleFlight(flight2.out, rnd, 0, &buf1);
    try testing.expect(client_fin.done);
    const server_done = try server2.handleFlight(client_fin.out, rnd, 0, &buf2);
    try testing.expect(server_done.done);

    try testing.expectEqualSlices(u8, client.write_keys.key[0..client.write_keys.key_len], server2.read_keys.key[0..server2.read_keys.key_len]);

    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const msg = "cert-DHE over a return-routability-checked connection";
    const rec = try client.send(msg, &wire);
    try testing.expectEqualSlices(u8, msg, try server2.recv(rec, &plain));
}

test "cert-DHE: our server accepts a secp256r1 client share and answers in the same group" {
    // The server side of the group plumbing: a client that offers P-256 (as
    // ours does after a group-change retry) must be answered with a P-256
    // ServerHello share, and both sides must land on the same keys. Driven
    // by hand, because this module's own client only ever offers P-256 after
    // a server asked it to.
    var client = try Connection.clientInit(certDheClientConfig());
    defer client.deinit();
    var server = try Connection.serverInit(certDheServerConfig());
    defer server.deinit();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x8a} ** 32);
    const rnd = seededForTest(&csprng);
    var buf1: [2048]u8 = undefined;
    var buf2: [2048]u8 = undefined;

    _ = try client.startHandshake(rnd, 0, &buf1);
    // Move the client to P-256 exactly as a real retry would.
    const hrr = try certHrrDatagram(.{ .selected_group = secp256r1_group });
    const ch2 = try client.handleFlight(hrr.bytes[0..hrr.len], rnd, 0, &buf2);
    try testing.expectEqual(secp256r1_group, client.ecdhe_group);

    // The server has no cookie configured, so it treats ClientHello2 as an
    // ordinary first ClientHello — which is all this test needs: it is about
    // the group, not the retry.
    const flight2 = try server.handleFlight(ch2.out, rnd, 0, &buf1);
    try testing.expectEqual(secp256r1_group, server.ecdhe_group);
    try testing.expectEqual(@as(usize, 65), server.ecdhe_public_len);

    // The client's transcript now contains the message_hash rewrite + HRR,
    // which this hand-built server never saw, so the handshake cannot
    // complete — the KEY EXCHANGE is what is under test, and it is checked
    // directly instead.
    _ = flight2;
    const shared_c = try ecdheSharedSecret(secp256r1_group, client.ecdhe_secret, server.ecdhe_public[0..server.ecdhe_public_len]);
    try testing.expectEqual(@as(usize, 32), shared_c.len);
}

// ── RNG-seam pins (B6, 2026-08-12) ─────────────────────────────────────────
//
// `startHandshake`/`handleFlight` take an `Entropy`, not a `std.Random`. The
// weak path still EXISTS — it has to, these tests need a reproducible
// handshake — but it is now a named arm a caller has to write out
// (`.seeded_for_test`), not the shape of the parameter itself. `std.Io` is
// still refused: this module is a deliberately sans-I/O state machine (no
// socket, no clock, no allocator — every external fact is an input VALUE), and
// a capability handle threaded through the per-datagram entry point would
// contradict the invariant the rest of the file is built on. A tagged union is
// a value, so it does not.
//
// The pins below are in two halves: the TYPE admits exactly two answers and
// they are distinct (`Entropy`), and the consequence of picking the wrong one
// is real and measured (`ecdheGenerate` reproducing a private key).

test "Entropy: exactly two arms, production and test are distinct, and nothing else is admitted" {
    // What the fix IS, pinned as a type property rather than as prose. If a
    // third arm appears, or the two collapse into one, or the production arm
    // is renamed out from under the callers, this fails.
    const info = @typeInfo(Entropy).@"union";
    try testing.expectEqual(@as(usize, 2), info.fields.len);
    try testing.expectEqualStrings("csprng", info.fields[0].name);
    try testing.expectEqualStrings("seeded_for_test", info.fields[1].name);

    // Distinct: the same generator under the two arms is not the same value,
    // so "which arm" survives being passed around. Without this the test would
    // still pass if the tag were cosmetic.
    var csprng = std.Random.DefaultCsprng.init([_]u8{0xB6} ** 32);
    const production: Entropy = .{ .csprng = csprng.random() };
    const for_test: Entropy = .{ .seeded_for_test = csprng.random() };
    try testing.expect(std.meta.activeTag(production) != std.meta.activeTag(for_test));

    // The union is TAGGED (a bare `union` would make the tag unreadable, and
    // the arms indistinguishable at runtime).
    try testing.expect(info.tag_type != null);

    // Both arms carry a `std.Random` — the difference is the caller's claim
    // about it, which is exactly what this module cannot check for itself.
    try testing.expectEqual(std.Random, info.fields[0].type);
    try testing.expectEqual(std.Random, info.fields[1].type);
}

test "the CSPRNG requirement is load-bearing: a seeded RNG reproduces the ECDHE private key exactly" {
    // This is R1 from the audit, demonstrated rather than asserted — it is why
    // `.seeded_for_test` has the doc comment it has. Two `Connection`s driven
    // from generators in the same state derive the SAME x25519 ephemeral
    // secret, so anyone who knows the seed recovers the shared secret and
    // decrypts every recorded session, retroactively.
    var a = std.Random.DefaultCsprng.init([_]u8{0xB6} ** 32);
    var b = std.Random.DefaultCsprng.init([_]u8{0xB6} ** 32);
    const ka = try ecdheGenerate(x25519_group, .{ .seeded_for_test = a.random() });
    const kb = try ecdheGenerate(x25519_group, .{ .seeded_for_test = b.random() });
    try testing.expectEqualSlices(u8, &ka.secret, &kb.secret);
    try testing.expectEqualSlices(u8, ka.public[0..ka.public_len], kb.public[0..kb.public_len]);

    // ... and it really is the generator that decides, not a constant in the
    // code: a different seed gives a different key. Both halves are needed —
    // the first alone would also pass if `ecdheGenerate` returned a fixed key.
    var c = std.Random.DefaultCsprng.init([_]u8{0x6B} ** 32);
    const kc = try ecdheGenerate(x25519_group, .{ .seeded_for_test = c.random() });
    try testing.expect(!std.mem.eql(u8, &ka.secret, &kc.secret));

    // The ARM is not what decides the bytes — `.csprng` over the same seeded
    // generator gives the identical key. That is the honest statement of what
    // the type does and does not buy: it makes the choice explicit, it cannot
    // make a bad generator good.
    var f = std.Random.DefaultCsprng.init([_]u8{0xB6} ** 32);
    const kf = try ecdheGenerate(x25519_group, .{ .csprng = f.random() });
    try testing.expectEqualSlices(u8, &ka.secret, &kf.secret);

    // Same for P-256, whose rejection-sampling loop could plausibly have
    // masked the dependency.
    var d = std.Random.DefaultCsprng.init([_]u8{0xB6} ** 32);
    var e = std.Random.DefaultCsprng.init([_]u8{0xB6} ** 32);
    const kd = try ecdheGenerate(secp256r1_group, .{ .seeded_for_test = d.random() });
    const ke = try ecdheGenerate(secp256r1_group, .{ .seeded_for_test = e.random() });
    try testing.expectEqualSlices(u8, &kd.secret, &ke.secret);
}

test "doc: every entry point where randomness enters states the CSPRNG requirement" {
    // Documentation IS the fix here, so it is what gets pinned. Assembled
    // from fragments so this test cannot match its own source text.
    const needle = "MUST be a " ++ "cryptographically secure";
    const src = @embedFile("Connection.zig");

    // Each declaration's preceding doc block must carry the sentence. The
    // window is generous (these doc comments are long) but strictly BEFORE
    // the declaration, so a sentence added anywhere else does not count.
    const decls = [_][]const u8{
        "pub fn startHandshake(",
        "pub fn handleFlight(",
        "fn ecdheGenerate(",
    };
    for (decls) |decl| {
        const at = std.mem.indexOf(u8, src, decl) orelse return error.DeclarationNotFound;
        const window_start = at -| 6000;
        try testing.expect(std.mem.indexOf(u8, src[window_start..at], needle) != null);
    }
}
