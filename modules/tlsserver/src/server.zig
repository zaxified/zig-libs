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
//! - **version** TLS 1.3 only — no `supported_versions` with 0x0304 is
//!   `protocol_version`, checked before anything else;
//! - **certificate** fixed, or chosen by a callback from the SNI and the
//!   ClientHello (none chosen: `access_denied`); the signature scheme is
//!   the key's first candidate the client offers and the key can produce
//!   (`certverify.canSign`: a 1024-bit RSA key has no `rsa_pss_rsae_sha512`;
//!   `handshake_failure` if none, or no `signature_algorithms` at all);
//! - **cipher suite** the client's first that the server enables;
//! - **group** the client's first `supported_groups` entry the server
//!   enables (no `supported_groups` or no `key_share` at all is
//!   `missing_extension`, RFC 8446 §9.2); without a share for it the
//!   server sends a HelloRetryRequest naming it (no cookie, RFC 8446
//!   §4.1.4);
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
//! Early data is never accepted and is skipped
//! (`inbound.Inbound.skip_early`).

const std = @import("std");
const tls13 = @import("tls13");
const record = @import("record.zig");
const alert = @import("alert.zig");
const inbound = @import("inbound.zig");
const outbound = @import("outbound.zig");
const hello = @import("hello.zig");
const messages = @import("messages.zig");
const burn = @import("burn.zig");
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
pub const CertifiedKey = struct {
    chain: []const []const u8,
    /// Borrowed (`certverify.SecretKey` holds pointers): must outlive the
    /// connections that use it.
    key: certverify.SecretKey,
    /// A DER OCSPResponse to staple on the leaf when the client asks
    /// (RFC 8446 §4.4.2.1). Empty counts as none (rustls). The module does
    /// not parse it: refreshing it before it expires is the caller's job.
    ocsp_response: ?[]const u8 = null,
    /// A `SignedCertificateTimestampList` (RFC 6962 §3.3, with its 2-octet
    /// length) to send on the leaf when the client asks (§3.3.1). Empty
    /// counts as none.
    sct_list: ?[]const u8 = null,

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
    };

    pub const max_chain_len = 16;

    /// What the handshake would refuse with `internal_error`, reported
    /// up front: call it when loading the certificate (a `select`
    /// callback's keys are checked again at every handshake).
    pub fn check(self: *const CertifiedKey) CheckError!void {
        if (self.chain.len == 0 or self.chain.len > max_chain_len) return error.ChainLength;
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

pub const Config = struct {
    certificate: union(enum) {
        fixed: *const CertifiedKey,
        select: CertificateSelector,
    },
    /// The suites the server enables (the client's order decides).
    cipher_suites: []const record.CipherSuite = &default_cipher_suites,
    /// The groups the server enables (the client's order decides).
    groups: []const u16 = &default_groups,
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
};

/// rustls's (ring provider) `supported_verify_schemes`: ECDSA P-384 and
/// P-256, Ed25519, RSA-PSS, then RSA PKCS#1 v1.5 — for certificates only,
/// never a TLS 1.3 CertificateVerify.
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
    /// into `out`; null for anything else.
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

/// The longest ticket plaintext: the `SessionState` prefix with a SHA-384
/// secret and a 1-octet nonce, then this server's fields (`TicketFields`).
const max_ticket_plaintext = tlsresume.select.SessionState(48).wireLen(1) + TicketFields.max_len;

/// The ticket blob a `Ticketer` may return (a `StekRing`'s adds 29 octets).
const max_ticket_len = max_ticket_plaintext + 128;

/// PSK identities looked at in one ClientHello; later ones are ignored.
const max_psk_identities = 32;

/// What this server appends to the `SessionState` in a ticket. The suite is
/// last, so it is read from the same place whichever hash length the prefix
/// was parsed with: a ticket of the other hash never matches the suite.
const TicketFields = struct {
    sni: ?[]const u8,
    alpn: ?[]const u8,
    /// The client's certificate (DER leaf), if it authenticated, and the
    /// scheme of its CertificateVerify (0 without one).
    peer: ?[]const u8,
    peer_scheme: u16 = 0,
    /// When the client proved that certificate (the full handshake's time,
    /// carried across resumptions), ms since the epoch.
    peer_auth_ms: i64 = 0,
    suite: u16,

    const format: u8 = 2;
    const max_len = 1 + 1 + 255 + 1 + 255 + 2 + clientauth.max_leaf_len + 2 + 8 + 2;

    fn write(f: TicketFields, out: []u8) usize {
        var n: usize = 0;
        out[n] = format;
        n += 1;
        for ([_]?[]const u8{ f.sni, f.alpn }) |v| {
            const b = v orelse "";
            out[n] = @intCast(b.len);
            @memcpy(out[n + 1 ..][0..b.len], b);
            n += 1 + b.len;
        }
        const p = f.peer orelse "";
        std.mem.writeInt(u16, out[n..][0..2], @intCast(p.len), .big);
        @memcpy(out[n + 2 ..][0..p.len], p);
        n += 2 + p.len;
        std.mem.writeInt(u16, out[n..][0..2], f.peer_scheme, .big);
        std.mem.writeInt(i64, out[n + 2 ..][0..8], f.peer_auth_ms, .big);
        std.mem.writeInt(u16, out[n + 10 ..][0..2], f.suite, .big);
        return n + 12;
    }

    /// Null for anything this server did not write (another format).
    fn parse(tail: []const u8) ?TicketFields {
        if (tail.len < 7 or tail[0] != format) return null;
        var at: usize = 1;
        var v: [2]?[]const u8 = undefined;
        for (&v) |*x| {
            if (at >= tail.len) return null;
            const n: usize = tail[at]; // not u8: `1 + n` overflows at 255
            if (tail.len - at - 1 < n) return null;
            x.* = if (n == 0) null else tail[at + 1 ..][0..n];
            at += 1 + n;
        }
        if (tail.len - at < 2) return null;
        const n: usize = std.mem.readInt(u16, tail[at..][0..2], .big);
        at += 2;
        if (tail.len - at < n or n > clientauth.max_leaf_len) return null;
        const peer: ?[]const u8 = if (n == 0) null else tail[at..][0..n];
        at += n;
        if (tail.len - at != 12) return null;
        return .{
            .sni = v[0],
            .alpn = v[1],
            .peer = peer,
            .peer_scheme = std.mem.readInt(u16, tail[at..][0..2], .big),
            .peer_auth_ms = std.mem.readInt(i64, tail[at + 2 ..][0..8], .big),
            .suite = std.mem.readInt(u16, tail[at + 10 ..][0..2], .big),
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
    /// Out: the client certificate of the last ticket accepted (the one
    /// `selectPsk` took, if it took one), a slice of its scratch, and the
    /// scheme it signed with.
    peer: ?[]const u8 = null,
    peer_scheme: u16 = 0,
    peer_auth_ms: i64 = 0,

    fn accepts(w: *Resumable, tail: []const u8, age_ms: i64) bool {
        const f = TicketFields.parse(tail) orelse return false;
        if (f.suite != w.suite or !Server.optEql(f.sni, w.sni) or age_ms > w.lifetime_ms) return false;
        if (w.need_peer and f.peer == null) return false;
        if (f.peer != null and (f.peer_auth_ms > w.now_ms or w.now_ms - f.peer_auth_ms > w.lifetime_ms)) return false;
        w.peer = f.peer;
        w.peer_scheme = f.peer_scheme;
        w.peer_auth_ms = f.peer_auth_ms;
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
    /// More than `max_key_updates` KeyUpdates without application data
    /// between them (`unexpected_message`, as BoringSSL; rustls closes
    /// without an alert).
    TooManyKeyUpdates,
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
        error.OutputFull, error.Closed, error.NotConnected => null,
        error.TooManyKeyUpdates => .unexpected_message,
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
    var tickets: usize = 0;
    if (cfg.tickets) |tk| {
        const one = 4 + 4 + 4 + 1 + 1 + 2 + max_ticket_len + 2 + 4;
        tickets = tk.count * one;
        tickets += (tickets / record.max_plaintext_len + 1) * (record.header_len + 1 + record.tag_len);
    }
    return @max(firstFlightLen(ck) + request, tickets + outbound.alert_reserve + 64);
}

fn firstFlightLen(ck: *const CertifiedKey) usize {
    var chain: usize = 3;
    for (ck.chain) |c| chain += 3 + c.len + 2;
    if (ck.ocspStaple()) |o| chain += 4 + 4 + o.len;
    if (ck.sctList()) |l| chain += 4 + l.len;
    const sig = for (certverify.candidateSchemes(ck.key)) |s| {
        break certverify.maxSignatureLen(s);
    } else 0;
    const hrr = record.header_len + (4 + 2 + 32 + 33 + 3 + 2 + 6 + 6) + 6;
    const flight = hrr + (4 + 2 + 32 + 33 + 3 + 2 + 8 + kex.hybrid_server_share_len + 6) + // ServerHello
        6 + // CCS
        (4 + 2 + 4 + 2 + 1 + 255 + 4) + // EncryptedExtensions
        (4 + 1 + chain) + (4 + 4 + sig) + (4 + 48);
    const records = flight / record.max_plaintext_len + 6;
    return flight + records * (record.header_len + 1 + record.tag_len) + outbound.alert_reserve + 64;
}

pub const Event = union(enum) {
    /// Everything buffered was used: read more and feed again.
    need_more,
    /// The client's Finished verified: the connection is up.
    handshake_done,
    /// Application data, a slice of the buffer given to `feed` (inside
    /// `consumed`: use it before discarding those octets).
    app_data: []u8,
    /// The client sent close_notify. It may still be written to.
    peer_closed,
};

pub const Result = struct {
    event: Event,
    consumed: usize,
};

const State = enum { client_hello, client_hello_retry, client_certificate, client_certificate_verify, client_finished, connected, failed };

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
    /// The handshake resumed a session (a ticket's PSK was accepted).
    resumed: bool = false,
    /// The client's certificate (DER leaf), `peer_len` octets: from its
    /// Certificate, or from the ticket resumed.
    peer_buf: [clientauth.max_leaf_len]u8 = undefined,
    peer_len: u16 = 0,
    /// The client proved it holds the key of `peer_buf` (its
    /// CertificateVerify verified, or the ticket was issued after one).
    peer_authenticated: bool = false,
    /// The scheme of the client's CertificateVerify (0: none), from the
    /// ticket on a resumption.
    peer_scheme: u16 = 0,
    /// When the client proved `peer_buf` (`TicketFields.peer_auth_ms`).
    peer_auth_ms: i64 = 0,

    /// secret-api-ok: returns the initial state; every secret field is zero until `feed` runs a handshake step (under `burn.handshake_burn`).
    pub fn init(config: *const Config, joiner_buf: []u8, output_buf: []u8) Server {
        return .{
            .config = config,
            .inbound = .init(joiner_buf),
            .out = .init(output_buf),
        };
    }

    /// Wipe every secret and both buffers.
    pub fn deinit(self: *Server) void {
        self.inbound.wipe();
        self.out.wipe();
        self.wipeHandshakeSecrets();
        std.crypto.secureZero(u8, &self.master_secret);
        std.crypto.secureZero(u8, &self.client_application_secret);
        std.crypto.secureZero(u8, &self.server_application_secret);
        self.state = .failed;
    }

    fn wipeHandshakeSecrets(self: *Server) void {
        std.crypto.secureZero(u8, &self.handshake_secret);
        std.crypto.secureZero(u8, &self.client_handshake_secret);
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

    /// The client's certificate (DER, the leaf of the chain the
    /// `ClientCertVerifier` accepted), once the client proved it holds its
    /// key; null without client authentication. On a resumption, the one
    /// of the handshake that issued the ticket. Valid while `self` is.
    pub fn peerCertificate(self: *const Server) ?[]const u8 {
        return if (self.peer_authenticated) self.peer_buf[0..self.peer_len] else null;
    }

    /// The signature scheme of the client's CertificateVerify (null: no
    /// client certificate). On a resumption, the one of the handshake that
    /// issued the ticket (BoringSSL `SSL_get_peer_signature_algorithm`).
    pub fn peerSignatureScheme(self: *const Server) ?u16 {
        return if (self.peer_authenticated and self.peer_scheme != 0) self.peer_scheme else null;
    }

    pub fn pendingOutput(self: *const Server) []const u8 {
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
        if (self.state == .failed) return error.Closed;
        self.flushKeyUpdate() catch |err| return self.fail(err);
        var at: usize = 0;
        while (true) {
            const r = self.inbound.next(buf[at..]) catch |err| return self.fail(err);
            at += r.consumed;
            switch (r.event) {
                .need_more => return .{ .event = .need_more, .consumed = at },
                .app_data => |d| {
                    self.key_updates_left = max_key_updates;
                    return .{ .event = .{ .app_data = d }, .consumed = at };
                },
                .peer_closed => {
                    self.peer_closed = true;
                    return .{ .event = .peer_closed, .consumed = at };
                },
                .handshake => |m| {
                    const done = self.onHandshake(m) catch |err| return self.fail(err);
                    if (done) return .{ .event = .handshake_done, .consumed = at };
                },
            }
        }
    }

    /// Seal application data into the output, as much as fits (at least
    /// one octet unless the output is full). Returns how much was taken.
    pub fn write(self: *Server, data: []const u8) Error!usize {
        switch (self.state) {
            .connected => {},
            .failed => return error.Closed,
            else => return error.NotConnected,
        }
        if (self.write_closed) return error.Closed;
        var done: usize = 0;
        while (done < data.len) {
            // RFC 8446 §5.5: retire the key well before its usage limit.
            if (self.out.tx.seq >= max_records_per_key and self.tx_update == null)
                self.tx_update = .update_requested;
            self.flushKeyUpdate() catch |err| return self.fail(err);
            if (self.tx_update != null) break;
            const s = self.out.slot();
            if (s.len == 0) break;
            const n = @min(s.len, data.len - done, record.max_plaintext_len);
            @memcpy(s[0..n], data[done..][0..n]);
            self.out.commit(.application_data, n) catch |err| return self.fail(err);
            done += n;
        }
        if (done == 0 and data.len != 0) return error.OutputFull;
        return done;
    }

    /// Turn the send key over now (RFC 8446 §4.6.3), asking the client to
    /// turn its own over too when `request` is `update_requested`. The
    /// KeyUpdate goes out before any later record — at once if the output
    /// has room. A KeyUpdate already due is not repeated, but one due
    /// without a request is turned into `update_requested` if that is asked.
    pub fn keyUpdate(self: *Server, request: KeyUpdateRequest) Error!void {
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
            if (!self.write_closed) if (alertFor(e)) |d| {
                const a: alert.Alert = if (d == .close_notify) .close_notify else .fatal(d);
                self.out.write(.alert, &a.encode()) catch {};
            };
            self.state = .failed;
            // A failed handshake reports no identity.
            self.peer_authenticated = false;
            self.out.wipeKey();
            self.inbound.wipe();
            self.wipeHandshakeSecrets();
            std.crypto.secureZero(u8, &self.master_secret);
            std.crypto.secureZero(u8, &self.client_application_secret);
            std.crypto.secureZero(u8, &self.server_application_secret);
        }
        return e;
    }

    fn onHandshake(self: *Server, m: inbound.HandshakeMessage) Error!bool {
        const t: messages.HandshakeType = @fromBackingInt(m.msg_type);
        switch (self.state) {
            .client_hello, .client_hello_retry => {
                if (t != .client_hello) return error.UnexpectedMessage;
                try burn.run(burn.handshake_burn, Error!void, onClientHello, .{ self, m });
                return false;
            },
            // No secret is touched: the chain and the signature are public.
            .client_certificate => {
                if (t != .certificate) return error.UnexpectedMessage;
                try self.onClientCertificate(m);
                return false;
            },
            .client_certificate_verify => {
                if (t != .certificate_verify) return error.UnexpectedMessage;
                try self.onClientCertificateVerify(m);
                return false;
            },
            .client_finished => {
                if (t != .finished) return error.UnexpectedMessage;
                try burn.run(burn.handshake_burn, Error!void, onClientFinished, .{ self, m });
                return true;
            },
            // Of the post-handshake messages a client sends only KeyUpdate
            // (no post-handshake authentication is requested).
            .connected => {
                if (t != .key_update) return error.UnexpectedMessage;
                try self.onKeyUpdate(m);
                return false;
            },
            .failed => unreachable,
        }
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

    fn onClientHello(self: *Server, m: inbound.HandshakeMessage) Error!void {
        const cfg = self.config;
        const retried = self.state == .client_hello_retry;
        const ch = hello.parseClientHello(m.body) catch |err| return switch (err) {
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
        // The version first: a TLS 1.2 (or older) client gets
        // `protocol_version` whatever else its hello lacks (rustls order).
        const versions = ch.supportedVersions() orelse return error.ProtocolVersion;
        if (!versions.contains(messages.tls13_version)) return error.ProtocolVersion;
        const sig_algs = ch.signatureAlgorithms() orelse return error.HandshakeFailure;

        const ck: *const CertifiedKey = switch (cfg.certificate) {
            .fixed => |k| k,
            .select => |s| s.select(s.ctx, sni, &ch) orelse return error.AccessDenied,
        };
        ck.check() catch return error.InternalError;
        const scheme = for (certverify.candidateSchemes(ck.key)) |s| {
            if (sig_algs.contains(@backingInt(s)) and certverify.canSign(ck.key, s)) break s;
        } else return error.HandshakeFailure;

        var cs = ch.cipherSuites();
        var suite: record.CipherSuite = while (cs.next()) |c| {
            const cand: record.CipherSuite = @fromBackingInt(c);
            if (cand.hashLen() != null and std.mem.indexOfScalar(record.CipherSuite, cfg.cipher_suites, cand) != null) break cand;
        } else return error.HandshakeFailure;
        // RFC 8446 §4.1.4: the ServerHello repeats the HelloRetryRequest's
        // suite, so the second hello must still offer it (stricter than
        // rustls, which re-chooses and compares only the hash: a client
        // would abort on the change anyway).
        if (retried) {
            if (!ch.cipherSuites().contains(@backingInt(self.suite))) return error.IllegalParameter;
            suite = self.suite;
        }
        // RFC 8446 §9.2: supported_groups and key_share come together.
        var gs = ch.supportedGroups() orelse return error.MissingExtension;
        var group: u16 = while (gs.next()) |g| {
            if (std.mem.indexOfScalar(u16, cfg.groups, g) != null) break g;
        } else return error.HandshakeFailure;
        // RFC 8446 §4.2.8: the second hello's share is for the group asked
        // for, whatever its supported_groups now prefer (rustls re-chooses).
        if (retried) group = self.group;

        if (ch.legacy_compression_methods.len != 1) return error.IllegalParameter;
        var shares = ch.keyShares() orelse return error.MissingExtension;
        var seen: std.StaticBitSet(1 << 16) = .empty;
        var share: ?[]const u8 = null;
        while (shares.next()) |e| {
            if (seen.isSet(e.group)) return error.IllegalParameter;
            seen.set(e.group);
            if (e.group == group) share = e.key_exchange;
        }
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
        if (cfg.tickets) |tk| {
            if (ch.pre_shared_key) |offer| {
                selected = switch (suite) {
                    .aes_256_gcm_sha384 => try self.choosePsk(S384, tk, m.body, offer, suite, sni, &psk_buf),
                    else => try self.choosePsk(S256, tk, m.body, offer, suite, sni, &psk_buf),
                };
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
            if (self.alpn == null and cfg.alpn_protocols.len != 0) return error.NoApplicationProtocol;
        }
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

        self.suite = suite;
        self.has_suite = true;
        self.group = group;
        switch (suite) {
            .aes_256_gcm_sha384 => try self.serverFlight(S384, m.raw, &ch, ck, scheme, group, &ex, !retried, psk, selected),
            else => try self.serverFlight(S256, m.raw, &ch, ck, scheme, group, &ex, !retried, psk, selected),
        }
        // Early data the client may have sent under a PSK we did not take
        // (never after a retry: refused above).
        self.inbound.skip_early = if (ch.early_data) record.max_plaintext_len else 0;
        self.state = if (cfg.client_auth != null and psk == null) .client_certificate else .client_finished;
    }

    /// RFC 8446 §4.2.11 through `tlsresume.select.selectPsk`: the index of
    /// the identity taken, its PSK in `psk_out`; null for a full handshake.
    fn choosePsk(
        self: *Server,
        comptime H: type,
        tk: *const Tickets,
        body: []const u8,
        offer: hello.PreSharedKey,
        suite: record.CipherSuite,
        sni: ?[]const u8,
        psk_out: *[48]u8,
    ) Error!?u16 {
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
        var empty_hash: [L]u8 = undefined;
        H.Hash.hash("", &empty_hash, .{});

        const now_ms = tk.clock.now_ms(tk.clock.ctx);
        var want: Resumable = .{
            .suite = @backingInt(suite),
            .sni = sni,
            .lifetime_ms = @as(i64, @min(tk.lifetime_s, max_ticket_lifetime_s)) * 1000,
            .now_ms = now_ms,
            .need_peer = if (self.config.client_auth) |ca| ca.mandatory else false,
        };
        const ring: TicketerRing = .{ .t = tk.ticketer };
        var scratch: [max_ticket_plaintext]u8 = undefined;
        defer std.crypto.secureZero(u8, &scratch);
        var sel: tlsresume.select.Selection(L) = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&sel));
        tlsresume.select.selectPsk(H.Hkdf, H.Hmac, TicketerRing, &sel, &ring, .{}, ids[0..n], binders[0..n], &empty_hash, &th, now_ms, null, null, .{ .ctx = &want, .accept = Resumable.accept }, &scratch) catch |err| return switch (err) {
            error.NoAcceptableIdentity => null,
            error.BinderMismatch => error.DecryptError,
        };
        @memcpy(psk_out[0..L], &sel.psk);
        // The ticket's client certificate (in `scratch`, which `selectPsk`
        // last opened the taken ticket into). Kept even if the psk modes
        // then refuse the resumption: `peer_authenticated` decides.
        if (want.peer) |p| {
            @memcpy(self.peer_buf[0..p.len], p);
            self.peer_len = @intCast(p.len);
            self.peer_scheme = want.peer_scheme;
            self.peer_auth_ms = want.peer_auth_ms;
        }
        return @intCast(sel.selected_index);
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
        self.inbound.skip_early = if (ch.early_data) record.max_plaintext_len else 0;
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
    ) Error!void {
        const cfg = self.config;
        const t = H.transcript(&self.transcript);
        t.append(client_hello_raw[0], client_hello_raw[4..]);

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

        // RFC 8446 §7.1: the PSK, or zeros.
        const L = H.len;
        var empty_hash: [L]u8 = undefined;
        H.Hash.hash("", &empty_hash, .{});
        var early: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &early);
        const zeros: [L]u8 = @splat(0);
        tls13.keyschedule.earlySecret(H.Hkdf, &early, psk orelse &zeros);
        const hs = self.handshake_secret[0..L];
        ks.deriveHandshakeSecret(H.Hkdf, hs, &early, &empty_hash, ex.shared.slice());
        var server_hs: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &server_hs);
        var th = t.currentHash();
        ks.deriveHandshakeTrafficSecrets(H.Hkdf, self.client_handshake_secret[0..L], &server_hs, hs, &th);
        self.out.installTx(self.suite, &server_hs) catch return error.InternalError;
        self.inbound.installRx(self.suite, self.client_handshake_secret[0..L]) catch |err| return switch (err) {
            error.UnexpectedMessage => error.UnexpectedMessage,
            else => error.InternalError,
        };

        // EncryptedExtensions.
        var alpn_body: [2 + 1 + 255]u8 = undefined;
        var exts: [2]messages.Extension = undefined;
        var n_exts: usize = 0;
        if (self.alpn) |p| {
            exts[n_exts] = .{ .type = 16, .data = try encoded(messages.alpnData(&alpn_body, p)) };
            n_exts += 1;
        }
        // RFC 6066 §3: not when resuming (rustls).
        if (self.sni_len != null and psk == null) {
            exts[n_exts] = .{ .type = 0, .data = "" };
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
            // leaf if the client asked (`check` bounded the chain).
            var entries: [CertifiedKey.max_chain_len]messages.CertificateEntry = undefined;
            for (ck.chain, 0..) |der, i| entries[i] = .{ .cert_data = der };
            if (ch.ocsp_requested) entries[0].ocsp_response = ck.ocspStaple();
            if (ch.sct_requested) entries[0].sct_list = ck.sctList();
            try self.send(H, try encoded(messages.certificate(self.out.slot(), "", entries[0..ck.chain.len])));

            // CertificateVerify over the transcript through Certificate.
            th = t.currentHash();
            var sig_buf: [1024]u8 = undefined;
            const sig = certverify.sign(scheme, ck.key, .server, &th, cfg.random, &sig_buf) catch return error.InternalError;
            try self.send(H, try encoded(messages.certificateVerify(self.out.slot(), @backingInt(scheme), sig)));
        }

        // Finished.
        th = t.currentHash();
        var finished_key: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &finished_key);
        ks.deriveFinishedKey(H.Hkdf, L, &finished_key, &server_hs);
        var verify_data: [L]u8 = undefined;
        tls13.keyschedule.computeFinishedVerifyData(H.Hmac, &verify_data, &finished_key, &th);
        try self.send(H, try encoded(messages.finished(self.out.slot(), &verify_data)));

        // Application secrets over the transcript through the server's
        // Finished; the server sends under its application key from here.
        const ms = self.master_secret[0..L];
        ks.deriveMasterSecret(H.Hkdf, ms, hs, &empty_hash);
        th = t.currentHash();
        ks.deriveApplicationTrafficSecrets(H.Hkdf, self.client_application_secret[0..L], self.server_application_secret[0..L], ms, &th);
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
        if (chain[0].len > clientauth.max_leaf_len) return error.BadCertificate;
        // The leaf must be able to sign the CertificateVerify, whatever
        // the verifier says (BoringSSL checks both here, before it).
        _ = try clientauth.leafPublicKey(chain[0]);
        try clientauth.checkLeafKeyUsage(chain[0]);
        const now_s = @divFloor(ca.clock.now_ms(ca.clock.ctx), 1000);
        try ca.verifier.verify(ca.verifier.ctx, chain[0..n], now_s);
        @memcpy(self.peer_buf[0..chain[0].len], chain[0]);
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
        const key = try clientauth.leafPublicKey(self.peer_buf[0..self.peer_len]);
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
        if (m.body.len != L or !std.crypto.timing_safe.eql([L]u8, expected, m.body[0..L].*)) return error.DecryptError;
        t.append(m.msg_type, m.body);
        self.inbound.installRx(self.suite, self.client_application_secret[0..L]) catch |err| return switch (err) {
            error.UnexpectedMessage => error.UnexpectedMessage,
            else => error.InternalError,
        };
        if (self.tickets_due != 0) {
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
        var plain: [max_ticket_plaintext]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain);
        var blob: [max_ticket_len]u8 = undefined;
        const fields: TicketFields = .{ .sni = self.serverName(), .alpn = self.alpn, .peer = self.peerCertificate(), .peer_scheme = self.peerSignatureScheme() orelse 0, .peer_auth_ms = self.peer_auth_ms, .suite = @backingInt(self.suite) };
        const slot = self.out.slot();
        var used: usize = 0;
        for (0..self.tickets_due) |i| {
            const nonce = [1]u8{@intCast(i)};
            state.ticket_nonce = &nonce;
            state.ticket_age_add = self.config.random.int(u32);
            const prefix = state.serialize(&plain) catch unreachable; // sized for it
            const n = prefix.len + fields.write(plain[prefix.len..]);
            var aead_nonce: [12]u8 = undefined;
            self.config.random.bytes(&aead_nonce);
            const ticket = tk.ticketer.seal(tk.ticketer.ctx, plain[0..n], aead_nonce, &blob) orelse break;
            if (ticket.len == 0 or ticket.len > max_ticket_len) break;
            const g: u16 = self.config.random.int(u4);
            const grease = [_]tlsresume.ticket.Extension{.{ .ext_type = (g << 12) | (g << 4) | 0x0a0a, .data = "" }};
            if (slot.len - used < 4) break;
            const body = (tlsresume.ticket.NewSessionTicket{
                .ticket_lifetime = @min(tk.lifetime_s, max_ticket_lifetime_s),
                .ticket_age_add = state.ticket_age_add,
                .ticket_nonce = &nonce,
                .ticket = ticket,
                .extensions = &grease,
            }).encode(slot[used + 4 ..]) catch break;
            slot[used] = @backingInt(messages.HandshakeType.new_session_ticket);
            std.mem.writeInt(u24, slot[used + 1 ..][0..3], @intCast(body.len), .big);
            used += 4 + body.len;
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
    /// Octets of a next handshake message in the same record.
    trailing: []const u8 = "",
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
    try b.appendSlice(gpa, &.{ 3, 3 });
    try b.appendNTimes(gpa, 0x42, 32);
    try b.append(gpa, 0);
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
    if (h.psk_without_modes) {
        const psk = [_]u8{ 0, 7, 0, 1, 0xaa, 0, 0, 0, 0, 0, 33, 32 } ++ @as([32]u8, @splat(0x55));
        try W.ext(&e, gpa, 41, &psk);
    }
    if (h.psk_modes) |m| {
        var d: [8]u8 = undefined;
        d[0] = @intCast(m.len);
        @memcpy(d[1..][0..m.len], m);
        try W.ext(&e, gpa, 45, d[0 .. 1 + m.len]);
    }
    if (h.early_data) try W.ext(&e, gpa, 42, "");
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

test "refusals and their alerts" {
    // Not TLS 1.3.
    try expectRefusal(.{ .versions = null }, error.ProtocolVersion, .protocol_version);
    try expectRefusal(.{ .versions = &.{ 0x0303, 0x0302 } }, error.ProtocolVersion, .protocol_version);
    // Nothing to sign with, nothing in common.
    try expectRefusal(.{ .sig_algs = null }, error.HandshakeFailure, .handshake_failure);
    try expectRefusal(.{ .sig_algs = &.{ 0x0807, 0x0804 } }, error.HandshakeFailure, .handshake_failure);
    try expectRefusal(.{ .suites = &.{ 0xc02f, 0x1304 } }, error.HandshakeFailure, .handshake_failure);
    try expectRefusal(.{ .groups = null }, error.MissingExtension, .missing_extension);
    // The version is checked before anything else the hello lacks.
    try expectRefusal(.{ .versions = null, .sig_algs = null, .groups = null }, error.ProtocolVersion, .protocol_version);
    try expectRefusal(.{ .groups = &.{ 0x0019, 0x0100 } }, error.HandshakeFailure, .handshake_failure);
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
    for ([_][]const u8{ &s2.handshake_secret, &s2.client_handshake_secret, &s2.master_secret, &s2.client_application_secret, &s2.server_application_secret }) |sec|
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
    } else |err| res.err = err;
    const p = s.pendingOutput();
    res.out_len = @min(p.len, res.out.len);
    @memcpy(res.out[0..res.out_len], p[0..res.out_len]);
    return res;
}

const p256_only: Hello = .{ .groups = &.{ 0x0017, 0x001d }, .shares = &.{.{ 0x0017, "" }} };
const x25519_share_first: Hello = .{ .groups = &.{ 0x0017, 0x001d }, .shares = &.{.{ 0x001d, "" }} };

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
    while (p.s.out.slot().len > 64) _ = try p.s.write(&@as([1024]u8, @splat('x')));
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
    while (p.s.out.slot().len > 64) _ = try p.s.write(&@as([1024]u8, @splat('x')));
    while (p.s.out.slot().len > 0) _ = p.s.write("y") catch break;
    _ = try p.sendKeyUpdate(1);
    try testing.expect(p.s.tx_update != null);
    _ = try p.drain();
    var empty: [0]u8 = .{};
    _ = try p.s.feed(&empty);
    try testing.expect(p.s.tx_update == null);
    try testing.expectEqual(@as(usize, 1), (try p.drain()).n_updates);
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

test "ticket fields: round trip, and what a ClientHello may resume" {
    var buf: [TicketFields.max_len]u8 = undefined;
    const long_alpn: [255]u8 = @splat('a');
    const long_sni: [253]u8 = @splat('b');
    const long_peer: [clientauth.max_leaf_len]u8 = @splat('c');
    for ([_]TicketFields{
        .{ .sni = "example.com", .alpn = "h2", .peer = null, .suite = 0x1302 },
        .{ .sni = null, .alpn = null, .peer = "LEAF", .peer_scheme = 0x0804, .suite = 0x1301 },
        .{ .sni = &long_sni, .alpn = &long_alpn, .peer = &long_peer, .peer_scheme = 0x0403, .suite = 0x1303 },
    }) |f| {
        const n = f.write(&buf);
        const back = TicketFields.parse(buf[0..n]).?;
        try testing.expect(Server.optEql(f.sni, back.sni) and Server.optEql(f.alpn, back.alpn) and
            Server.optEql(f.peer, back.peer) and f.peer_scheme == back.peer_scheme and f.suite == back.suite);
        // Every truncation, an extra octet and another format are refused.
        for (0..n) |cut| try testing.expect(TicketFields.parse(buf[0..cut]) == null);
        if (n < buf.len) {
            buf[n] = 0;
            try testing.expect(TicketFields.parse(buf[0 .. n + 1]) == null);
        }
        buf[0] ^= 1;
        try testing.expect(TicketFields.parse(buf[0..n]) == null);
    }
    // A peer longer than the cap is not this server's (its octets there).
    var over: [TicketFields.max_len + 1]u8 = undefined;
    const too_long: [clientauth.max_leaf_len + 1]u8 = @splat('d');
    const no = (TicketFields{ .sni = null, .alpn = null, .peer = &too_long, .suite = 0x1301 }).write(&over);
    try testing.expect(TicketFields.parse(over[0..no]) == null);

    const n = (TicketFields{ .sni = "example.com", .alpn = null, .peer = null, .suite = 0x1301 }).write(&buf);
    const tail = buf[0..n];
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
    const n2 = (TicketFields{ .sni = null, .alpn = null, .peer = null, .suite = 0x1301 }).write(&buf);
    try testing.expect(other.accepts(buf[0..n2], 0));
    try testing.expect(!want.accepts(buf[0..n2], 0));

    // A mandatory client certificate: only a ticket that carries one, which
    // is handed out.
    var need: Resumable = .{ .suite = 0x1301, .sni = null, .lifetime_ms = 1000, .need_peer = true };
    try testing.expect(!need.accepts(buf[0..n2], 0));
    try testing.expectEqual(null, need.peer);
    const n3 = (TicketFields{ .sni = null, .alpn = null, .peer = "LEAF", .peer_scheme = 0x0807, .suite = 0x1301 }).write(&buf);
    try testing.expect(need.accepts(buf[0..n3], 0));
    try testing.expectEqualStrings("LEAF", need.peer.?);
    try testing.expectEqual(@as(u16, 0x0807), need.peer_scheme);
    // The certificate is good for the lifetime from its proof, whatever
    // the ticket's own age (a re-issued ticket is young).
    const n4 = (TicketFields{ .sni = null, .alpn = null, .peer = "LEAF", .peer_auth_ms = 5_000, .suite = 0x1301 }).write(&buf);
    need.now_ms = 6_000;
    try testing.expect(need.accepts(buf[0..n4], 0));
    try testing.expectEqual(@as(i64, 5_000), need.peer_auth_ms);
    need.now_ms = 6_001;
    try testing.expect(!need.accepts(buf[0..n4], 0));
    need.now_ms = 4_999; // proved in the future
    try testing.expect(!need.accepts(buf[0..n4], 0));
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
fn rfc8448S6Server(cfg: *const Config, joiner: []u8, out: []u8) Server {
    const kat = @import("message_kat_vectors.zig");
    var s: Server = .init(cfg, joiner, out);
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

test "RFC 8448 §6: the client's Certificate and CertificateVerify (RSA-PSS) verify" {
    const kat = @import("message_kat_vectors.zig");
    var prng = std.Random.DefaultPrng.init(1);
    var auth: ClientAuth = .{ .verifier = .{ .verify = AcceptAny.verify }, .clock = .{ .now_ms = AcceptAny.clock } };
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random(), .client_auth = &auth };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [4096]u8 = undefined;
    // The leaf: certificate_list at 4 + 1 + 3, its cert_data length first.
    const cert_msg = &kat.rfc8448_s6_client_certificate;
    const leaf = cert_msg[11..][0..std.mem.readInt(u24, cert_msg[8..11], .big)];
    {
        var s = rfc8448S6Server(&cfg, &joiner, &out);
        try testing.expect(!try s.onHandshake(handshakeMessage(cert_msg)));
        try testing.expectEqual(null, s.peerCertificate()); // not before its CertificateVerify
        try testing.expect(!try s.onHandshake(handshakeMessage(&kat.rfc8448_s6_client_certificate_verify)));
        try testing.expectEqual(State.client_finished, s.state);
        try testing.expectEqualSlices(u8, leaf, s.peerCertificate().?);
        // The client's Finished, over the transcript through its
        // CertificateVerify, under the RFC's client handshake secret.
        s.client_handshake_secret[0..32].* = kat.rfc8448_s6_client_handshake_secret;
        try testing.expect(try s.onHandshake(handshakeMessage(&kat.rfc8448_s6_client_finished)));
        try testing.expect(s.isConnected());
    }
    // One signature octet off: decrypt_error.
    {
        var cv = kat.rfc8448_s6_client_certificate_verify;
        cv[cv.len - 1] ^= 1;
        var s = rfc8448S6Server(&cfg, &joiner, &out);
        _ = try s.onHandshake(handshakeMessage(cert_msg));
        try testing.expectError(error.DecryptError, s.onHandshake(handshakeMessage(&cv)));
    }
    // A scheme the server did not ask for, and RSA PKCS#1 v1.5 (asked for,
    // for certificates only): illegal_parameter.
    for ([_]struct { []const u16, u16 }{ .{ &.{0x0403}, 0x0804 }, .{ &.{ 0x0804, 0x0401 }, 0x0401 } }) |c| {
        auth.schemes = c[0];
        var cv = kat.rfc8448_s6_client_certificate_verify;
        std.mem.writeInt(u16, cv[4..6], c[1], .big);
        var s = rfc8448S6Server(&cfg, &joiner, &out);
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
        var s = rfc8448S6Server(&cfg, &joiner, &out);
        try testing.expectError(error.UnsupportedCertificate, s.onHandshake(handshakeMessage(&msg)));
        try testing.expectEqual(alert.Description.unsupported_certificate, alertFor(error.UnsupportedCertificate).?);
    }
    // Out of order: a Finished where the Certificate belongs.
    {
        var s = rfc8448S6Server(&cfg, &joiner, &out);
        try testing.expectError(error.UnexpectedMessage, s.onHandshake(handshakeMessage(&kat.rfc8448_s6_client_finished)));
    }
}
