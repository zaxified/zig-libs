// SPDX-License-Identifier: MIT

//! RFC 4954 — the SMTP AUTH extension, PLAIN (RFC 4616), LOGIN, and the OAuth 2
//! bearer mechanisms XOAUTH2 (Google/Microsoft) and OAUTHBEARER (RFC 7628).
//!
//! Both mechanisms transmit the password in the clear after a base64 encode
//! that is not encryption. RFC 4954 §9 (Security Considerations), last
//! paragraph, verbatim: "If an implementation supports SASL mechanisms that
//! are vulnerable to passive eavesdropping attacks (such as [PLAIN]), then the
//! implementation MUST support at least one configuration where these SASL
//! mechanisms are not advertised or used without the presence of an external
//! security layer such as [TLS]." `session.zig` is that configuration, and it
//! is the default — AUTH is refused on a plaintext link unless the caller sets
//! `Options.allow_plaintext_auth`, and the refusal is a typed error, not a
//! warning.
//!
//! Earlier revisions of this file, `session.zig`, `README.md` and `SPEC.md`
//! cited "RFC 4954 §14" for that rule and quoted a sentence — "the AUTH
//! command ... MUST NOT be used over an unencrypted connection unless the
//! client has explicitly requested it" — which appears nowhere in RFC 4954.
//! §14 is "Additional Requirements When Using SASL PLAIN over TLS" and is
//! about certificate and hostname verification once TLS is already up. The
//! error is recorded here rather than silently overwritten (audit BD-26).
//!
//! LOGIN was never standardised (it has no RFC; the challenges are the literal
//! base64 of "Username:" and "Password:"). It is implemented because a large
//! minority of servers offer nothing else, and it is chosen only after PLAIN.
//!
//! SCRAM-SHA-256 (RFC 5802, RFC 7677) is client side only, without channel
//! binding (GS2 header `n,,`), see `ScramClient`.
//!
//! Credentials are validated before they are encoded: a NUL byte inside a
//! PLAIN credential would forge the field separators of RFC 4616, and a CR or
//! LF anywhere would forge a whole SMTP command line.

const std = @import("std");
const testing = std.testing;

pub const AuthError = error{
    /// A NUL in a credential (would forge the RFC 4616 field separator) or a
    /// CR/LF (would forge a command line).
    InvalidCredential,
    /// The encoded response does not fit the caller's buffer.
    NoSpaceLeft,
    /// The server sent a challenge that is not valid base64.
    MalformedChallenge,
    /// The server sent a challenge we do not understand for this mechanism.
    UnexpectedChallenge,
    /// SCRAM: a credential with an octet above 127. SASLprep (RFC 4013, the
    /// RFC 5802 §2.2 normalisation) is NOT implemented; guessing at it would
    /// derive a key the server does not, so the login is refused instead.
    NonAsciiCredential,
    /// SCRAM: the server's iteration count is outside
    /// `scram_min_iterations..scram_max_iterations`.
    ScramIterationsOutOfRange,
    /// SCRAM: the server's `v=` signature is wrong or absent. The server does
    /// not know the password's verifier; the login must fail.
    ServerSignatureMismatch,
};

const b64 = std.base64.standard;
// Not std's encoder for the credential: it indexes its alphabet by the secret
// (with the old per-byte `checkCredential`: 312 memcheck contexts, ctgrind
// `smtp/auth`; 6 after, the single validity verdict per call).
const b64ct = @import("b64ct").standard;

/// The two challenges LOGIN uses, base64 as they appear on the wire.
pub const login_username_challenge = "VXNlcm5hbWU6"; // "Username:"
pub const login_password_challenge = "UGFzc3dvcmQ6"; // "Password:"

/// A credential must not hold NUL, CR or LF. Scanned without a branch per
/// byte (the password is secret; ctgrind `smtp/auth`): each
/// byte's match is a borrow-derived bit, ORed together and branched on once.
fn checkCredential(s: []const u8) AuthError!void {
    var bad: u8 = 0;
    for (s) |c| bad |= isZero(c) | isZero(c ^ '\r') | isZero(c ^ '\n');
    if (bad != 0) return error.InvalidCredential;
}

/// 1 when `x == 0`, else 0, without a branch.
inline fn isZero(x: u8) u8 {
    return @import("b64ct").eqMask(x, 0) & 1;
}

/// Encoded length of `n` raw octets (base64 with padding).
pub fn encodedLen(n: usize) usize {
    return b64.Encoder.calcSize(n);
}

/// RFC 4616 §2: `authzid NUL authcid NUL passwd`, base64-encoded. `authzid` is
/// almost always empty (an empty authorization identity means "the identity in
/// authcid").
pub fn plainResponse(buf: []u8, authzid: []const u8, authcid: []const u8, passwd: []const u8) AuthError![]const u8 {
    try checkCredential(authzid);
    try checkCredential(authcid);
    try checkCredential(passwd);
    const raw_len = authzid.len + 1 + authcid.len + 1 + passwd.len;
    if (encodedLen(raw_len) > buf.len) return error.NoSpaceLeft;

    // The raw form is built in a stack buffer that is wiped afterwards: it
    // holds the plaintext password.
    var raw: [1024]u8 = undefined;
    if (raw_len > raw.len) return error.NoSpaceLeft;
    defer std.crypto.secureZero(u8, raw[0..raw_len]);
    var i: usize = 0;
    @memcpy(raw[i..][0..authzid.len], authzid);
    i += authzid.len;
    raw[i] = 0;
    i += 1;
    @memcpy(raw[i..][0..authcid.len], authcid);
    i += authcid.len;
    raw[i] = 0;
    i += 1;
    @memcpy(raw[i..][0..passwd.len], passwd);
    i += passwd.len;
    return b64ct.encode(buf, raw[0..i]);
}

/// 1 when the octet is not a legal bearer-token byte (VCHAR, 0x21..0x7e;
/// RFC 6750 §2.1 b64token is a subset), without a branch: the token is secret.
inline fn badTokenByte(c: u8) u8 {
    const t: i16 = @as(i16, c) - 0x21;
    const lo: u16 = @as(u16, @bitCast(t)) >> 15; // c < 0x21
    const hi: u16 = @as(u16, @bitCast(@as(i16, 0x5d) - t)) >> 15; // c > 0x7e
    return @intCast(lo | hi);
}

/// Token: non-empty and every byte 0x21..0x7e (so no space, no \x01 field
/// separator, no control characters). One verdict per call.
fn checkToken(token: []const u8) AuthError!void {
    if (token.len == 0) return error.InvalidCredential;
    var bad: u8 = 0;
    for (token) |c| bad |= badTokenByte(c);
    if (bad != 0) return error.InvalidCredential;
}

/// A user name inside an OAuth initial response: no NUL, CR, LF, and no \x01
/// (the field separator, which would forge a whole `auth=` field).
fn checkUser(s: []const u8) AuthError!void {
    var bad: u8 = 0;
    for (s) |c| bad |= isZero(c) | isZero(c ^ '\r') | isZero(c ^ '\n') | isZero(c ^ 1);
    if (bad != 0) return error.InvalidCredential;
}

/// Raw (pre-base64) length of the XOAUTH2 initial response; the size of the
/// `scratch` buffer `xoauth2Response` needs.
pub fn xoauth2RawLen(user: []const u8, token: []const u8) usize {
    return "user=".len + user.len + "\x01auth=Bearer ".len + token.len + 2;
}

/// XOAUTH2 initial response (Google/Microsoft format), base64:
/// `user=<user>\x01auth=Bearer <token>\x01\x01`. `scratch` (at least
/// `xoauth2RawLen` bytes) holds the plaintext and is wiped before return.
pub fn xoauth2Response(buf: []u8, scratch: []u8, user: []const u8, token: []const u8) AuthError![]const u8 {
    try checkUser(user);
    try checkToken(token);
    const raw_len = xoauth2RawLen(user, token);
    if (raw_len > scratch.len or encodedLen(raw_len) > buf.len) return error.NoSpaceLeft;
    const raw = scratch[0..raw_len];
    defer std.crypto.secureZero(u8, raw);
    var w: RawWriter = .{ .out = raw };
    w.put("user=");
    w.put(user);
    w.put("\x01auth=Bearer ");
    w.put(token);
    w.put("\x01\x01");
    return b64ct.encode(buf, raw);
}

const RawWriter = struct {
    out: []u8,
    i: usize = 0,
    fn put(self: *RawWriter, s: []const u8) void {
        @memcpy(self.out[self.i..][0..s.len], s);
        self.i += s.len;
    }
};

/// RFC 5801 §4 GS2 name escaping inside `a=`: ',' is `=2C`, '=' is `=3D`.
fn gs2EscapedLen(s: []const u8) usize {
    var n: usize = 0;
    for (s) |c| n += if (c == ',' or c == '=') @as(usize, 3) else 1;
    return n;
}

/// Raw length of the OAUTHBEARER initial response; the `scratch` size for
/// `oauthbearerResponse`.
pub fn oauthbearerRawLen(user: []const u8, token: []const u8) usize {
    const a = if (user.len == 0) 0 else "a=".len + gs2EscapedLen(user);
    return "n,".len + a + ",".len + "\x01auth=Bearer ".len + token.len + 2;
}

/// OAUTHBEARER initial response (RFC 7628 §3.1), base64: the GS2 header
/// `n,a=<user>,` (`n,,` for an empty user) then
/// `\x01auth=Bearer <token>\x01\x01`. `scratch` as for `xoauth2Response`.
pub fn oauthbearerResponse(buf: []u8, scratch: []u8, user: []const u8, token: []const u8) AuthError![]const u8 {
    try checkUser(user);
    try checkToken(token);
    const raw_len = oauthbearerRawLen(user, token);
    if (raw_len > scratch.len or encodedLen(raw_len) > buf.len) return error.NoSpaceLeft;
    const raw = scratch[0..raw_len];
    defer std.crypto.secureZero(u8, raw);
    var w: RawWriter = .{ .out = raw };
    w.put("n,");
    if (user.len != 0) {
        w.put("a=");
        for (user) |c| switch (c) {
            ',' => w.put("=2C"),
            '=' => w.put("=3D"),
            else => w.put(&.{c}),
        };
    }
    w.put(",\x01auth=Bearer ");
    w.put(token);
    w.put("\x01\x01");
    return b64ct.encode(buf, raw);
}

/// The client's answer to an OAUTHBEARER error challenge (RFC 7628 §3.2.3):
/// a single \x01, base64.
pub const oauthbearer_error_ack = "AQ==";

/// One LOGIN step: base64 of the credential the server just asked for.
pub fn loginResponse(buf: []u8, credential: []const u8) AuthError![]const u8 {
    try checkCredential(credential);
    if (encodedLen(credential.len) > buf.len) return error.NoSpaceLeft;
    return b64ct.encode(buf, credential);
}

/// Decode a server challenge (the text of a `334` reply). An empty challenge is
/// legal and decodes to an empty slice.
pub fn decodeChallenge(buf: []u8, challenge: []const u8) AuthError![]const u8 {
    const trimmed = std.mem.trim(u8, challenge, " \t");
    if (trimmed.len == 0) return buf[0..0];
    const n = b64.Decoder.calcSizeForSlice(trimmed) catch return error.MalformedChallenge;
    if (n > buf.len) return error.NoSpaceLeft;
    b64.Decoder.decode(buf[0..n], trimmed) catch return error.MalformedChallenge;
    return buf[0..n];
}

/// Which LOGIN credential a `334` challenge is asking for. Servers differ in
/// what they put in the challenge (some send "Username:", some "User Name",
/// some nothing at all), so the *order* of the exchange is authoritative and
/// the challenge text is only used to catch an obviously reversed server.
pub const LoginStep = enum { username, password, unknown };

pub fn classifyLoginChallenge(challenge: []const u8) LoginStep {
    var buf: [128]u8 = undefined;
    const decoded = decodeChallenge(&buf, challenge) catch return .unknown;
    if (asciiContains(decoded, "user")) return .username;
    if (asciiContains(decoded, "pass")) return .password;
    return .unknown;
}

fn asciiContains(hay: []const u8, needle: []const u8) bool {
    if (needle.len > hay.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(hay[i..][0..needle.len], needle)) return true;
    }
    return false;
}

// ── SCRAM-SHA-256 ──────────────────────────────────────────────────────────

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// RFC 7677 §4 / RFC 5802 §5.1 want a minimum of 4096; a server asking for less
/// is weakening the verifier and is refused.
pub const scram_min_iterations: u32 = 4096;
/// Ceiling on the server's PBKDF2 iteration count. The server picks the work
/// the client does; without a cap a hostile server is a CPU-exhaustion lever.
/// 600 000 is the OWASP 2023 figure for PBKDF2-HMAC-SHA256, well above the
/// 4096 that most SMTP servers use (Cyrus/Dovecot 4096..10000).
pub const scram_max_iterations: u32 = 600_000;
/// Longest decoded salt accepted.
pub const scram_max_salt_len: usize = 256;

/// Plain-ASCII check for a SCRAM credential, one verdict per call (no branch
/// per byte: the password is secret). Non-ASCII octets are
/// `error.NonAsciiCredential` (no SASLprep); ASCII controls are refused
/// because SASLprep prohibits them (RFC 4013 §2.3) and they would otherwise be
/// silently kept.
fn checkScramCredential(s: []const u8) AuthError!void {
    var non_ascii: u8 = 0;
    var ctl: u8 = 0;
    for (s) |c| {
        non_ascii |= c >> 7;
        // c < 0x20: 16-bit borrow of c - 0x20, bit 15; c == 0x7f via isZero.
        const lt: u16 = (@as(u16, c) -% 0x20) >> 15;
        ctl |= @as(u8, @intCast(lt)) | isZero(c ^ 0x7f);
    }
    if (non_ascii != 0) return error.NonAsciiCredential;
    if (ctl != 0) return error.InvalidCredential;
}

fn validNonceByte(c: u8) bool {
    return c >= 0x21 and c <= 0x7e and c != ',';
}

/// Client side of SCRAM-SHA-256 (RFC 5802, RFC 7677), no channel binding, no
/// authorization identity (GS2 header `n,,`; base64 `biws`).
///
///     var sc = try ScramClient.init(gpa, user, nonce);
///     defer sc.deinit();
///     const first = try sc.clientFirst(&buf);                // raw; AUTH base64s it
///     const final = try sc.clientFinal(&buf2, server_first, password);
///     try sc.verifyServerFinal(server_final);                // MUST be checked
///
/// Not implemented, and refused with an error rather than guessed at: SASLprep
/// of non-ASCII credentials (`error.NonAsciiCredential`), channel binding
/// (SCRAM-SHA-256-PLUS), an authorization identity. The password is never
/// copied; SaltedPassword, ClientKey, StoredKey, ClientSignature and the proof
/// are wiped before `clientFinal` returns (std's PBKDF2 internals are not ours
/// to wipe). The server signature is compared in constant time.
pub const ScramClient = struct {
    gpa: std.mem.Allocator,
    /// `n=<escaped user>,r=<client nonce>` (client-first-message-bare), owned.
    first_bare: []u8,
    /// The client nonce is the last `nonce_len` octets of `first_bare`.
    nonce_len: usize,
    /// Expected `v=` value, set by `clientFinal`.
    server_sig: [Sha256.digest_length]u8 = @splat(0),
    have_sig: bool = false,

    /// `nonce` must be non-empty printable ASCII without ',' (RFC 5802 §5.1);
    /// the caller supplies the randomness (see `Options.scram_random`).
    pub fn init(gpa: std.mem.Allocator, username: []const u8, nonce: []const u8) (AuthError || std.mem.Allocator.Error)!ScramClient {
        try checkScramCredential(username);
        if (nonce.len == 0) return error.InvalidCredential;
        for (nonce) |c| if (!validNonceByte(c)) return error.InvalidCredential;
        var n: usize = "n=".len + ",r=".len + nonce.len;
        for (username) |c| n += if (c == ',' or c == '=') @as(usize, 3) else 1;
        const fb = try gpa.alloc(u8, n);
        var w: RawWriter = .{ .out = fb };
        w.put("n=");
        for (username) |c| switch (c) {
            ',' => w.put("=2C"),
            '=' => w.put("=3D"),
            else => w.put(&.{c}),
        };
        w.put(",r=");
        w.put(nonce);
        return .{ .gpa = gpa, .first_bare = fb, .nonce_len = nonce.len };
    }

    pub fn deinit(self: *ScramClient) void {
        std.crypto.secureZero(u8, &self.server_sig);
        self.gpa.free(self.first_bare);
        self.* = undefined;
    }

    /// Raw length of `clientFirst`.
    pub fn clientFirstLen(self: *const ScramClient) usize {
        return "n,,".len + self.first_bare.len;
    }

    /// client-first-message: `n,,n=<user>,r=<nonce>` (raw, before base64).
    pub fn clientFirst(self: *const ScramClient, out: []u8) AuthError![]const u8 {
        const n = self.clientFirstLen();
        if (n > out.len) return error.NoSpaceLeft;
        @memcpy(out[0..3], "n,,");
        @memcpy(out[3..n], self.first_bare);
        return out[0..n];
    }

    /// Raw length of `clientFinal`'s output for a server-first with a combined
    /// nonce of `combined_nonce_len` octets.
    pub fn clientFinalLen(combined_nonce_len: usize) usize {
        return "c=biws,r=".len + combined_nonce_len + ",p=".len + b64.Encoder.calcSize(Sha256.digest_length);
    }

    /// Parse the server-first-message, derive the keys and write the
    /// client-final-message `c=biws,r=<nonce>,p=<proof>` (raw) to `out`. Refuses
    /// a nonce that does not extend ours, a malformed message, a salt that is
    /// not base64 or longer than `scram_max_salt_len`, and an iteration count
    /// outside `scram_min_iterations..scram_max_iterations` — all before any
    /// key derivation.
    pub fn clientFinal(self: *ScramClient, out: []u8, server_first: []const u8, password: []const u8) AuthError![]const u8 {
        try checkScramCredential(password);
        var it = std.mem.splitScalar(u8, server_first, ',');
        const r_attr = it.next() orelse return error.UnexpectedChallenge;
        const s_attr = it.next() orelse return error.UnexpectedChallenge;
        const i_attr = it.next() orelse return error.UnexpectedChallenge;
        // A leading `m=` is a mandatory extension we do not know (RFC 5802 §5.1).
        if (!std.mem.startsWith(u8, r_attr, "r=") or !std.mem.startsWith(u8, s_attr, "s=") or
            !std.mem.startsWith(u8, i_attr, "i=")) return error.UnexpectedChallenge;
        const nonce = r_attr[2..];
        const my_nonce = self.first_bare[self.first_bare.len - self.nonce_len ..];
        if (nonce.len <= self.nonce_len or !std.mem.startsWith(u8, nonce, my_nonce)) return error.UnexpectedChallenge;
        for (nonce) |c| if (!validNonceByte(c)) return error.UnexpectedChallenge;

        const iter_txt = i_attr[2..];
        if (iter_txt.len == 0 or iter_txt.len > 10) return error.UnexpectedChallenge;
        for (iter_txt) |c| if (c < '0' or c > '9') return error.UnexpectedChallenge;
        const iters = std.fmt.parseInt(u32, iter_txt, 10) catch return error.ScramIterationsOutOfRange;
        if (iters < scram_min_iterations or iters > scram_max_iterations) return error.ScramIterationsOutOfRange;

        var salt_buf: [scram_max_salt_len]u8 = undefined;
        const salt_txt = s_attr[2..];
        const salt_n = b64.Decoder.calcSizeForSlice(salt_txt) catch return error.MalformedChallenge;
        if (salt_n == 0 or salt_n > salt_buf.len) return error.MalformedChallenge;
        b64.Decoder.decode(salt_buf[0..salt_n], salt_txt) catch return error.MalformedChallenge;
        const salt = salt_buf[0..salt_n];

        if (clientFinalLen(nonce.len) > out.len) return error.NoSpaceLeft;

        var salted: [32]u8 = undefined;
        var client_key: [32]u8 = undefined;
        var stored_key: [32]u8 = undefined;
        var client_sig: [32]u8 = undefined;
        var proof: [32]u8 = undefined;
        var server_key: [32]u8 = undefined;
        defer {
            std.crypto.secureZero(u8, &salted);
            std.crypto.secureZero(u8, &client_key);
            std.crypto.secureZero(u8, &stored_key);
            std.crypto.secureZero(u8, &client_sig);
            std.crypto.secureZero(u8, &proof);
            std.crypto.secureZero(u8, &server_key);
        }
        // Only reachable errors: WeakParameters (iters >= 4096, no) and
        // OutputTooLong (32 bytes, no).
        std.crypto.pwhash.pbkdf2(&salted, password, salt, iters, HmacSha256) catch return error.UnexpectedChallenge;
        HmacSha256.create(&client_key, "Client Key", &salted);
        Sha256.hash(&client_key, &stored_key, .{});
        HmacSha256.create(&server_key, "Server Key", &salted);

        // AuthMessage = client-first-bare "," server-first "," client-final-without-proof
        const without_proof_len = "c=biws,r=".len + nonce.len;
        var w: RawWriter = .{ .out = out };
        w.put("c=biws,r=");
        w.put(nonce);
        const cfwp = out[0..without_proof_len];

        var mac = HmacSha256.init(&stored_key);
        mac.update(self.first_bare);
        mac.update(",");
        mac.update(server_first);
        mac.update(",");
        mac.update(cfwp);
        mac.final(&client_sig);
        for (&proof, client_key, client_sig) |*p, a, b_| p.* = a ^ b_;

        var smac = HmacSha256.init(&server_key);
        smac.update(self.first_bare);
        smac.update(",");
        smac.update(server_first);
        smac.update(",");
        smac.update(cfwp);
        smac.final(&self.server_sig);
        self.have_sig = true;

        w.put(",p=");
        var enc: [44]u8 = undefined;
        w.put(b64ct.encode(&enc, &proof));
        return out[0..w.i];
    }

    /// Check the server-final-message. Anything but a correct `v=` is an error;
    /// the comparison is constant time. `server_final` may carry trailing
    /// `,extension` attributes (ignored).
    pub fn verifyServerFinal(self: *const ScramClient, server_final: []const u8) AuthError!void {
        if (!self.have_sig) return error.UnexpectedChallenge;
        // `e=` is the server's error attribute (RFC 5802 §7): a failure.
        if (!std.mem.startsWith(u8, server_final, "v=")) return error.ServerSignatureMismatch;
        const rest = server_final[2..];
        const end = std.mem.findScalar(u8, rest, ',') orelse rest.len;
        const txt = rest[0..end];
        const sig_n = b64.Decoder.calcSizeForSlice(txt) catch return error.MalformedChallenge;
        if (sig_n != Sha256.digest_length) return error.ServerSignatureMismatch;
        var got: [Sha256.digest_length]u8 = undefined;
        b64.Decoder.decode(&got, txt) catch return error.MalformedChallenge;
        if (!std.crypto.timing_safe.eql([Sha256.digest_length]u8, got, self.server_sig)) return error.ServerSignatureMismatch;
    }
};

// ── tests ──────────────────────────────────────────────────────────────────

const rfc7677_nonce = "rOprNGfwEbeRWgbNEkqO";
const rfc7677_server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
const rfc7677_client_final = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
const rfc7677_server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

test "SCRAM-SHA-256: RFC 7677 §3 exchange, byte for byte" {
    var sc = try ScramClient.init(testing.allocator, "user", rfc7677_nonce);
    defer sc.deinit();
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("n,,n=user,r=rOprNGfwEbeRWgbNEkqO", try sc.clientFirst(&buf));
    const fin = try sc.clientFinal(&buf, rfc7677_server_first, "pencil");
    try testing.expectEqualStrings(rfc7677_client_final, fin);
    try sc.verifyServerFinal(rfc7677_server_final);
    // trailing extension attributes are ignored
    try sc.verifyServerFinal(rfc7677_server_final ++ ",x=1");
}

test "SCRAM-SHA-256: a wrong or missing server signature fails" {
    var sc = try ScramClient.init(testing.allocator, "user", rfc7677_nonce);
    defer sc.deinit();
    var buf: [256]u8 = undefined;
    // before clientFinal there is nothing to compare with
    try testing.expectError(error.UnexpectedChallenge, sc.verifyServerFinal(rfc7677_server_final));
    _ = try sc.clientFinal(&buf, rfc7677_server_first, "pencil");
    // one flipped character, a short signature, an error attribute, garbage
    try testing.expectError(error.ServerSignatureMismatch, sc.verifyServerFinal("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95H4="));
    try testing.expectError(error.ServerSignatureMismatch, sc.verifyServerFinal("v=AAAA"));
    try testing.expectError(error.ServerSignatureMismatch, sc.verifyServerFinal("e=invalid-proof"));
    try testing.expectError(error.ServerSignatureMismatch, sc.verifyServerFinal(""));
    try testing.expectError(error.MalformedChallenge, sc.verifyServerFinal("v=!!!"));
    // the wrong password derives a different signature too
    var sc2 = try ScramClient.init(testing.allocator, "user", rfc7677_nonce);
    defer sc2.deinit();
    _ = try sc2.clientFinal(&buf, rfc7677_server_first, "wrong");
    try testing.expectError(error.ServerSignatureMismatch, sc2.verifyServerFinal(rfc7677_server_final));
}

test "SCRAM-SHA-256: server-first is validated before any key is derived" {
    var buf: [256]u8 = undefined;
    const cases = [_]struct { sf: []const u8, err: AuthError }{
        // nonce that does not extend ours, and one that merely equals ours
        .{ .sf = "r=XXXXXXXXXXXXXXXXXXXXserver,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", .err = error.UnexpectedChallenge },
        .{ .sf = "r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", .err = error.UnexpectedChallenge },
        // missing / reordered attributes, a mandatory extension
        .{ .sf = "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==", .err = error.UnexpectedChallenge },
        .{ .sf = "s=W22ZaJ0SNY7soEsUEjb6gQ==,r=rOprNGfwEbeRWgbNEkqOx,i=4096", .err = error.UnexpectedChallenge },
        .{ .sf = "m=ext,r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", .err = error.UnexpectedChallenge },
        .{ .sf = "", .err = error.UnexpectedChallenge },
        // iteration count: both bounds, one past each, junk, overflow
        .{ .sf = "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4095", .err = error.ScramIterationsOutOfRange },
        .{ .sf = "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0", .err = error.ScramIterationsOutOfRange },
        .{ .sf = "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=600001", .err = error.ScramIterationsOutOfRange },
        .{ .sf = "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=99999999999", .err = error.UnexpectedChallenge },
        .{ .sf = "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096x", .err = error.UnexpectedChallenge },
        .{ .sf = "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=-4096", .err = error.UnexpectedChallenge },
        .{ .sf = "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=", .err = error.UnexpectedChallenge },
        // salt: not base64, empty
        .{ .sf = "r=rOprNGfwEbeRWgbNEkqOx,s=!!!!,i=4096", .err = error.MalformedChallenge },
        .{ .sf = "r=rOprNGfwEbeRWgbNEkqOx,s=,i=4096", .err = error.MalformedChallenge },
    };
    for (cases) |c| {
        var sc = try ScramClient.init(testing.allocator, "user", rfc7677_nonce);
        defer sc.deinit();
        try testing.expectError(c.err, sc.clientFinal(&buf, c.sf, "pencil"));
        try testing.expect(!sc.have_sig);
    }
    // the accepted edges: 4096 and 600000 pass the checks (600000 is not run
    // here: PBKDF2 at that count would only slow the test down)
    var sc = try ScramClient.init(testing.allocator, "user", rfc7677_nonce);
    defer sc.deinit();
    var tiny: [10]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, sc.clientFinal(&tiny, rfc7677_server_first, "pencil"));
}

test "SCRAM-SHA-256: no SASLprep, so non-ASCII and control octets are refused" {
    var buf: [256]u8 = undefined;
    try testing.expectError(error.NonAsciiCredential, ScramClient.init(testing.allocator, "us\xc3\xa9r", rfc7677_nonce));
    var sc = try ScramClient.init(testing.allocator, "user", rfc7677_nonce);
    defer sc.deinit();
    try testing.expectError(error.NonAsciiCredential, sc.clientFinal(&buf, rfc7677_server_first, "p\xc3\xa9ncil"));
    try testing.expectError(error.InvalidCredential, sc.clientFinal(&buf, rfc7677_server_first, "pen\x00cil"));
    try testing.expectError(error.InvalidCredential, sc.clientFinal(&buf, rfc7677_server_first, "pen\ncil"));
    try testing.expectError(error.InvalidCredential, sc.clientFinal(&buf, rfc7677_server_first, "pen\x7fcil"));
    try testing.expect(!sc.have_sig);
    // bad nonces and a name that needs RFC 5802 escaping
    try testing.expectError(error.InvalidCredential, ScramClient.init(testing.allocator, "u", ""));
    try testing.expectError(error.InvalidCredential, ScramClient.init(testing.allocator, "u", "a,b"));
    try testing.expectError(error.InvalidCredential, ScramClient.init(testing.allocator, "u", "a b"));
    var esc = try ScramClient.init(testing.allocator, "a,b=c", "nonce");
    defer esc.deinit();
    try testing.expectEqualStrings("n,,n=a=2Cb=3Dc,r=nonce", try esc.clientFirst(&buf));
    var small: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, esc.clientFirst(&small));
}

test "RFC 4616 §4 worked example" {
    // The RFC's own example: authzid empty, authcid "tim", passwd "tanstaaftanstaaf".
    var buf: [128]u8 = undefined;
    const r = try plainResponse(&buf, "", "tim", "tanstaaftanstaaf");
    try testing.expectEqualStrings("AHRpbQB0YW5zdGFhZnRhbnN0YWFm", r);

    // ...and it really is NUL "tim" NUL "tanstaaftanstaaf".
    var dec: [128]u8 = undefined;
    const back = try decodeChallenge(&dec, r);
    try testing.expectEqualSlices(u8, "\x00tim\x00tanstaaftanstaaf", back);
}

test "RFC 4954 §4 AUTH PLAIN example" {
    // The RFC's example is base64("\0test\0tEsTiNg") = "AHRlc3QAdEVzVGlOZw==".
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("AHRlc3QAdEVzVGlOZw==", try plainResponse(&buf, "", "test", "tEsTiNg"));
}

test "PLAIN with a non-empty authorization identity" {
    var buf: [128]u8 = undefined;
    const r = try plainResponse(&buf, "admin", "tim", "pw");
    var dec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, "admin\x00tim\x00pw", try decodeChallenge(&dec, r));
}

test "LOGIN challenges are the literal base64 the servers send" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, "Username:", try decodeChallenge(&buf, login_username_challenge));
    try testing.expectEqualSlices(u8, "Password:", try decodeChallenge(&buf, login_password_challenge));
    try testing.expectEqual(LoginStep.username, classifyLoginChallenge(login_username_challenge));
    try testing.expectEqual(LoginStep.password, classifyLoginChallenge(login_password_challenge));
    // A server that sends something else is not fatal — the order rules.
    try testing.expectEqual(LoginStep.unknown, classifyLoginChallenge("Zm9v"));
    try testing.expectEqual(LoginStep.unknown, classifyLoginChallenge("not base64!!"));

    try testing.expectEqualStrings("dXNlckBleGFtcGxlLmNvbQ==", try loginResponse(&buf, "user@example.com"));
    try testing.expectEqualStrings("c2VjcmV0", try loginResponse(&buf, "secret"));
}

test "XOAUTH2 initial response" {
    var buf: [256]u8 = undefined;
    var scratch: [256]u8 = undefined;
    // Fixed vector, base64 computed independently.
    const r = try xoauth2Response(&buf, &scratch, "someuser@example.com", "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg");
    var dec: [256]u8 = undefined;
    try testing.expectEqualSlices(u8, "user=someuser@example.com\x01auth=Bearer ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg\x01\x01", try decodeChallenge(&dec, r));
    try testing.expectEqualStrings(
        "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ==",
        r,
    );
    // The scratch plaintext is wiped.
    for (scratch[0..xoauth2RawLen("someuser@example.com", "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg")]) |c| try testing.expectEqual(@as(u8, 0), c);
}

test "OAUTHBEARER initial response, RFC 7628 §4.1 shape" {
    var buf: [256]u8 = undefined;
    var scratch: [256]u8 = undefined;
    const r = try oauthbearerResponse(&buf, &scratch, "user@example.com", "vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg==");
    var dec: [256]u8 = undefined;
    try testing.expectEqualSlices(u8, "n,a=user@example.com,\x01auth=Bearer vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg==\x01\x01", try decodeChallenge(&dec, r));
    for (scratch[0..oauthbearerRawLen("user@example.com", "vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg==")]) |c| try testing.expectEqual(@as(u8, 0), c);

    // Empty user: no a= part. ',' and '=' in the user are GS2-escaped.
    const r2 = try oauthbearerResponse(&buf, &scratch, "", "tok");
    try testing.expectEqualSlices(u8, "n,,\x01auth=Bearer tok\x01\x01", try decodeChallenge(&dec, r2));
    const r3 = try oauthbearerResponse(&buf, &scratch, "a,b=c", "tok");
    try testing.expectEqualSlices(u8, "n,a=a=2Cb=3Dc,\x01auth=Bearer tok\x01\x01", try decodeChallenge(&dec, r3));
    try testing.expectEqualSlices(u8, "\x01", try decodeChallenge(&dec, oauthbearer_error_ack));
}

test "OAuth responses refuse forged fields and small buffers" {
    var buf: [256]u8 = undefined;
    var scratch: [256]u8 = undefined;
    const fns = .{ xoauth2Response, oauthbearerResponse };
    inline for (fns) |f| {
        try testing.expectError(error.InvalidCredential, f(&buf, &scratch, "u\x01auth=Bearer x", "tok"));
        try testing.expectError(error.InvalidCredential, f(&buf, &scratch, "u\r\nQUIT", "tok"));
        try testing.expectError(error.InvalidCredential, f(&buf, &scratch, "u\x00", "tok"));
        try testing.expectError(error.InvalidCredential, f(&buf, &scratch, "u", ""));
        try testing.expectError(error.InvalidCredential, f(&buf, &scratch, "u", "to ken"));
        try testing.expectError(error.InvalidCredential, f(&buf, &scratch, "u", "tok\x01\x01"));
        try testing.expectError(error.InvalidCredential, f(&buf, &scratch, "u", "tok\r\n"));
        try testing.expectError(error.InvalidCredential, f(&buf, &scratch, "u", "tok\x7f"));
        try testing.expectError(error.InvalidCredential, f(&buf, &scratch, "u", "tok\xc3\xa9"));
        _ = try f(&buf, &scratch, "u", "!~"); // the 0x21 and 0x7e edges
        var small: [8]u8 = undefined;
        try testing.expectError(error.NoSpaceLeft, f(&small, &scratch, "user", "token"));
        var tiny_scratch: [8]u8 = undefined;
        try testing.expectError(error.NoSpaceLeft, f(&buf, &tiny_scratch, "user", "token"));
    }
}

test "credentials that would forge a separator or a command line are refused" {
    var buf: [128]u8 = undefined;
    try testing.expectError(error.InvalidCredential, plainResponse(&buf, "", "ti\x00m", "pw"));
    try testing.expectError(error.InvalidCredential, plainResponse(&buf, "", "tim", "pw\x00extra"));
    try testing.expectError(error.InvalidCredential, plainResponse(&buf, "", "tim", "pw\r\nQUIT"));
    try testing.expectError(error.InvalidCredential, plainResponse(&buf, "a\nb", "tim", "pw"));
    try testing.expectError(error.InvalidCredential, loginResponse(&buf, "user\r\nMAIL FROM:<x@example.com>"));
}

test "buffers that are too small are an error, never a truncation" {
    var small: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, plainResponse(&small, "", "tim", "tanstaaftanstaaf"));
    try testing.expectError(error.NoSpaceLeft, loginResponse(&small, "a-long-username"));
    var out: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, decodeChallenge(&out, "dXNlckBleGFtcGxlLmNvbQ=="));
}

test "a malformed base64 challenge is a typed error" {
    var buf: [64]u8 = undefined;
    try testing.expectError(error.MalformedChallenge, decodeChallenge(&buf, "!!!!"));
    try testing.expectError(error.MalformedChallenge, decodeChallenge(&buf, "AAAAA"));
    try testing.expectEqualSlices(u8, "", try decodeChallenge(&buf, ""));
    try testing.expectEqualSlices(u8, "", try decodeChallenge(&buf, "  "));
}

/// `testkit.fuzz.seed`, aliased so the corpus below reads as the strings it is.
/// A corpus entry is not the frame: `Smith.slice` reads a little-endian `u32`
/// length first, so a raw string would arrive minus its own first four octets.
/// `testkit/src/fuzz.zig` carries the other two hazards.
const seed = @import("testkit").fuzz.seed;

/// Credentials and challenges, in the format `Smith.slice` reads. The harness
/// hands each one to all four entry points, so one string plays both roles.
///
/// The two RFC worked examples, both LOGIN challenges verbatim, the three
/// base64 shapes `decodeChallenge` refuses, and the two credential shapes
/// `checkCredential` refuses. Valid base64 is a structured alphabet with a
/// length that must be a multiple of four: uniform random octets of a random
/// length clear both conditions essentially never, so before this the harness
/// exercised `MalformedChallenge` and nothing beyond it -- and, with the
/// collapsed draw, not even that.
const auth_seeds = [_][]const u8{
    seed("AHRpbQB0YW5zdGFhZnRhbnN0YWFm"), // RFC 4616 §4's own PLAIN response
    seed("AHRlc3QAdEVzVGlOZw=="), // RFC 4954 §4's AUTH PLAIN example
    seed("VXNlcm5hbWU6"), // the LOGIN "Username:" challenge
    seed("UGFzc3dvcmQ6"), // the LOGIN "Password:" challenge
    seed("dXNlckBleGFtcGxlLmNvbQ=="), // base64("user@example.com")
    seed("Zm9v"), // valid base64 that classifies as neither step
    seed("tanstaaftanstaaf"), // a plain password, and NOT valid base64
    seed("tim"), // a three-octet credential
    seed("not base64!!"), // MalformedChallenge: characters outside the alphabet
    seed("!!!!"), // MalformedChallenge: right length, wrong alphabet
    seed("AAAAA"), // MalformedChallenge: a length that is not a multiple of 4
    seed("  "), // whitespace only: trimmed to empty, which is legal
    seed("ti\x00m"), // InvalidCredential: a NUL would forge the RFC 4616 separator
    seed("pw\r\nQUIT"), // InvalidCredential: a CRLF would forge a command line
    seed(strRepeat("A", 200)), // exactly the harness buffer: over the PLAIN output cap
};

test "fuzz: arbitrary challenges and credentials never crash" {
    try testing.fuzz({}, fuzzAuth, .{ .corpus = &auth_seeds });
}

fn fuzzAuth(_: void, smith: *std.testing.Smith) !void {
    var raw: [200]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and all four entry points were called with
    // an empty string, with the seed sitting unread in `raw`.
    const len = smith.slice(&raw);
    const s = raw[0..len];
    var buf: [512]u8 = undefined;
    _ = plainResponse(&buf, "", s, s) catch {};
    _ = loginResponse(&buf, s) catch {};
    _ = decodeChallenge(&buf, s) catch {};
    _ = classifyLoginChallenge(s);
}

test "corpus: every auth seed reaches all four entry points, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. A seed
    // longer than the harness's buffer reads back EMPTY (`Smith.slice` falls
    // back to the range minimum), which is silent everywhere else.
    //
    // ⚠ One "accepted" number would be misleading here: `decodeChallenge("")`
    // is legal by design, so an empty draw already "succeeds" at one of the
    // four entry points -- which is precisely why the collapsed harness looked
    // healthy. Three counts are pinned instead, one per behaviour that a real
    // string is needed to reach: a credential the encoder accepts, a challenge
    // the decoder accepts, and a challenge that classifies as a known LOGIN
    // step.
    var nonempty: usize = 0;
    var credential_ok: usize = 0;
    var challenge_ok: usize = 0;
    var classified: usize = 0;
    for (auth_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [200]u8 = undefined;
        const len = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        const s = raw[0..len];
        var buf: [512]u8 = undefined;
        if (plainResponse(&buf, "", s, s)) |_| {
            credential_ok += 1;
        } else |_| {}
        if (decodeChallenge(&buf, s)) |_| {
            challenge_ok += 1;
        } else |_| {}
        if (classifyLoginChallenge(s) != .unknown) classified += 1;
    }
    try testing.expectEqual(auth_seeds.len, nonempty);
    // Measured: 0 of 15 seeds non-empty before the draw was fixed,
    // 15 of 15 after.
    try testing.expectEqual(@as(usize, 12), credential_ok);
    try testing.expectEqual(@as(usize, 9), challenge_ok);
    // 3 = the two LOGIN challenges plus the PLAIN response, whose decoded
    // "\x00test\x00tEsTiNg" contains "test" and so reads as a username prompt.
    try testing.expectEqual(@as(usize, 3), classified);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

test "exact-fit buffers and ceilings are accepted, one past is refused" {
    var big: [2048]u8 = undefined;
    // PLAIN: a buffer of exactly the encoded size is enough.
    const want = encodedLen(1 + 3 + 1 + 16);
    try testing.expectEqual(want, (try plainResponse(big[0..want], "", "tim", "tanstaaftanstaaf")).len);
    // The staging buffer is 1024 octets: a 1024-octet raw form fits, 1025 does not.
    var pw: [1022]u8 = undefined;
    @memset(&pw, 'p');
    try testing.expectEqual(encodedLen(1024), (try plainResponse(&big, "", "a", pw[0..1021])).len);
    try testing.expectError(error.NoSpaceLeft, plainResponse(&big, "", "a", pw[0..1022]));
    // LOGIN and challenge decoding: the exact size.
    try testing.expectEqualStrings("c2VjcmV0", try loginResponse(big[0..encodedLen(6)], "secret"));
    try testing.expectEqualStrings("user", try decodeChallenge(big[0..4], "dXNlcg=="));
    // A challenge that decodes to exactly "user" / "pass" is classified (the
    // needle is as long as the haystack).
    try testing.expectEqual(LoginStep.username, classifyLoginChallenge("VXNlcg=="));
    try testing.expectEqual(LoginStep.password, classifyLoginChallenge("cGFzcw=="));
}

test "SCRAM-SHA-256: exact-fit buffers, wide counts, nonce and salt edges are accepted" {
    var buf: [512]u8 = undefined;
    // client-first into a buffer of exactly its length
    var sc0 = try ScramClient.init(testing.allocator, "user", rfc7677_nonce);
    defer sc0.deinit();
    const first = try sc0.clientFirst(&buf);
    var exact: [64]u8 = undefined;
    try testing.expectEqualStrings(first, try sc0.clientFirst(exact[0..first.len]));

    // client-final into a buffer of exactly its length
    var sc1 = try ScramClient.init(testing.allocator, "user", rfc7677_nonce);
    defer sc1.deinit();
    try testing.expectEqualStrings(rfc7677_client_final, try sc1.clientFinal(buf[0..rfc7677_client_final.len], rfc7677_server_first, "pencil"));

    // a 10-digit iteration count (leading zeros) is accepted; the proof covers the text as sent
    var sc2 = try ScramClient.init(testing.allocator, "user", rfc7677_nonce);
    defer sc2.deinit();
    const fin2 = try sc2.clientFinal(&buf, "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0000004096", "pencil");
    try testing.expect(std.mem.startsWith(u8, fin2, "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p="));

    // the first and the last printable nonce octets ('!' and '~') are legal
    var sc3 = try ScramClient.init(testing.allocator, "user", rfc7677_nonce);
    defer sc3.deinit();
    _ = try sc3.clientFinal(&buf, "r=rOprNGfwEbeRWgbNEkqO!~,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", "pencil");

    // a salt of exactly scram_max_salt_len octets is accepted, one more is not
    var salt: [scram_max_salt_len + 3]u8 = @splat(7);
    var enc: [400]u8 = undefined;
    const gpa = testing.allocator;
    const ok_salt = b64.Encoder.encode(&enc, salt[0..scram_max_salt_len]);
    const sf_ok = try gpa.print("r=rOprNGfwEbeRWgbNEkqOx,s={s},i=4096", .{ok_salt});
    defer gpa.free(sf_ok);
    var sc4 = try ScramClient.init(gpa, "user", rfc7677_nonce);
    defer sc4.deinit();
    _ = try sc4.clientFinal(&buf, sf_ok, "pencil");
    const big_salt = b64.Encoder.encode(&enc, salt[0 .. scram_max_salt_len + 1]);
    const sf_big = try gpa.print("r=rOprNGfwEbeRWgbNEkqOx,s={s},i=4096", .{big_salt});
    defer gpa.free(sf_big);
    var sc5 = try ScramClient.init(gpa, "user", rfc7677_nonce);
    defer sc5.deinit();
    try testing.expectError(error.MalformedChallenge, sc5.clientFinal(&buf, sf_big, "pencil"));

    // the iteration ceiling itself is accepted (PBKDF2 really runs 600000 rounds)
    var sc6 = try ScramClient.init(gpa, "user", rfc7677_nonce);
    defer sc6.deinit();
    _ = try sc6.clientFinal(&buf, "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=600000", "pencil");
}
