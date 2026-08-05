// SPDX-License-Identifier: MIT

//! SSH-2.0 user authentication (RFC 4252) — part 2 of this module, layered
//! directly on the part-1 transport (`transport.Transport`): every message
//! here travels as an ordinary encrypted binary packet through
//! `Transport.sendPacket`/`recvPacket`, so this file contains no framing,
//! no cipher and no KEX code.
//!
//! Implemented, both roles:
//!   - the `ssh-userauth` service handshake (SSH_MSG_SERVICE_REQUEST →
//!     SSH_MSG_SERVICE_ACCEPT; the server half already lives at the end of
//!     `server.serverHandshake`, the client half is `Transport.requestService`),
//!   - the `publickey` method (§7) including the two-phase
//!     query→SSH_MSG_USERAUTH_PK_OK→signed-request flow,
//!   - the `password` method (§8), without the password-change sub-protocol,
//!   - SSH_MSG_USERAUTH_FAILURE / _SUCCESS / _BANNER.
//!
//! **The load-bearing security property is the session-id binding.** The
//! `publickey` signature (§7) is computed over
//!
//!     string    session identifier      <- transport.Transport.session_id
//!     byte      SSH_MSG_USERAUTH_REQUEST (50)
//!     string    user name
//!     string    service name
//!     string    "publickey"
//!     boolean   TRUE
//!     string    public key algorithm name
//!     string    public key blob
//!
//! and nothing else (`signedBlob` below is the single encoder both roles use,
//! so client and server cannot drift). The session identifier is the exchange
//! hash `H` of the connection's first KEX — unique per connection and
//! unforgeable by a third party — so a signature captured on one connection
//! cannot be replayed onto another. A verifier that omitted it, or a signer
//! that used a value not tied to its own transport, would produce a
//! replayable credential; `serveUserauth` therefore always takes the session
//! id from *its own* `Transport`, never from anything on the wire.
//!
//! Key algorithms: whatever `server.HostKey` can sign/`transport.
//! verifySignature` can verify — `ssh-ed25519` (RFC 8709), `rsa-sha2-256` /
//! `rsa-sha2-512` (RFC 8332, key blob typed `ssh-rsa`) and
//! `ecdsa-sha2-nistp256` (RFC 5656).
//!
//! Deferred (documented in SPEC.md, not stubbed): `keyboard-interactive`
//! (RFC 4256), `hostbased` (§9), the §8 password-change exchange, agent
//! forwarding, and certificate (`*-cert-v01@openssh.com`) key types.

const std = @import("std");
const transport = @import("transport.zig");
const messages = @import("messages.zig");
const server_mod = @import("server.zig");

const Cursor = messages.Cursor;

/// A client authentication key. Deliberately the same union as the server's
/// host key (`server.HostKey`): the wire formats an SSH implementation needs
/// for "a public key blob + a signature made by it" are identical whether the
/// key authenticates a host during KEX or a user during RFC 4252, so
/// `publicBlob`/`sign`/`algorithmName`/`fromOpenSSH` are reused verbatim
/// rather than mirrored. Load one with `AuthKey.fromOpenSSH(id_ed25519_text,
/// null)`.
pub const AuthKey = server_mod.HostKey;

/// The service userauth authenticates *for* (RFC 4252 §5) — always the
/// connection protocol in practice, and the only value this module accepts.
pub const connection_service = "ssh-connection";

/// Bounds on peer-supplied strings. RFC 4252 sets no limits; these are DoS
/// guards, all far above anything a real deployment uses.
pub const max_user_len = 255;
pub const max_service_len = 64;
pub const max_password_len = 1024;
/// 4 KiB comfortably holds any key blob this module can verify (an rsa-4096
/// blob is ~535 bytes) while keeping the SSH_MSG_USERAUTH_PK_OK echo of it
/// inside one binary packet.
pub const max_key_blob_len = 4 * 1024;
pub const max_signature_len = 4 * 1024;
pub const max_banner_len = 8 * 1024;

pub const UserauthError = transport.TransportError || error{
    /// The peer rejected every credential we offered (client), or the peer
    /// exhausted `AuthConfig.max_attempts` (server).
    AuthenticationFailed,
    /// The peer asked for a method this module does not implement.
    UnsupportedAuthMethod,
    /// A peer-supplied user/service/key/signature string exceeded the
    /// corresponding `max_*_len` bound above.
    NameTooLong,
};

/// How many bytes of scratch a userauth exchange reads a packet into. Big
/// enough for an rsa-4096 key blob + signature several times over.
const scratch_len = 64 * 1024;

fn msgType(p: transport.Packet) u8 {
    return if (p.payload.len == 0) 0 else p.payload[0];
}

/// The connection's session id, borrowed from the transport itself.
///
/// Note the `|*s|` capture: `SessionId.slice()` returns a slice into the
/// `SessionId` value, so capturing the optional *by value* here would hand
/// back a pointer into a dead stack temporary. The whole security property
/// of this file rides on this slice being the transport's real exchange
/// hash, so it must borrow, never copy.
fn sessionId(t: *const transport.Transport) UserauthError![]const u8 {
    if (t.session_id) |*s| return s.slice();
    return error.ProtocolError;
}

// ── the signed blob (RFC 4252 §7) ──────────────────────────────────────────

/// Encode the exact byte string an RFC 4252 §7 `publickey` signature is made
/// over. **One encoder, used by both the signer (client) and the verifier
/// (server)** — the whole point being that the two cannot disagree about
/// what was signed. See the module doc comment for the field list and why
/// `session_id` leads it.
pub fn signedBlob(
    w: *std.Io.Writer,
    session_id: []const u8,
    user: []const u8,
    service: []const u8,
    algorithm: []const u8,
    key_blob: []const u8,
) std.Io.Writer.Error!void {
    try messages.writeString(w, session_id);
    try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_USERAUTH_REQUEST));
    try messages.writeString(w, user);
    try messages.writeString(w, service);
    try messages.writeString(w, "publickey");
    try w.writeByte(1); // boolean TRUE — "this request carries a signature"
    try messages.writeString(w, algorithm);
    try messages.writeString(w, key_blob);
}

// ── client side ────────────────────────────────────────────────────────────

/// Client-side `publickey` options.
pub const PublickeyOptions = struct {
    /// Service to authenticate for (RFC 4252 §5). Only `ssh-connection` is
    /// meaningful; exposed for completeness.
    service: []const u8 = connection_service,
    /// Do the RFC 4252 §7 two-phase flow: first a signature-less *query*
    /// request, and only after SSH_MSG_USERAUTH_PK_OK the real signed one.
    /// This is what OpenSSH does (it avoids computing a signature — and
    /// touching an agent/HSM — for a key the server will not accept), and it
    /// is what the server side here supports. Set false to send the signed
    /// request straight away (also legal per §7, one round trip cheaper).
    probe_first: bool = true,
};

/// Client: authenticate as `user` with `key` using RFC 4252 §7 `publickey`.
///
/// Preconditions: `t` has completed its transport handshake (so
/// `t.session_id` is set) and the `ssh-userauth` service has been accepted —
/// call `transport.Transport.requestService("ssh-userauth", buf)` first, or
/// use `authenticate` below, which does both.
///
/// Returns normally on SSH_MSG_USERAUTH_SUCCESS; `error.AuthenticationFailed`
/// on SSH_MSG_USERAUTH_FAILURE. SSH_MSG_USERAUTH_BANNER (§5.4) is skipped,
/// SSH_MSG_IGNORE/DEBUG are skipped.
pub fn authenticatePublickey(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    user: []const u8,
    key: AuthKey,
    opts: PublickeyOptions,
) UserauthError!void {
    return authenticatePublickeyBoundTo(t, gpa, user, key, opts, try sessionId(t));
}

/// Same as `authenticatePublickey`, but the caller supplies the session
/// identifier the signature is bound to.
///
/// Exists so the module's own negative test can prove the binding actually
/// bites (sign against a *wrong* session id and watch a conforming verifier
/// reject it). Production callers want `authenticatePublickey`, which always
/// passes the transport's own `session_id`; passing anything else here
/// produces a signature that is not bound to this connection.
pub fn authenticatePublickeyBoundTo(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    user: []const u8,
    key: AuthKey,
    opts: PublickeyOptions,
    session_id: []const u8,
) UserauthError!void {
    if (user.len > max_user_len or opts.service.len > max_service_len)
        return error.NameTooLong;

    const scratch = try gpa.alloc(u8, scratch_len);
    defer gpa.free(scratch);

    const algorithm = key.algorithmName();
    const blob = try key.publicBlob(gpa);
    defer gpa.free(blob);

    if (opts.probe_first) {
        try sendPublickeyRequest(t, gpa, user, opts.service, algorithm, blob, null);
        switch (try awaitAuthReply(t, scratch)) {
            .pk_ok => {},
            .failure => return error.AuthenticationFailed,
            // A server must not conclude authentication from a query that
            // carried no signature; treating it as success would let a
            // malicious server "authenticate" us without proof of key
            // possession, so this is a protocol error, not a shortcut.
            .success => return error.ProtocolError,
        }
    }

    // Real request: sign `session_id || 50 || user || service || "publickey"
    // || TRUE || alg || blob` (RFC 4252 §7).
    const to_sign = try gpa.alloc(u8, 1024 + blob.len + user.len + opts.service.len + algorithm.len + session_id.len);
    defer gpa.free(to_sign);
    var bw: std.Io.Writer = .fixed(to_sign);
    try signedBlob(&bw, session_id, user, opts.service, algorithm, blob);
    const signature = try key.sign(gpa, bw.buffered());
    defer gpa.free(signature);

    try sendPublickeyRequest(t, gpa, user, opts.service, algorithm, blob, signature);
    switch (try awaitAuthReply(t, scratch)) {
        .success => return,
        .failure => return error.AuthenticationFailed,
        .pk_ok => return error.ProtocolError,
    }
}

/// Client: authenticate as `user` with `password` (RFC 4252 §8). Same
/// preconditions as `authenticatePublickey`.
///
/// Note the transport-level caveat: the password is sent inside an ordinary
/// encrypted packet, so its confidentiality rests entirely on the part-1
/// transport — which is exactly why RFC 4252 §8 requires the transport to
/// provide confidentiality. This function scrubs its own request buffer, but
/// cannot scrub the packet-encoding scratch inside `writePacket`.
pub fn authenticatePassword(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    user: []const u8,
    password: []const u8,
) UserauthError!void {
    if (user.len > max_user_len) return error.NameTooLong;
    if (password.len > max_password_len) return error.NameTooLong;

    const scratch = try gpa.alloc(u8, scratch_len);
    defer gpa.free(scratch);

    const buf = try gpa.alloc(u8, 512 + user.len + password.len);
    defer {
        std.crypto.secureZero(u8, buf);
        gpa.free(buf);
    }
    var w: std.Io.Writer = .fixed(buf);
    try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_USERAUTH_REQUEST));
    try messages.writeString(&w, user);
    try messages.writeString(&w, connection_service);
    try messages.writeString(&w, "password");
    try w.writeByte(0); // FALSE: not a password *change* request
    try messages.writeString(&w, password);
    try t.sendPacket(w.buffered());

    switch (try awaitAuthReply(t, scratch)) {
        .success => return,
        .failure => return error.AuthenticationFailed,
        // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ shares message number 60; the
        // change sub-protocol is deliberately not implemented.
        .pk_ok => return error.UnsupportedAuthMethod,
    }
}

/// Client convenience: request the `ssh-userauth` service, then authenticate
/// with `key` — the whole of RFC 4252 for the common case, one call.
pub fn authenticate(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    user: []const u8,
    key: AuthKey,
) UserauthError!void {
    const scratch = try gpa.alloc(u8, scratch_len);
    defer gpa.free(scratch);
    try t.requestService("ssh-userauth", scratch);
    return authenticatePublickey(t, gpa, user, key, .{});
}

fn sendPublickeyRequest(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    user: []const u8,
    service: []const u8,
    algorithm: []const u8,
    blob: []const u8,
    signature: ?[]const u8,
) UserauthError!void {
    const buf = try gpa.alloc(u8, 512 + user.len + service.len + algorithm.len +
        blob.len + if (signature) |s| s.len else 0);
    defer gpa.free(buf);
    var w: std.Io.Writer = .fixed(buf);
    try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_USERAUTH_REQUEST));
    try messages.writeString(&w, user);
    try messages.writeString(&w, service);
    try messages.writeString(&w, "publickey");
    try w.writeByte(if (signature != null) 1 else 0);
    try messages.writeString(&w, algorithm);
    try messages.writeString(&w, blob);
    if (signature) |s| try messages.writeString(&w, s);
    return t.sendPacket(w.buffered());
}

const AuthReply = enum { success, failure, pk_ok };

/// Read packets until one is an authentication verdict, skipping the
/// informational messages RFC 4252/4253 allow at any point (BANNER, IGNORE,
/// DEBUG). Anything else from the peer is a protocol error rather than
/// something to guess about.
fn awaitAuthReply(t: *transport.Transport, scratch: []u8) UserauthError!AuthReply {
    var seen: usize = 0;
    while (seen < 64) : (seen += 1) {
        const pkt = try t.recvPacket(scratch);
        switch (@as(messages.MessageType, @enumFromInt(msgType(pkt)))) {
            .SSH_MSG_IGNORE, .SSH_MSG_DEBUG => continue,
            .SSH_MSG_USERAUTH_BANNER => {
                // §5.4: string message || string language tag. Validated
                // (bounded) and discarded — displaying it is caller policy.
                var c = Cursor{ .b = pkt.payload[1..] };
                const msg = try c.string();
                if (msg.len > max_banner_len) return error.NameTooLong;
                continue;
            },
            .SSH_MSG_USERAUTH_SUCCESS => return .success,
            .SSH_MSG_USERAUTH_FAILURE => return .failure,
            .SSH_MSG_USERAUTH_PK_OK => return .pk_ok,
            .SSH_MSG_DISCONNECT => return error.ProtocolError,
            else => return error.ProtocolError,
        }
    }
    return error.ProtocolError;
}

// ── server side ────────────────────────────────────────────────────────────

/// Server policy hook: is `key_blob` an authorized key for `user`? The
/// equivalent of one line of an `authorized_keys` file. Storage/parsing of
/// that file is deliberately the caller's concern — this module never touches
/// the filesystem.
///
/// `algorithm` is the *signature* algorithm name from the request, which is
/// NOT always the key blob's own type name: RFC 8332 §3 pairs both
/// `rsa-sha2-256` and `rsa-sha2-512` with an `ssh-rsa`-typed blob (that
/// pairing is enforced by `transport.keyBlobTypeFor` before this hook is
/// called). A
/// callback that compares an `authorized_keys` line should compare
/// `key_blob` — the full wire blob, type prefix included, exactly what
/// `AuthKey.publicBlob` produces and what the base64 field of an
/// `authorized_keys` line decodes to — and treat `algorithm` as policy input
/// only (e.g. to refuse a weaker hash).
///
/// Called for BOTH phases of the §7 flow: once for the signature-less query
/// (deciding whether to answer SSH_MSG_USERAUTH_PK_OK) and again before
/// verifying the real signature. Returning true does NOT by itself
/// authenticate anyone: `serveUserauth` still requires a valid, session-id-
/// bound signature.
pub const AuthorizedKeyCheck = *const fn (user: []const u8, algorithm: []const u8, key_blob: []const u8) bool;

/// Server policy hook for the §8 `password` method. Implementations should
/// compare in constant time (`std.crypto.timing_safe.eql`) and rate-limit;
/// neither is this module's business.
pub const PasswordCheck = *const fn (user: []const u8, password: []const u8) bool;

pub const AuthConfig = struct {
    /// Enables the `publickey` method when set.
    authorized_key: ?AuthorizedKeyCheck = null,
    /// Enables the `password` method when set.
    password: ?PasswordCheck = null,
    /// Optional SSH_MSG_USERAUTH_BANNER (§5.4) sent once, before the first
    /// verdict.
    banner: ?[]const u8 = null,
    /// Rejected *credentials* tolerated before giving up with
    /// `error.AuthenticationFailed`.
    ///
    /// This is a credential budget, not a time or packet budget: messages
    /// that produce no verdict — SSH_MSG_IGNORE, SSH_MSG_DEBUG, and the
    /// RFC 4252 §7 signature-less `publickey` *query* (which is answered
    /// SSH_MSG_USERAUTH_PK_OK and is by definition not an attempt) — do not
    /// consume it, so an unauthenticated peer can keep `serveUserauth`
    /// looping for as long as it keeps sending. There is no OpenSSH-style
    /// `LoginGraceTime` here and there cannot be: this module never owns the
    /// socket (see SPEC.md → Threat model), so the read deadline belongs to
    /// the caller that does.
    max_attempts: u32 = 20,
};

/// Which method actually succeeded.
pub const AuthMethod = enum { publickey, password };

/// Outcome of a successful `serveUserauth`. The user name is copied into a
/// fixed buffer (bounded by `max_user_len`) so the caller has no allocation
/// to free and no pointer into the packet scratch.
pub const AuthResult = struct {
    user_buf: [max_user_len]u8 = undefined,
    user_len: usize = 0,
    method: AuthMethod = .publickey,

    pub fn user(self: *const AuthResult) []const u8 {
        return self.user_buf[0..self.user_len];
    }
};

/// Server: drive RFC 4252 to a verdict on `t`.
///
/// Returns the authenticated identity on SSH_MSG_USERAUTH_SUCCESS. Every
/// rejected attempt costs one of `config.max_attempts`; exhausting them (or
/// receiving no acceptable method) yields `error.AuthenticationFailed`.
/// Receiving something that is not an SSH_MSG_USERAUTH_REQUEST at all —
/// notably a client that tries to open a channel *before* authenticating —
/// is `error.ProtocolError`: the connection protocol is unreachable until
/// this function has returned successfully.
///
/// Call after `server.serverHandshake`/`accept` (which already answered the
/// client's SSH_MSG_SERVICE_REQUEST for `ssh-userauth`).
pub fn serveUserauth(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    config: AuthConfig,
) UserauthError!AuthResult {
    const sid = try sessionId(t);
    const scratch = try gpa.alloc(u8, scratch_len);
    // The §8 `password` method delivers the peer's plaintext secret straight
    // into this buffer, so the server half owes the same scrub the client
    // half (`authenticatePassword`) already does for its request buffer —
    // otherwise a successful login leaves the password sitting in freed heap
    // for whatever allocates next. Unconditional: the failure and error
    // paths carry the same plaintext.
    defer {
        std.crypto.secureZero(u8, scratch);
        gpa.free(scratch);
    }

    var banner_sent = false;
    var attempts: u32 = 0;
    while (attempts < config.max_attempts) {
        const pkt = try t.recvPacket(scratch);
        switch (@as(messages.MessageType, @enumFromInt(msgType(pkt)))) {
            .SSH_MSG_IGNORE, .SSH_MSG_DEBUG => continue,
            .SSH_MSG_DISCONNECT => return error.AuthenticationFailed,
            .SSH_MSG_USERAUTH_REQUEST => {},
            // RFC 4252: the connection protocol only becomes available after
            // SSH_MSG_USERAUTH_SUCCESS. A CHANNEL_OPEN here is a client
            // trying to skip authentication.
            else => {
                t.sendDisconnect(.protocol_error, "expected SSH_MSG_USERAUTH_REQUEST") catch {};
                return error.ProtocolError;
            },
        }

        if (!banner_sent) {
            if (config.banner) |b| try sendBanner(t, b);
            banner_sent = true;
        }

        var c = Cursor{ .b = pkt.payload[1..] };
        const user = try c.string();
        const service = try c.string();
        const method = try c.string();
        if (user.len > max_user_len or service.len > max_service_len)
            return error.NameTooLong;

        // §5: authenticating for any service other than the connection
        // protocol is not something this module supports.
        if (!std.mem.eql(u8, service, connection_service)) {
            attempts += 1;
            try sendFailure(t, config);
            continue;
        }

        if (std.mem.eql(u8, method, "publickey") and config.authorized_key != null) {
            switch (try servePublickey(t, &c, user, service, sid, config)) {
                .success => {
                    try sendSuccess(t);
                    var res = AuthResult{ .method = .publickey };
                    @memcpy(res.user_buf[0..user.len], user);
                    res.user_len = user.len;
                    return res;
                },
                // The query phase answered PK_OK; the client will now send
                // the signed request. Not an attempt.
                .pk_ok_sent => continue,
                .failure => {
                    attempts += 1;
                    try sendFailure(t, config);
                    continue;
                },
            }
        }

        if (std.mem.eql(u8, method, "password") and config.password != null) {
            const change = try c.boolean();
            const password = try c.string();
            if (password.len > max_password_len) return error.NameTooLong;
            if (!change and config.password.?(user, password)) {
                try sendSuccess(t);
                var res = AuthResult{ .method = .password };
                @memcpy(res.user_buf[0..user.len], user);
                res.user_len = user.len;
                return res;
            }
            attempts += 1;
            try sendFailure(t, config);
            continue;
        }

        // "none" (§5.2, the conventional way a client asks which methods are
        // available) and anything unsupported both land here.
        attempts += 1;
        try sendFailure(t, config);
    }
    t.sendDisconnect(.no_more_auth_methods_available, "too many authentication attempts") catch {};
    return error.AuthenticationFailed;
}

const PublickeyOutcome = enum { success, failure, pk_ok_sent };

/// The `publickey` half of `serveUserauth`. `c` is positioned just after the
/// method name.
fn servePublickey(
    t: *transport.Transport,
    c: *Cursor,
    user: []const u8,
    service: []const u8,
    session_id: []const u8,
    config: AuthConfig,
) UserauthError!PublickeyOutcome {
    const has_signature = try c.boolean();
    const algorithm = try c.string();
    const key_blob = try c.string();
    if (key_blob.len > max_key_blob_len) return error.NameTooLong;

    // The algorithm name must be one we can verify, and the key blob must be
    // of the type that algorithm implies (RFC 8332 §3 for the rsa-sha2-*
    // name/`ssh-rsa` blob-type split). Rejecting a mismatch here stops an
    // "announce ed25519, present an RSA blob" style confusion at the door.
    const want_blob_type = transport.keyBlobTypeFor(algorithm) orelse return .failure;
    var kc = Cursor{ .b = key_blob };
    const blob_type = kc.string() catch return .failure;
    if (!std.mem.eql(u8, blob_type, want_blob_type)) return .failure;

    if (!config.authorized_key.?(user, algorithm, key_blob)) return .failure;

    if (!has_signature) {
        // §7 query phase: SSH_MSG_USERAUTH_PK_OK || string alg || string blob.
        var buf: [max_key_blob_len + 256]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_USERAUTH_PK_OK));
        try messages.writeString(&w, algorithm);
        try messages.writeString(&w, key_blob);
        try t.sendPacket(w.buffered());
        return .pk_ok_sent;
    }

    const signature = try c.string();
    if (signature.len > max_signature_len) return error.NameTooLong;

    // Reconstruct exactly what the client must have signed — with OUR
    // session id, never anything taken from the request. This is the
    // replay-prevention step (see the module doc comment).
    var to_sign: [max_key_blob_len + 2048]u8 = undefined;
    var bw: std.Io.Writer = .fixed(&to_sign);
    signedBlob(&bw, session_id, user, service, algorithm, key_blob) catch
        return error.NameTooLong;

    // `transport.verifySignature` dispatches on the KEY BLOB's type and, for
    // RSA, on the algorithm name inside the signature blob — so a signature
    // blob announcing a different algorithm than the request did cannot slip
    // through: it either fails to verify or is an unsupported algorithm.
    var sc = Cursor{ .b = signature };
    const sig_algorithm = sc.string() catch return .failure;
    if (!std.mem.eql(u8, sig_algorithm, algorithm)) return .failure;

    transport.verifySignature(blob_type, key_blob, signature, bw.buffered()) catch |e| switch (e) {
        error.HostKeyVerificationFailed, error.UnsupportedAlgorithm, error.ProtocolError => return .failure,
        else => return e,
    };
    return .success;
}

fn sendSuccess(t: *transport.Transport) UserauthError!void {
    return t.sendPacket(&[_]u8{@intFromEnum(messages.MessageType.SSH_MSG_USERAUTH_SUCCESS)});
}

/// SSH_MSG_USERAUTH_FAILURE (§5.1): `name-list of methods that can continue
/// || boolean partial success`. Partial success is always false — this
/// module never requires a second method.
fn sendFailure(t: *transport.Transport, config: AuthConfig) UserauthError!void {
    var names: [2][]const u8 = undefined;
    var n: usize = 0;
    if (config.authorized_key != null) {
        names[n] = "publickey";
        n += 1;
    }
    if (config.password != null) {
        names[n] = "password";
        n += 1;
    }
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_USERAUTH_FAILURE));
    try messages.writeNameList(&w, names[0..n]);
    try w.writeByte(0);
    return t.sendPacket(w.buffered());
}

fn sendBanner(t: *transport.Transport, banner: []const u8) UserauthError!void {
    if (banner.len > max_banner_len) return error.NameTooLong;
    var buf: [max_banner_len + 64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_USERAUTH_BANNER));
    try messages.writeString(&w, banner);
    try messages.writeString(&w, ""); // language tag
    return t.sendPacket(w.buffered());
}

// ── tests ──────────────────────────────────────────────────────────────────
//
// The end-to-end client↔server userauth exchanges (positive and negative)
// live in `connection.zig`'s loopback harness, which drives the whole stack
// (transport → userauth → channels → exec). The tests here cover the pieces
// that can be checked without a connection.

test "signedBlob: exact RFC 4252 §7 field order and framing" {
    const t = std.testing;
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try signedBlob(&w, "SID", "alice", connection_service, "ssh-ed25519", "KEYBLOB");

    var c = Cursor{ .b = w.buffered() };
    try t.expectEqualStrings("SID", try c.string());
    try t.expectEqual(@as(u8, 50), try c.byte());
    try t.expectEqualStrings("alice", try c.string());
    try t.expectEqualStrings("ssh-connection", try c.string());
    try t.expectEqualStrings("publickey", try c.string());
    try t.expectEqual(true, try c.boolean());
    try t.expectEqualStrings("ssh-ed25519", try c.string());
    try t.expectEqualStrings("KEYBLOB", try c.string());
    try t.expect(c.atEnd());
}

test "signedBlob: a different session id yields a different signed message" {
    const t = std.testing;
    var b1: [256]u8 = undefined;
    var w1: std.Io.Writer = .fixed(&b1);
    try signedBlob(&w1, "SID-A", "alice", connection_service, "ssh-ed25519", "K");
    var b2: [256]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&b2);
    try signedBlob(&w2, "SID-B", "alice", connection_service, "ssh-ed25519", "K");
    try t.expect(!std.mem.eql(u8, w1.buffered(), w2.buffered()));
}

test "sessionId borrows from the transport (regression: not a dead stack copy)" {
    const t = std.testing;
    var in_buf: [1]u8 = .{0};
    var r: std.Io.Reader = .fixed(&in_buf);
    var out_buf: [1]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buf);
    var tr = transport.Transport.init(&r, &w);

    // No KEX yet → no session id to bind to, and userauth must refuse
    // rather than sign against garbage.
    try t.expectError(error.ProtocolError, sessionId(&tr));

    tr.session_id = transport.SessionId.from("0123456789abcdef");
    const s = try sessionId(&tr);
    try t.expectEqualStrings("0123456789abcdef", s);
    // Must alias the transport's own storage. Returning a slice into a
    // by-value copy of the optional's payload compiles fine and yields
    // whatever the stack happened to hold — which is how the signature ends
    // up bound to nothing at all.
    try t.expectEqual(@intFromPtr(&tr.session_id.?.bytes[0]), @intFromPtr(s.ptr));
}

/// Frame `payloads` as plaintext binary packets (the `.none` cipher state) so
/// a test can feed a crafted message stream straight into a server loop
/// without a socket or a KEX.
fn framePackets(out: []u8, payloads: []const []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(out);
    var cipher: transport.CipherState = .none;
    for (payloads) |p| try transport.writePacket(&w, &cipher, p);
    return w.buffered();
}

test "serveUserauth: an oversize peer string is a typed error, not a panic" {
    const t = std.testing;

    // SSH_MSG_USERAUTH_REQUEST whose `user` string announces 4 GiB.
    var pbuf: [64]u8 = undefined;
    var pw: std.Io.Writer = .fixed(&pbuf);
    try pw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_USERAUTH_REQUEST));
    try pw.writeAll(&[_]u8{ 0xff, 0xff, 0xff, 0xff });
    try pw.writeAll("junk");

    var wire: [512]u8 = undefined;
    const framed = try framePackets(&wire, &.{pw.buffered()});

    var r: std.Io.Reader = .fixed(framed);
    var sink_buf: [512]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var tr = transport.Transport.init(&r, &sink);
    tr.session_id = transport.SessionId.from("session");

    try t.expectError(error.ProtocolError, serveUserauth(&tr, t.allocator, .{
        .authorized_key = struct {
            fn f(_: []const u8, _: []const u8, _: []const u8) bool {
                return true;
            }
        }.f,
    }));
}

test "serveUserauth: an oversize packet length is rejected by the framing layer" {
    const t = std.testing;
    // A packet_length field of 0xffff_ffff — the Binary Packet Protocol must
    // refuse it before anything tries to allocate or index with it.
    const evil = [_]u8{ 0xff, 0xff, 0xff, 0xff } ++ [_]u8{0} ** 16;
    var r: std.Io.Reader = .fixed(&evil);
    var sink_buf: [512]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var tr = transport.Transport.init(&r, &sink);
    tr.session_id = transport.SessionId.from("session");

    try t.expectError(error.ProtocolError, serveUserauth(&tr, t.allocator, .{
        .password = struct {
            fn f(_: []const u8, _: []const u8) bool {
                return true;
            }
        }.f,
    }));
}

test "serveUserauth: a received plaintext password does not survive in the freed packet scratch" {
    const t = std.testing;

    // A well-formed RFC 4252 §8 `password` request the callback accepts.
    const secret = "s3cr3t-correct-horse-battery";
    var pbuf: [256]u8 = undefined;
    var pw: std.Io.Writer = .fixed(&pbuf);
    try pw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_USERAUTH_REQUEST));
    try messages.writeString(&pw, "alice");
    try messages.writeString(&pw, connection_service);
    try messages.writeString(&pw, "password");
    try pw.writeByte(0); // FALSE: not a password *change* request
    try messages.writeString(&pw, secret);

    var wire: [512]u8 = undefined;
    const framed = try framePackets(&wire, &.{pw.buffered()});

    // Back `serveUserauth`'s allocations with a buffer this test still owns
    // after they are freed, so the freed bytes can be inspected directly.
    // `recvPacket` decodes the request INTO that scratch, so without the
    // scrub the plaintext password is still lying there, verbatim, for
    // whatever allocates the block next.
    //
    // WHERE THIS TEST HAS TEETH: `std.mem.Allocator.free` does
    // `@memset(bytes, undefined)` before calling the vtable, which in
    // Debug/ReleaseSafe writes 0xaa over the block and hides the leak from
    // any in-process observer. That memset is a no-op in ReleaseFast/
    // ReleaseSmall — exactly the modes a server actually ships in — and
    // there this test fails without the `secureZero` in `serveUserauth`
    // (verified: the password was found at offset 46 of the freed block).
    // The assertion is unconditional because the property must hold in every
    // mode; only its discriminating power is mode-dependent.
    const backing = try t.allocator.alloc(u8, 256 * 1024);
    defer t.allocator.free(backing);
    @memset(backing, 0);
    var fba = std.heap.FixedBufferAllocator.init(backing);

    var r: std.Io.Reader = .fixed(framed);
    var sink_buf: [512]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var tr = transport.Transport.init(&r, &sink);
    tr.session_id = transport.SessionId.from("session");

    const res = try serveUserauth(&tr, fba.allocator(), .{
        .password = struct {
            fn f(u: []const u8, p: []const u8) bool {
                return std.mem.eql(u8, u, "alice") and
                    std.mem.eql(u8, p, "s3cr3t-correct-horse-battery");
            }
        }.f,
    });
    // Positive control: the exchange really happened (an authentication that
    // never ran would trivially leave no password behind).
    try t.expectEqualStrings("alice", res.user());
    try t.expectEqual(AuthMethod.password, res.method);

    try t.expectEqual(@as(?usize, null), std.mem.indexOf(u8, backing, secret));
}

test "an ed25519 userauth signature verifies only against its own session id" {
    const t = std.testing;
    const gpa = t.allocator;
    const seed: [32]u8 = [_]u8{7} ** 32;
    const key: AuthKey = .{ .ed25519 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) };
    const blob = try key.publicBlob(gpa);
    defer gpa.free(blob);

    var mbuf: [512]u8 = undefined;
    var mw: std.Io.Writer = .fixed(&mbuf);
    try signedBlob(&mw, "session-A", "alice", connection_service, "ssh-ed25519", blob);
    const sig = try key.sign(gpa, mw.buffered());
    defer gpa.free(sig);

    try transport.verifySignature("ssh-ed25519", blob, sig, mw.buffered());

    // Same signature, verifier that believes the session id is different →
    // rejected. (This is the property the loopback reject-test exercises
    // end-to-end.)
    var obuf: [512]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&obuf);
    try signedBlob(&ow, "session-B", "alice", connection_service, "ssh-ed25519", blob);
    try t.expectError(
        error.HostKeyVerificationFailed,
        transport.verifySignature("ssh-ed25519", blob, sig, ow.buffered()),
    );
}

test "servePublickey: an ed25519 key blob, its OWN valid signature, wrapped in a signature blob that LIES about the algorithm name, is refused (RFC 8332 §3 blob-type check)" {
    // The blob-type guard the module doc comment calls out by name
    // ("announce ed25519, present an RSA blob"). This is not a strawman:
    // `transport.verifySignature`'s `ssh-ed25519` branch never looks at the
    // signature blob's OWN algorithm-name field at all (see its source) —
    // only `key_type` (derived from the KEY BLOB) selects that branch. So a
    // forged outer signature blob can claim ANY algorithm name and still
    // carry a genuine raw ed25519 signature that verifies fine once that
    // branch is reached. The one thing standing between "genuine ed25519
    // signature, mislabelled rsa-sha2-256" and a successful login is the
    // blob-type cross-check at the top of `servePublickey` — `signedBlob`
    // folds the request's declared `algorithm` into what gets signed, so the
    // signature is cryptographically valid over exactly this forged request.
    const t = std.testing;
    const gpa = t.allocator;
    const seed: [32]u8 = [_]u8{9} ** 32;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const key: AuthKey = .{ .ed25519 = kp };
    const blob = try key.publicBlob(gpa);
    defer gpa.free(blob);

    const session_id = "session-mismatch";
    const user = "alice";
    const lying_algorithm = "rsa-sha2-256"; // transport.keyBlobTypeFor => "ssh-rsa", but `blob` is "ssh-ed25519"

    var mbuf: [512]u8 = undefined;
    var mw: std.Io.Writer = .fixed(&mbuf);
    try signedBlob(&mw, session_id, user, connection_service, lying_algorithm, blob);
    const raw_sig = try kp.sign(mw.buffered(), null);

    // Hand-build the OUTER signature blob with a forged algorithm name,
    // wrapping the genuine raw ed25519 bytes — exactly what
    // `HostKey.sign` never does (it always names the real key type), and
    // exactly what an attacker who controls the wire is free to send.
    var sbuf: [512]u8 = undefined;
    var sw: std.Io.Writer = .fixed(&sbuf);
    try messages.writeString(&sw, lying_algorithm);
    try messages.writeString(&sw, &raw_sig.toBytes());
    const forged_sig_blob = sw.buffered();

    var rbuf: [4096]u8 = undefined;
    var rw: std.Io.Writer = .fixed(&rbuf);
    try rw.writeByte(1); // has_signature = TRUE
    try messages.writeString(&rw, lying_algorithm);
    try messages.writeString(&rw, blob);
    try messages.writeString(&rw, forged_sig_blob);

    var dummy_in: std.Io.Reader = .fixed(&.{});
    var dummy_out_buf: [64]u8 = undefined;
    var dummy_out: std.Io.Writer = .fixed(&dummy_out_buf);
    var tr = transport.Transport.init(&dummy_in, &dummy_out);

    var c = Cursor{ .b = rw.buffered() };
    const outcome = try servePublickey(&tr, &c, user, connection_service, session_id, .{
        .authorized_key = struct {
            fn f(_: []const u8, _: []const u8, _: []const u8) bool {
                return true;
            }
        }.f,
    });
    try t.expectEqual(PublickeyOutcome.failure, outcome);
}
