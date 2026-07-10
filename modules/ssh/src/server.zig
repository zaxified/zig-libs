// SPDX-License-Identifier: MIT

//! SSH-2.0 SERVER (responder) transport layer (RFC 4253) — the crypto mirror
//! of the client side in `transport.zig`.
//!
//! This file deliberately does NOT re-implement anything role-symmetric — it
//! imports and reuses `transport.zig`'s packet codec (`readPacket`/
//! `writePacket`), `KexInit` encode/decode + `TransportError`, `deriveKeys`'
//! KDF formula, the two `CipherState` variants, `exchangeVersions`, and the
//! `Transport` struct's steady-state `sendPacket`/`recvPacket`. What is new
//! here is purely the responder-role KEX exchange (receiving the client's
//! ephemeral public value instead of sending one) and host-key signing
//! (instead of the client's host-key signature *verification*), plus loading
//! host private keys from OpenSSH `PROTOCOL.key` files.
//!
//! A few small private helpers of `transport.zig` (`fillRandom`,
//! `hashString`/`encodeMpint`, the per-letter `deriveKeyBytes` and the
//! cipher-install `buildCipher`, `pickFirst`) are not `pub` there and
//! `transport.zig` is off-limits to this pass, so byte-identical local
//! mirrors live here — each is marked "mirrors transport.zig".
//!
//! Scope: transport/KEX handshake only, ending with the responder side of
//! SSH_MSG_SERVICE_REQUEST → SSH_MSG_SERVICE_ACCEPT. Userauth (RFC 4252,
//! SSH_MSG_USERAUTH_*) and connection-protocol channels (RFC 4254,
//! SSH_MSG_CHANNEL_*) are out of scope here, same as `root.zig`'s
//! `userauth`/`openSession`/`exec` placeholders.
//!
//! Provenance: clean-room from RFC 4253/4251/8731 (+ RFC 8332/8709/5656 for
//! the host-key algorithms and OpenSSH `PROTOCOL.key`/
//! `PROTOCOL.chacha20poly1305` for the container/cipher formats); crypto from
//! `std.crypto` plus the sibling `rsa` module.

const std = @import("std");
const builtin = @import("builtin");
const transport = @import("transport.zig");
const messages = @import("messages.zig");
const rsa = @import("rsa");

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const X25519 = std.crypto.dh.X25519;

// ── entropy (mirrors transport.zig's private fillRandom) ────────────────────

/// Fill `buf` with cryptographically secure random bytes from the OS
/// (getrandom(2)). Never a user-space PRNG — the server's ephemeral X25519
/// key and KEXINIT cookie depend on real entropy. Panics (does not silently
/// degrade) if the OS entropy source is unavailable, matching
/// `transport.zig`'s client-side policy (whose `fillRandom` is private).
fn fillRandom(buf: []u8) void {
    if (builtin.os.tag != .linux)
        @compileError("fillRandom: only the Linux getrandom(2) entropy path is wired up");
    var off: usize = 0;
    while (off < buf.len) {
        const rc = std.os.linux.getrandom(buf.ptr + off, buf.len - off, 0);
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            if (signed == -@as(isize, @intFromEnum(std.os.linux.E.INTR))) continue;
            @panic("getrandom failed");
        }
        off += @intCast(signed);
    }
}

// ── small wire/hash helpers (mirror transport.zig privates) ─────────────────

/// A non-allocating cursor over an SSH wire blob (`uint32 len || bytes`).
/// Mirrors transport.zig's private `SliceReader`.
const WireCursor = struct {
    b: []const u8,
    i: usize = 0,

    fn string(self: *WireCursor) transport.TransportError![]const u8 {
        if (self.i + 4 > self.b.len) return error.ProtocolError;
        const len = std.mem.readInt(u32, self.b[self.i..][0..4], .big);
        self.i += 4;
        if (@as(usize, len) + self.i > self.b.len) return error.ProtocolError;
        const s = self.b[self.i .. self.i + len];
        self.i += len;
        return s;
    }
};

/// `update` with a `string`-framed (uint32 length-prefixed) value — the RFC
/// 4253 §8 exchange-hash convention. Mirrors transport.zig's `hashString`.
fn hashString(sh: *Sha256, data: []const u8) void {
    var lb: [4]u8 = undefined;
    std.mem.writeInt(u32, &lb, @intCast(data.len), .big);
    sh.update(&lb);
    sh.update(data);
}

/// Encode a non-negative big-endian magnitude as an SSH mpint into `out`,
/// returning the written slice. Mirrors transport.zig's `encodeMpint`.
fn encodeMpint(out: []u8, magnitude: []const u8) []const u8 {
    var w: std.Io.Writer = .fixed(out);
    messages.writeMpint(&w, magnitude) catch unreachable;
    return w.buffered();
}

fn msgType(p: transport.Packet) u8 {
    return if (p.payload.len == 0) 0 else p.payload[0];
}

fn stripLeadingZeros(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i < s.len and s[i] == 0) i += 1;
    return s[i..];
}

// ── host key (signing side) ─────────────────────────────────────────────────

/// A loaded server host private key, tagged by key type. The client-side
/// counterpart of each variant is verified in `transport.zig`'s
/// `verifySignature` — this is the signing mirror of that function, one
/// variant per host-key algorithm the server can offer in `KexInit`'s
/// `server_host_key_algorithms`.
pub const HostKey = union(enum) {
    /// `ssh-ed25519` (RFC 8709). Signing is `std.crypto.sign.Ed25519` — no
    /// wire-format parsing needed once the `KeyPair` is in memory.
    ed25519: Ed25519.KeyPair,
    /// `rsa-sha2-256` / `rsa-sha2-512` (RFC 8332). Carries the RSA secret key
    /// plus which digest variant this host key signs with (a single RSA key
    /// could in principle offer either/both algorithm names, but this module
    /// pins one hash per loaded `HostKey` value for simplicity — a caller
    /// wanting both loads the same key twice under two `HostKey` values).
    /// `public_key` carries the matching (n, e) pair for building `K_S`
    /// (`rsa.SecretKey` does not store the public exponent `e`).
    rsa: struct {
        secret_key: rsa.SecretKey,
        public_key: rsa.PublicKey,
        hash: RsaHash,
    },
    /// `ecdsa-sha2-nistp256` (RFC 5656). Included because
    /// `std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair` already exists and the
    /// shape mirrors `ed25519` exactly — no extra parsing machinery needed.
    ecdsa_p256: EcdsaP256.KeyPair,

    pub const RsaHash = enum { sha2_256, sha2_512 };

    /// The IANA/RFC algorithm name this host key signs with (matches an
    /// entry in `transport.server_host_key_algorithms`), and the wire
    /// key-type name embedded in `K_S` (RFC 4253 §7.1's "server_host_key
    /// algorithms" name-list intentionally equals the key-blob type name for
    /// every algorithm this module offers, except rsa-sha2-* whose key blob
    /// is still typed `"ssh-rsa"` per RFC 8332 §3).
    pub fn algorithmName(self: HostKey) []const u8 {
        return switch (self) {
            .ed25519 => "ssh-ed25519",
            .rsa => |r| switch (r.hash) {
                .sha2_256 => "rsa-sha2-256",
                .sha2_512 => "rsa-sha2-512",
            },
            .ecdsa_p256 => "ecdsa-sha2-nistp256",
        };
    }

    pub const FromOpenSSHError = rsa.FromOpenSSHError || error{
        /// The container parsed structurally but names a key type this
        /// module does not load (only `ssh-rsa` and `ssh-ed25519`).
        UnsupportedKeyType,
    };

    /// Load a host private key from OpenSSH `PROTOCOL.key` text
    /// (`-----BEGIN OPENSSH PRIVATE KEY-----`). `passphrase` is `null` for an
    /// unencrypted key.
    ///
    /// Dispatch: the openssh-key-v1 container's public-key blob names the key
    /// type. `"ssh-rsa"` routes to the sibling `rsa` module's
    /// `rsa.fromOpenSSH` for the secret key (which handles bcrypt-pbkdf +
    /// AES for encrypted keys) plus a local parse of the container's public
    /// blob for (e, n); the result is pinned to `.sha2_256` (RFC 8332 leaves
    /// the rsa-sha2-* variant to negotiation, the container does not encode
    /// it — flip `.hash` after loading for `rsa-sha2-512`). `"ssh-ed25519"`
    /// routes to `parseEd25519OpenSSH` (unencrypted containers only — real
    /// deployed host keys are unencrypted; an encrypted ed25519 container is
    /// rejected with `error.UnsupportedCipher`).
    pub fn fromOpenSSH(text: []const u8, passphrase: ?[]const u8) FromOpenSSHError!HostKey {
        var bin_buf: [16 * 1024]u8 = undefined;
        defer std.crypto.secureZero(u8, &bin_buf);
        const bin = try pemDecodeOpensshBlock(text, &bin_buf);
        const hdr = try parseContainerHeader(bin);

        var pk_cur = WireCursor{ .b = hdr.public_blob };
        const key_type = pk_cur.string() catch return error.InvalidOpenSSH;

        if (std.mem.eql(u8, key_type, "ssh-rsa")) {
            const sk = try rsa.fromOpenSSH(text, passphrase orelse "");
            // Public (e, n) from the container's (always-plaintext) public
            // blob: string "ssh-rsa" || mpint e || mpint n.
            const e_wire = pk_cur.string() catch return error.InvalidOpenSSH;
            const n_wire = pk_cur.string() catch return error.InvalidOpenSSH;
            const pk = rsa.PublicKey.fromBytes(n_wire, e_wire) catch return error.InvalidOpenSSH;
            // Cross-check: the public blob's n must be the secret key's n.
            var n_sk: [rsa.max_modulus_len]u8 = undefined;
            sk.n.toBytes(&n_sk, .big) catch return error.InvalidPrivateKey;
            if (!std.mem.eql(u8, stripLeadingZeros(&n_sk), stripLeadingZeros(n_wire)))
                return error.InvalidPrivateKey;
            return .{ .rsa = .{ .secret_key = sk, .public_key = pk, .hash = .sha2_256 } };
        }
        if (std.mem.eql(u8, key_type, "ssh-ed25519")) {
            return .{ .ed25519 = try parseEd25519OpenSSH(bin, passphrase orelse "") };
        }
        return error.UnsupportedKeyType;
    }

    /// Build the SSH wire-format host-key blob `K_S` (RFC 4253 §7.1 / RFC
    /// 4251 §5): `string(key-type-name) || <type-specific material>`.
    ///   - ed25519: `string("ssh-ed25519") || string(32-byte pubkey)`
    ///     (RFC 8709 §4).
    ///   - rsa: `string("ssh-rsa") || mpint(e) || mpint(n)` (RFC 4253 §6.6 —
    ///     note the blob type name is always `"ssh-rsa"` here, never
    ///     `"rsa-sha2-*"`; only the *signature* blob's algorithm name differs,
    ///     per RFC 8332 §3).
    ///   - ecdsa_p256: `string("ecdsa-sha2-nistp256") ||
    ///     string("nistp256") || string(SEC1 uncompressed point Q)`
    ///     (RFC 5656 §3.1).
    pub fn publicBlob(self: HostKey, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var buf: [1024]u8 = undefined; // rsa-4096 K_S is ~535 bytes; others far less
        var w: std.Io.Writer = .fixed(&buf);
        switch (self) {
            .ed25519 => |kp| {
                messages.writeString(&w, "ssh-ed25519") catch unreachable;
                messages.writeString(&w, &kp.public_key.toBytes()) catch unreachable;
            },
            .rsa => |r| {
                var eb: [rsa.max_modulus_len]u8 = undefined;
                var nb: [rsa.max_modulus_len]u8 = undefined;
                r.public_key.e.toBytes(&eb, .big) catch unreachable;
                r.public_key.n.toBytes(&nb, .big) catch unreachable;
                messages.writeString(&w, "ssh-rsa") catch unreachable;
                messages.writeMpint(&w, &eb) catch unreachable;
                messages.writeMpint(&w, &nb) catch unreachable;
            },
            .ecdsa_p256 => |kp| {
                const q = kp.public_key.toUncompressedSec1();
                messages.writeString(&w, "ecdsa-sha2-nistp256") catch unreachable;
                messages.writeString(&w, "nistp256") catch unreachable;
                messages.writeString(&w, &q) catch unreachable;
            },
        }
        return gpa.dupe(u8, w.buffered());
    }

    /// Sign `exchange_hash` (`H`) with this host key, returning the SSH
    /// signature wire blob `string(sig-type-name) || string(raw-signature-
    /// bytes)` (RFC 4253 §6.6):
    ///   - ed25519: `sig-type-name = "ssh-ed25519"`, raw bytes = the 64-byte
    ///     `std.crypto.sign.Ed25519` signature (no domain-separation context
    ///     per RFC 8709).
    ///   - rsa: `sig-type-name = "rsa-sha2-256"` or `"rsa-sha2-512"` (per
    ///     `self.rsa.hash`), raw bytes = `rsa.signPkcs1v15(secret_key,
    ///     Sha256|Sha512, exchange_hash, out)` (RFC 8332 §3).
    ///   - ecdsa_p256: `sig-type-name = "ecdsa-sha2-nistp256"`, raw bytes =
    ///     `mpint(r) || mpint(s)` (RFC 5656 §3.1.2 — NOT the raw 64-byte
    ///     fixed-width form; `transport.zig`'s `verifySignature` decodes this
    ///     mpint pair back out on the client side).
    ///
    /// Signing failures cannot occur for a key that loaded/validated
    /// successfully (the std/rsa sign paths only fail on malformed key
    /// material or too-small moduli, both rejected at load time), so they
    /// panic rather than widening the error set.
    pub fn sign(self: HostKey, gpa: std.mem.Allocator, exchange_hash: []const u8) std.mem.Allocator.Error![]u8 {
        var buf: [1024]u8 = undefined; // rsa-4096 signature blob is ~532 bytes
        var w: std.Io.Writer = .fixed(&buf);
        switch (self) {
            .ed25519 => |kp| {
                const sig = kp.sign(exchange_hash, null) catch
                    @panic("ed25519 host-key signing failed on a validated key");
                messages.writeString(&w, "ssh-ed25519") catch unreachable;
                messages.writeString(&w, &sig.toBytes()) catch unreachable;
            },
            .rsa => |r| {
                var sbuf: [rsa.max_modulus_len]u8 = undefined;
                const raw = switch (r.hash) {
                    .sha2_256 => rsa.signPkcs1v15(r.secret_key, Sha256, exchange_hash, &sbuf),
                    .sha2_512 => rsa.signPkcs1v15(r.secret_key, Sha512, exchange_hash, &sbuf),
                } catch @panic("rsa host-key signing failed on a validated key");
                messages.writeString(&w, self.algorithmName()) catch unreachable;
                messages.writeString(&w, raw) catch unreachable;
            },
            .ecdsa_p256 => |kp| {
                const sig = kp.sign(exchange_hash, null) catch
                    @panic("ecdsa host-key signing failed on a validated key");
                var inner_buf: [80]u8 = undefined;
                var iw: std.Io.Writer = .fixed(&inner_buf);
                messages.writeMpint(&iw, &sig.r) catch unreachable;
                messages.writeMpint(&iw, &sig.s) catch unreachable;
                messages.writeString(&w, "ecdsa-sha2-nistp256") catch unreachable;
                messages.writeString(&w, iw.buffered()) catch unreachable;
            },
        }
        return gpa.dupe(u8, w.buffered());
    }
};

// ── openssh-key-v1 container parsing (ed25519 + type dispatch) ──────────────

/// Decode the base64 body of a `-----BEGIN OPENSSH PRIVATE KEY-----` PEM
/// block into `out` (the `rsa` module's PEM decoder is private to it).
fn pemDecodeOpensshBlock(text: []const u8, out: []u8) HostKey.FromOpenSSHError![]u8 {
    const begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const end = "-----END OPENSSH PRIVATE KEY-----";
    const bi = std.mem.indexOf(u8, text, begin) orelse return error.MissingPemBlock;
    const body_start = bi + begin.len;
    const ei = std.mem.indexOfPos(u8, text, body_start, end) orelse return error.InvalidPem;

    var b64: [24 * 1024]u8 = undefined;
    var n: usize = 0;
    for (text[body_start..ei]) |c| {
        if (c == '\r' or c == '\n' or c == ' ' or c == '\t') continue;
        if (n >= b64.len) return error.InvalidPem;
        b64[n] = c;
        n += 1;
    }
    const dec = std.base64.standard.Decoder;
    const dlen = dec.calcSizeForSlice(b64[0..n]) catch return error.InvalidPem;
    if (dlen > out.len) return error.InvalidPem;
    dec.decode(out[0..dlen], b64[0..n]) catch return error.InvalidPem;
    return out[0..dlen];
}

const ContainerHeader = struct {
    ciphername: []const u8,
    kdfname: []const u8,
    kdfoptions: []const u8,
    /// Public-key blob #1 — always plaintext, even in an encrypted container.
    public_blob: []const u8,
    /// The (possibly encrypted) private-keys section.
    private_section: []const u8,
};

/// Parse the openssh-key-v1 container framing (OpenSSH `PROTOCOL.key`):
/// magic `"openssh-key-v1\x00"`, cipher/kdf strings, nkeys (must be 1), the
/// public-key blob and the private-keys section.
fn parseContainerHeader(bin: []const u8) HostKey.FromOpenSSHError!ContainerHeader {
    const magic = "openssh-key-v1\x00";
    if (bin.len < magic.len or !std.mem.eql(u8, bin[0..magic.len], magic))
        return error.InvalidOpenSSH;
    var cur = WireCursor{ .b = bin, .i = magic.len };
    const ciphername = cur.string() catch return error.InvalidOpenSSH;
    const kdfname = cur.string() catch return error.InvalidOpenSSH;
    const kdfoptions = cur.string() catch return error.InvalidOpenSSH;
    if (cur.i + 4 > bin.len) return error.InvalidOpenSSH;
    const nkeys = std.mem.readInt(u32, bin[cur.i..][0..4], .big);
    cur.i += 4;
    if (nkeys != 1) return error.InvalidOpenSSH;
    const public_blob = cur.string() catch return error.InvalidOpenSSH;
    const private_section = cur.string() catch return error.InvalidOpenSSH;
    if (cur.i != bin.len) return error.InvalidOpenSSH;
    return .{
        .ciphername = ciphername,
        .kdfname = kdfname,
        .kdfoptions = kdfoptions,
        .public_blob = public_blob,
        .private_section = private_section,
    };
}

/// Parse an ed25519 private key from an **unencrypted** openssh-key-v1
/// container (cipher/kdf `"none"` — which is what real deployed host keys
/// like `/etc/ssh/ssh_host_ed25519_key` use). An encrypted container is
/// rejected with `error.UnsupportedCipher` (`passphrase` is accepted for
/// signature compatibility but never consumed).
///
/// Private-keys section layout (all RFC 4251 §5 primitives): `uint32`
/// checkint1 == `uint32` checkint2, `string` keytype `"ssh-ed25519"`,
/// `string` 32-byte pubkey, `string` 64-byte (seed || pubkey) — exactly the
/// `std.crypto.sign.Ed25519.SecretKey` encoding — `string` comment, then
/// deterministic padding bytes `0x01, 0x02, ...`.
pub fn parseEd25519OpenSSH(bin: []const u8, passphrase: []const u8) HostKey.FromOpenSSHError!Ed25519.KeyPair {
    _ = passphrase; // encrypted containers are rejected below, never decrypted
    const hdr = try parseContainerHeader(bin);
    if (!std.mem.eql(u8, hdr.ciphername, "none")) return error.UnsupportedCipher;
    if (!std.mem.eql(u8, hdr.kdfname, "none") or hdr.kdfoptions.len != 0)
        return error.InvalidOpenSSH;

    var cur = WireCursor{ .b = hdr.private_section };
    if (cur.b.len < 8) return error.InvalidOpenSSH;
    const check1 = std.mem.readInt(u32, cur.b[0..4], .big);
    const check2 = std.mem.readInt(u32, cur.b[4..8], .big);
    cur.i = 8;
    // Unencrypted container: a checkint mismatch is corruption, not a
    // passphrase problem.
    if (check1 != check2) return error.InvalidOpenSSH;

    const keytype = cur.string() catch return error.InvalidOpenSSH;
    if (!std.mem.eql(u8, keytype, "ssh-ed25519")) return error.UnsupportedKeyType;
    const pub_bytes = cur.string() catch return error.InvalidOpenSSH;
    const priv_bytes = cur.string() catch return error.InvalidOpenSSH;
    _ = cur.string() catch return error.InvalidOpenSSH; // comment
    if (pub_bytes.len != 32 or priv_bytes.len != 64) return error.InvalidPrivateKey;
    // priv = 32-byte seed || 32-byte public key; the copies must agree.
    if (!std.mem.eql(u8, priv_bytes[32..64], pub_bytes)) return error.InvalidPrivateKey;
    // Deterministic padding to the cipher block size (8 for "none").
    const pad = cur.b[cur.i..];
    if (pad.len >= 8) return error.InvalidOpenSSH;
    for (pad, 0..) |b, i| {
        if (b != @as(u8, @intCast(i + 1))) return error.InvalidOpenSSH;
    }

    const sk = Ed25519.SecretKey.fromBytes(priv_bytes[0..64].*) catch
        return error.InvalidPrivateKey;
    const kp = Ed25519.KeyPair.fromSecretKey(sk) catch return error.InvalidPrivateKey;
    // fromSecretKey re-derives the public key from the seed; require it to
    // match the container's copy.
    if (!std.mem.eql(u8, &kp.public_key.toBytes(), pub_bytes)) return error.InvalidPrivateKey;
    return kp;
}

// ── server configuration ────────────────────────────────────────────────────

/// Server-side handshake configuration, the responder-role counterpart of
/// what the client passes inline to `transport.Transport.clientHandshake`
/// (a `HostKeyVerifier` callback) — the server instead offers a fixed set of
/// host keys it can sign with.
pub const ServerConfig = struct {
    /// Host keys this server can authenticate itself with, most-preferred
    /// first. `serverHandshake` picks the first algorithm on the *client's*
    /// `server_host_key_algorithms` name-list for which a key is loaded
    /// here (RFC 4253 §7.1 negotiation is client-preference-ordered).
    host_keys: []const HostKey,
    /// Our identification `softwareversion` (RFC 4253 §4.2) — same field
    /// name/shape as `transport.IdentificationString.softwareversion`.
    /// Defaults to the client's own constant so a server and client built
    /// from this same module advertise consistent software; a real server
    /// deployment will usually want to override it.
    server_software: []const u8 = transport.software_version,
};

// ── server-side (responder-role) key exchange ───────────────────────────────

/// Run the server side of curve25519-sha256 key exchange (RFC 8731): receive
/// SSH_MSG_KEX_ECDH_INIT (`Q_C`, the client's ephemeral public value),
/// generate our own ephemeral keypair (`Q_S`, seeded from getrandom(2) via
/// `fillRandom`), compute the shared secret `K` and exchange hash `H`
/// (identical SHA-256 formula/field order to `transport.zig`'s
/// `curve25519Kex`: `H = SHA256(V_C || V_S || I_C || I_S || K_S || Q_C ||
/// Q_S || K)` with every field `string`-framed except `K`, which is an
/// mpint), sign `H` with `host_key`, then send SSH_MSG_KEX_ECDH_REPLY
/// (`K_S`, `Q_S`, signature).
///
/// This is the genuinely new, server-only half of KEX — the client-side
/// counterpart (`transport.curve25519Kex`) sends `Q_C` first and then
/// verifies the reply's signature; this function receives `Q_C` first and
/// then produces the signature. Everything downstream of having `K`/`H`
/// (key derivation, cipher construction, the Binary Packet Protocol) is
/// reused from `transport.zig`, not reimplemented.
pub fn curve25519KexServer(
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    cipher: *transport.CipherState,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: HostKey,
    gpa: std.mem.Allocator,
) transport.TransportError!transport.KexResult {
    // SSH_MSG_KEX_ECDH_INIT: byte || string Q_C.
    var buf: [16384]u8 = undefined;
    const pkt = try transport.readPacket(r, cipher, &buf);
    if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXDH_INIT)) return error.KexFailed;
    var cur = WireCursor{ .b = pkt.payload[1..] };
    const q_c = try cur.string();
    if (q_c.len != 32) return error.KexFailed;
    var q_c_arr: [32]u8 = undefined;
    @memcpy(&q_c_arr, q_c);

    // Our ephemeral X25519 keypair (seed from the OS CSPRNG, zeroed after).
    var seed: [32]u8 = undefined;
    fillRandom(&seed);
    defer std.crypto.secureZero(u8, &seed);
    const kp = X25519.KeyPair.generateDeterministic(seed) catch return error.KexFailed;
    const q_s = kp.public_key;

    var shared = X25519.scalarmult(kp.secret_key, q_c_arr) catch return error.KexFailed;
    defer std.crypto.secureZero(u8, &shared);

    var kmbuf: [4 + 33]u8 = undefined;
    defer std.crypto.secureZero(u8, &kmbuf);
    const k_mpint = encodeMpint(&kmbuf, &shared);

    const k_s = try host_key.publicBlob(gpa);
    defer gpa.free(k_s);

    // H = SHA256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K).
    var h: [32]u8 = undefined;
    {
        var sh = Sha256.init(.{});
        hashString(&sh, client_id);
        hashString(&sh, server_id);
        hashString(&sh, client_kexinit_payload);
        hashString(&sh, server_kexinit_payload);
        hashString(&sh, k_s);
        hashString(&sh, q_c);
        hashString(&sh, &q_s);
        sh.update(k_mpint); // K, already mpint-encoded
        sh.final(&h);
    }

    const sig = try host_key.sign(gpa, &h);
    defer gpa.free(sig);

    // SSH_MSG_KEX_ECDH_REPLY: byte || string K_S || string Q_S || string sig.
    var obuf: [2048]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&obuf);
    try ow.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_KEXDH_REPLY));
    try messages.writeString(&ow, k_s);
    try messages.writeString(&ow, &q_s);
    try messages.writeString(&ow, sig);
    try transport.writePacket(w, cipher, ow.buffered());

    return .{ .shared_secret = shared, .exchange_hash = h };
}

// ── key install (mirrors transport.zig's private deriveKeyBytes/buildCipher) ─

/// RFC 4253 §7.2 KDF for one key letter: `HASH(K || H || X || session_id)`,
/// extended via `HASH(K || H || <all so far>)` to fill `out`. Mirrors
/// transport.zig's private `deriveKeyBytes` (needed here because the
/// chacha20-poly1305 cipher takes 64 bytes of `C`/`D` material, which the
/// public `transport.deriveKeys` struct does not expose).
fn deriveKeyBytes(out: []u8, letter: u8, k_mpint: []const u8, h: [32]u8, session_id: [32]u8) void {
    var first: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &first);
    var s = Sha256.init(.{});
    s.update(k_mpint);
    s.update(&h);
    s.update(&[_]u8{letter});
    s.update(&session_id);
    s.final(&first);
    var written: usize = @min(out.len, 32);
    @memcpy(out[0..written], first[0..written]);
    while (written < out.len) {
        var s2 = Sha256.init(.{});
        s2.update(k_mpint);
        s2.update(&h);
        s2.update(out[0..written]);
        var block: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &block);
        s2.final(&block);
        const take = @min(@as(usize, 32), out.len - written);
        @memcpy(out[written .. written + take], block[0..take]);
        written += take;
    }
}

const Direction = enum { c2s, s2c };

/// Build the installed `CipherState` for one direction from a negotiated
/// cipher name and the KEX result. Mirrors transport.zig's private
/// `buildCipher`; the direction letters (A/C/E = client-to-server, B/D/F =
/// server-to-client) are fixed by RFC 4253 §7.2 regardless of which role
/// calls this — the *server* assigns `.s2c` to its WRITE cipher and `.c2s`
/// to its READ cipher (the exact swap of the client's assignment).
fn buildCipher(name: []const u8, dir: Direction, kr: transport.KexResult, sid: [32]u8, seq: u32) transport.TransportError!transport.CipherState {
    var kmbuf: [4 + 33]u8 = undefined;
    defer std.crypto.secureZero(u8, &kmbuf);
    const k_mpint = encodeMpint(&kmbuf, &kr.shared_secret);
    const h = kr.exchange_hash;
    if (std.mem.eql(u8, name, "chacha20-poly1305@openssh.com")) {
        var km: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &km);
        deriveKeyBytes(&km, if (dir == .c2s) 'C' else 'D', k_mpint, h, sid);
        return .{ .chacha20_poly1305 = .{
            .key_main = km[0..32].*,
            .key_header = km[32..64].*,
            .sequence_number = seq,
        } };
    } else if (std.mem.eql(u8, name, "aes256-ctr")) {
        var iv: [16]u8 = undefined;
        var ek: [32]u8 = undefined;
        var mk: [32]u8 = undefined;
        deriveKeyBytes(&iv, if (dir == .c2s) 'A' else 'B', k_mpint, h, sid);
        deriveKeyBytes(&ek, if (dir == .c2s) 'C' else 'D', k_mpint, h, sid);
        deriveKeyBytes(&mk, if (dir == .c2s) 'E' else 'F', k_mpint, h, sid);
        return .{ .aes256_ctr_hmac_sha256 = .{
            .enc_key = ek,
            .enc_iv = iv,
            .mac_key = mk,
            .sequence_number = seq,
        } };
    }
    return error.UnsupportedAlgorithm;
}

/// First name on `preferred` that `available` also lists (RFC 4253 §7.1 —
/// the *client's* list is the preference order, so the server passes the
/// client's list first). Mirrors transport.zig's private `pickFirst`.
fn pickFirst(preferred: []const []const u8, available: []const []const u8) ?[]const u8 {
    for (preferred) |p| {
        for (available) |a| {
            if (std.mem.eql(u8, p, a)) return p;
        }
    }
    return null;
}

// ── full server handshake ───────────────────────────────────────────────────

/// Full server (responder) handshake — the mirror of
/// `transport.Transport.clientHandshake`, taking a `ServerConfig` instead of
/// a `HostKeyVerifier`. Operates on an already-`transport.Transport.init`-ed
/// connection (same struct the client side uses — NOT duplicated here).
///
/// Sequence: version exchange (reused `transport.exchangeVersions` —
/// role-symmetric) → KEXINIT exchange (our `server_host_key_algorithms`
/// list is built from `config.host_keys`) → client-preference negotiation →
/// `curve25519KexServer` → NEWKEYS both ways → cipher install with the
/// server direction mapping (write = s2c, read = c2s) → respond to the
/// client's SSH_MSG_SERVICE_REQUEST `"ssh-userauth"` with
/// SSH_MSG_SERVICE_ACCEPT.
///
/// After this returns, `t` is an encrypted transport ready for userauth
/// (out of scope here, see `root.zig`'s `userauth` placeholder).
pub fn serverHandshake(t: *transport.Transport, gpa: std.mem.Allocator, config: ServerConfig) transport.TransportError!void {
    if (config.host_keys.len == 0) return error.UnsupportedAlgorithm;

    // 1. Version exchange (role-symmetric; we speak first, which is the
    // conventional server behavior anyway).
    const local_id = transport.IdentificationString{ .softwareversion = config.server_software };
    const v_c = try transport.exchangeVersions(gpa, t.reader, t.writer, local_id);
    defer gpa.free(v_c);
    var vsbuf: [128]u8 = undefined;
    const v_s = std.fmt.bufPrint(&vsbuf, "SSH-2.0-{s}", .{config.server_software}) catch
        return error.VersionExchangeFailed;

    const scratch = try gpa.alloc(u8, 64 * 1024);
    defer gpa.free(scratch);

    // 2. Our KEXINIT: host-key algorithms restricted to keys we hold.
    const hk_names = try gpa.alloc([]const u8, config.host_keys.len);
    defer gpa.free(hk_names);
    for (config.host_keys, hk_names) |hk, *name| name.* = hk.algorithmName();

    var cookie: [16]u8 = undefined;
    fillRandom(&cookie);
    const empty: []const []const u8 = &.{};
    const local_kex = transport.KexInit{
        .cookie = cookie,
        .kex_algorithms = &transport.kex_algorithms,
        .server_host_key_algorithms = hk_names,
        .encryption_algorithms_client_to_server = &transport.encryption_algorithms,
        .encryption_algorithms_server_to_client = &transport.encryption_algorithms,
        .mac_algorithms_client_to_server = &transport.mac_algorithms,
        .mac_algorithms_server_to_client = &transport.mac_algorithms,
        .compression_algorithms_client_to_server = &transport.compression_algorithms,
        .compression_algorithms_server_to_client = &transport.compression_algorithms,
        .languages_client_to_server = empty,
        .languages_server_to_client = empty,
        .first_kex_packet_follows = false,
        .reserved = 0,
    };
    var isbuf: [2048]u8 = undefined;
    var isw: std.Io.Writer = .fixed(&isbuf);
    try local_kex.encode(&isw);
    const i_s = try gpa.dupe(u8, isw.buffered());
    defer gpa.free(i_s);

    var none_r: transport.CipherState = .none;
    var none_w: transport.CipherState = .none;
    // Explicit plaintext-phase packet counts (the `.none` cipher state does
    // not track sequence numbers) — these seed the installed ciphers below.
    var sent: u32 = 0;
    var rcvd: u32 = 0;

    try transport.writePacket(t.writer, &none_w, i_s); // our KEXINIT
    sent += 1;

    const cpkt = try transport.readPacket(t.reader, &none_r, scratch); // client KEXINIT
    rcvd += 1;
    if (msgType(cpkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXINIT)) return error.ProtocolError;
    const i_c = try gpa.dupe(u8, cpkt.payload);
    defer gpa.free(i_c);

    var creader: std.Io.Reader = .fixed(cpkt.payload[1..]);
    var client_kex = try transport.KexInit.decode(gpa, &creader);
    defer client_kex.deinit(gpa);

    // 3. Negotiate (client-preference order per RFC 4253 §7.1).
    const kex_name = pickFirst(client_kex.kex_algorithms, &transport.kex_algorithms) orelse
        return error.UnsupportedAlgorithm;
    var host_key: ?HostKey = null;
    outer: for (client_kex.server_host_key_algorithms) |name| {
        for (config.host_keys) |hk| {
            if (std.mem.eql(u8, name, hk.algorithmName())) {
                host_key = hk;
                break :outer;
            }
        }
    }
    const hk = host_key orelse return error.UnsupportedAlgorithm;
    const cipher_c2s = pickFirst(client_kex.encryption_algorithms_client_to_server, &transport.encryption_algorithms) orelse
        return error.UnsupportedAlgorithm;
    const cipher_s2c = pickFirst(client_kex.encryption_algorithms_server_to_client, &transport.encryption_algorithms) orelse
        return error.UnsupportedAlgorithm;
    // MAC only matters for a non-AEAD cipher (mirrors the client's policy).
    if (!std.mem.eql(u8, cipher_c2s, "chacha20-poly1305@openssh.com")) {
        _ = pickFirst(client_kex.mac_algorithms_client_to_server, &transport.mac_algorithms) orelse
            return error.UnsupportedAlgorithm;
    }
    if (!std.mem.eql(u8, cipher_s2c, "chacha20-poly1305@openssh.com")) {
        _ = pickFirst(client_kex.mac_algorithms_server_to_client, &transport.mac_algorithms) orelse
            return error.UnsupportedAlgorithm;
    }

    // RFC 4253 §7: a wrongly-guessed first KEX packet must be discarded
    // (OpenSSH never guesses; this is spec completeness).
    if (client_kex.first_kex_packet_follows) {
        const guess_ok = client_kex.kex_algorithms.len > 0 and
            std.mem.eql(u8, client_kex.kex_algorithms[0], kex_name) and
            client_kex.server_host_key_algorithms.len > 0 and
            std.mem.eql(u8, client_kex.server_host_key_algorithms[0], hk.algorithmName());
        if (!guess_ok) {
            _ = try transport.readPacket(t.reader, &none_r, scratch);
            rcvd += 1;
        }
    }

    // 4. Responder-side KEX (reads KEX_ECDH_INIT, writes KEX_ECDH_REPLY).
    var kex_result = try curve25519KexServer(t.reader, t.writer, &none_w, i_c, i_s, v_c, v_s, hk, gpa);
    defer std.crypto.secureZero(u8, &kex_result.shared_secret);
    rcvd += 1;
    sent += 1;

    if (t.session_id == null) t.session_id = kex_result.exchange_hash;
    const sid = t.session_id.?;

    // 5. NEWKEYS both ways (still plaintext).
    try transport.writePacket(t.writer, &none_w, &[_]u8{@intFromEnum(messages.MessageType.SSH_MSG_NEWKEYS)});
    sent += 1;
    const nk = try transport.readPacket(t.reader, &none_r, scratch);
    rcvd += 1;
    if (msgType(nk) != @intFromEnum(messages.MessageType.SSH_MSG_NEWKEYS)) return error.ProtocolError;

    // 6. Install ciphers — SERVER direction mapping: we ENCRYPT with the
    // server-to-client keys ('B'/'D'/'F') and DECRYPT with the
    // client-to-server keys ('A'/'C'/'E'), the exact swap of
    // `clientHandshake`'s assignment.
    t.write_cipher = try buildCipher(cipher_s2c, .s2c, kex_result, sid, sent);
    t.read_cipher = try buildCipher(cipher_c2s, .c2s, kex_result, sid, rcvd);

    // 7. SSH_MSG_SERVICE_REQUEST "ssh-userauth" → SSH_MSG_SERVICE_ACCEPT
    // (responder mirror of `transport.Transport.requestService`).
    while (true) {
        const pkt = try t.recvPacket(scratch);
        switch (@as(messages.MessageType, @enumFromInt(msgType(pkt)))) {
            .SSH_MSG_IGNORE, .SSH_MSG_DEBUG => continue,
            .SSH_MSG_SERVICE_REQUEST => {
                var cur = WireCursor{ .b = pkt.payload[1..] };
                const service = try cur.string();
                if (!std.mem.eql(u8, service, "ssh-userauth")) return error.ProtocolError;
                var abuf: [64]u8 = undefined;
                var aw: std.Io.Writer = .fixed(&abuf);
                try aw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_SERVICE_ACCEPT));
                try messages.writeString(&aw, service);
                try t.sendPacket(aw.buffered());
                return;
            },
            else => return error.ProtocolError,
        }
    }
}

/// Convenience: `transport.Transport.init` followed by `serverHandshake` —
/// the responder-side mirror of `transport.connect`.
pub fn accept(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    gpa: std.mem.Allocator,
    config: ServerConfig,
) transport.TransportError!transport.Transport {
    var t = transport.Transport.init(reader, writer);
    try serverHandshake(&t, gpa, config);
    return t;
}

// ── tests ──────────────────────────────────────────────────────────────────

test "HostKey type compiles" {
    const t = std.testing;
    var seed: [32]u8 = [_]u8{0} ** 32;
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    const hk: HostKey = .{ .ed25519 = kp };
    try t.expectEqualStrings("ssh-ed25519", hk.algorithmName());

    const rsa_hk: HostKey = .{ .rsa = .{
        .secret_key = undefined,
        .public_key = undefined,
        .hash = .sha2_256,
    } };
    try t.expectEqualStrings("rsa-sha2-256", rsa_hk.algorithmName());
    const rsa_hk512: HostKey = .{ .rsa = .{
        .secret_key = undefined,
        .public_key = undefined,
        .hash = .sha2_512,
    } };
    try t.expectEqualStrings("rsa-sha2-512", rsa_hk512.algorithmName());

    _ = &seed;
}

test "ServerConfig is constructible with a default server_software" {
    const t = std.testing;
    var seed: [32]u8 = [_]u8{1} ** 32;
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    const keys = [_]HostKey{.{ .ed25519 = kp }};
    const cfg = ServerConfig{ .host_keys = &keys };
    try t.expectEqualStrings(transport.software_version, cfg.server_software);
    try t.expectEqual(@as(usize, 1), cfg.host_keys.len);
    _ = &seed;
}

// Throwaway, purpose-generated test fixtures (ssh-keygen -N "" -C
// "zig-libs-ssh-test-fixture"); never used outside this test file.
const fixture_ed25519_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    \\QyNTUxOQAAACAbXh+0xX5CqQGbodRtCemLNds0YSHGSbliNLhNrJtVowAAAKBLNuLfSzbi
    \\3wAAAAtzc2gtZWQyNTUxOQAAACAbXh+0xX5CqQGbodRtCemLNds0YSHGSbliNLhNrJtVow
    \\AAAEAT1J99c1Kuebn+/em6EEfb1f4ugX6800dEkxIiGL7b1hteH7TFfkKpAZuh1G0J6Ys1
    \\2zRhIcZJuWI0uE2sm1WjAAAAGXppZy1saWJzLXNzaC10ZXN0LWZpeHR1cmUBAgME
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
const fixture_ed25519_pub_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIBteH7TFfkKpAZuh1G0J6Ys12zRhIcZJuWI0uE2sm1Wj";

const fixture_rsa_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
    \\NhAAAAAwEAAQAAAQEAsTT0LyOIfVddUOIh7ipZkRnSCOkePGSxxPc/2vu1OlM+JT+igdyT
    \\b9h42yQTw9vG2P2uStEmiaasYGAjENl+eK1bOzTWMUwlBUi4zVXN9CxxWUZmLl59u9Y9uz
    \\uM0wDMdEWSQ5iLSOfcIHMnJwy5tKBZj71ejcNFkfAlcN8kT9jR1eqlMBfhH8OJLRLUbLXr
    \\Jlnjyi9Ao6Ki3HoP+65KZKCma0powh1Vo0crCNc0cYdG4vnoBUYOvg7iL3GtW99Yg8pg7z
    \\h7GAq2+gKPnCEoZMjOu+NZ4yQw8dW25SeahszGNxLRteoek6d9lJHvbtrdzMLE/ci7/Pe0
    \\cveoowVLwwAAA9DfoGmR36BpkQAAAAdzc2gtcnNhAAABAQCxNPQvI4h9V11Q4iHuKlmRGd
    \\II6R48ZLHE9z/a+7U6Uz4lP6KB3JNv2HjbJBPD28bY/a5K0SaJpqxgYCMQ2X54rVs7NNYx
    \\TCUFSLjNVc30LHFZRmYuXn271j27O4zTAMx0RZJDmItI59wgcycnDLm0oFmPvV6Nw0WR8C
    \\Vw3yRP2NHV6qUwF+Efw4ktEtRstesmWePKL0CjoqLceg/7rkpkoKZrSmjCHVWjRysI1zRx
    \\h0bi+egFRg6+DuIvca1b31iDymDvOHsYCrb6Ao+cIShkyM6741njJDDx1bblJ5qGzMY3Et
    \\G16h6Tp32Uke9u2t3MwsT9yLv897Ry96ijBUvDAAAAAwEAAQAAAQAtWwZcwlV+70t9FkPk
    \\94XxM5CkozYP8x3k8fuwCti50vCHDCCF6HT8HYXhYPyGFsxwYY2orJuWg8h+6lxPRbuvG3
    \\/MSZvBBmI7Vf+m3p1WL8HbPb+NgrXfy9gFAhrrLrslz2C+WF7eDCo1TAPrZMBrUNdbiPaY
    \\hjBaSALtPs/Gd6Tl34dr7sf0egcJhEInYtYV5HwOMvVlyZ4oQWejvV9mr9dPd/46YZtAno
    \\JktXCjtkqAoWClgp1QUb5vbb+HMtuzHVFUtzyQ3iTFA4Nw0uMuumNyNgHIPIEoNZrK2ugU
    \\ylXZOX8PSJuD4kXvd6Pa9cyuQKsqGuS3gxy0dx3Sa9IxAAAAgH/wPnFcrOrAPoLklNtk/b
    \\mudndObm73psJlWpiqv5R6Ydxa3Lnk4pcijFx/QoddlEHPKXEsCXXSwDyQSkPzY6/Zm/Gh
    \\lQNpJpXfvF237eJ4N3/x4FdvP30XV2LM15P16a9rTGDU9/lfspx3DWskKDvMN8XjSoEleE
    \\2D6w732aSfAAAAgQDnZIzPFadc1axuEv7Duj2KsVEGoYHK6zcJuhMtlelqi+nlgx9roPSS
    \\oXxc5wQEG/tPh7pTfETpp4OTAcih2e1bHy1RjLjuDa6ClXkYt3ex7IfQ9FCly/uHNKPBJi
    \\EKR8mqwC+FuAs0U+7LnNLRI7FKreiwHGZ7KnjBCPZyYJoF/QAAAIEAxA0+QV7uVgb4MWvk
    \\VORUlLPAZu5kk3gnKl3mE7yIHYiSJ+8bfM2mT2lNALDcO9LsO94S2AoZbc+nEvfgEGhMuO
    \\Yb4M407p9NvfmEe2+hUBuPjlRTLzAPw+MAhvg7K+uV0tsbNiAAQ9Piquu6D9D7fWMU6LtR
    \\+MAP9t6jMgYUZL8AAAAZemlnLWxpYnMtc3NoLXRlc3QtZml4dHVyZQEC
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
const fixture_rsa_pub_b64 =
    "AAAAB3NzaC1yc2EAAAADAQABAAABAQCxNPQvI4h9V11Q4iHuKlmRGdII6R48ZLHE9z/a+7U6" ++
    "Uz4lP6KB3JNv2HjbJBPD28bY/a5K0SaJpqxgYCMQ2X54rVs7NNYxTCUFSLjNVc30LHFZRmYu" ++
    "Xn271j27O4zTAMx0RZJDmItI59wgcycnDLm0oFmPvV6Nw0WR8CVw3yRP2NHV6qUwF+Efw4kt" ++
    "EtRstesmWePKL0CjoqLceg/7rkpkoKZrSmjCHVWjRysI1zRxh0bi+egFRg6+DuIvca1b31iD" ++
    "ymDvOHsYCrb6Ao+cIShkyM6741njJDDx1bblJ5qGzMY3EtG16h6Tp32Uke9u2t3MwsT9yLv8" ++
    "97Ry96ijBUvD";

fn decodeFixturePub(b64: []const u8, buf: []u8) ![]u8 {
    const dec = std.base64.standard.Decoder;
    const n = try dec.calcSizeForSlice(b64);
    try dec.decode(buf[0..n], b64);
    return buf[0..n];
}

test "HostKey.fromOpenSSH: ed25519 fixture parses; K_S matches ssh-keygen's .pub blob" {
    const t = std.testing;
    const hk = try HostKey.fromOpenSSH(fixture_ed25519_key, null);
    try t.expectEqualStrings("ssh-ed25519", hk.algorithmName());

    const blob = try hk.publicBlob(t.allocator);
    defer t.allocator.free(blob);
    var pubbuf: [128]u8 = undefined;
    const expected = try decodeFixturePub(fixture_ed25519_pub_b64, &pubbuf);
    try t.expectEqualSlices(u8, expected, blob);

    // Sign + verify round-trip through the wire blob.
    const h = [_]u8{0x5A} ** 32;
    const sig_blob = try hk.sign(t.allocator, &h);
    defer t.allocator.free(sig_blob);
    var cur = WireCursor{ .b = sig_blob };
    try t.expectEqualStrings("ssh-ed25519", try cur.string());
    const sig_bytes = try cur.string();
    try t.expectEqual(@as(usize, 64), sig_bytes.len);
    var sig_arr: [64]u8 = undefined;
    @memcpy(&sig_arr, sig_bytes);
    try Ed25519.Signature.fromBytes(sig_arr).verify(&h, hk.ed25519.public_key);
}

test "HostKey.fromOpenSSH: rsa fixture parses; K_S matches .pub; sha2-256 and sha2-512 signatures verify" {
    const t = std.testing;
    var hk = try HostKey.fromOpenSSH(fixture_rsa_key, null);
    try t.expectEqualStrings("rsa-sha2-256", hk.algorithmName());

    const blob = try hk.publicBlob(t.allocator);
    defer t.allocator.free(blob);
    var pubbuf: [1024]u8 = undefined;
    const expected = try decodeFixturePub(fixture_rsa_pub_b64, &pubbuf);
    try t.expectEqualSlices(u8, expected, blob);

    const h = [_]u8{0xA5} ** 32;
    inline for (.{ HostKey.RsaHash.sha2_256, HostKey.RsaHash.sha2_512 }) |hash| {
        hk.rsa.hash = hash;
        const sig_blob = try hk.sign(t.allocator, &h);
        defer t.allocator.free(sig_blob);
        var cur = WireCursor{ .b = sig_blob };
        const algo = try cur.string();
        const sig_bytes = try cur.string();
        switch (hash) {
            .sha2_256 => {
                try t.expectEqualStrings("rsa-sha2-256", algo);
                try rsa.verifyPkcs1v15(hk.rsa.public_key, Sha256, &h, sig_bytes);
            },
            .sha2_512 => {
                try t.expectEqualStrings("rsa-sha2-512", algo);
                try rsa.verifyPkcs1v15(hk.rsa.public_key, Sha512, &h, sig_bytes);
            },
        }
    }
}

test "HostKey.sign/publicBlob: ecdsa-p256 mpint(r)||mpint(s) wire shape verifies" {
    const t = std.testing;
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i + 7);
    const kp = try EcdsaP256.KeyPair.generateDeterministic(seed);
    const hk: HostKey = .{ .ecdsa_p256 = kp };

    const blob = try hk.publicBlob(t.allocator);
    defer t.allocator.free(blob);
    var kcur = WireCursor{ .b = blob };
    try t.expectEqualStrings("ecdsa-sha2-nistp256", try kcur.string());
    try t.expectEqualStrings("nistp256", try kcur.string());
    const q = try kcur.string();
    const pk = try EcdsaP256.PublicKey.fromSec1(q);

    const h = [_]u8{0x3C} ** 32;
    const sig_blob = try hk.sign(t.allocator, &h);
    defer t.allocator.free(sig_blob);
    var scur = WireCursor{ .b = sig_blob };
    try t.expectEqualStrings("ecdsa-sha2-nistp256", try scur.string());
    const inner = try scur.string();
    var icur = WireCursor{ .b = inner };
    const r_m = stripLeadingZeros(try icur.string());
    const s_m = stripLeadingZeros(try icur.string());
    try t.expect(r_m.len <= 32 and s_m.len <= 32);
    var rs = [_]u8{0} ** 64;
    @memcpy(rs[32 - r_m.len .. 32], r_m);
    @memcpy(rs[64 - s_m.len .. 64], s_m);
    try EcdsaP256.Signature.fromBytes(rs).verify(&h, pk);
}

test "parseEd25519OpenSSH rejects an encrypted container with a clear error" {
    const t = std.testing;
    // Synthesize a structurally-valid container header naming aes256-ctr.
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("openssh-key-v1\x00");
    try messages.writeString(&w, "aes256-ctr");
    try messages.writeString(&w, "bcrypt");
    try messages.writeString(&w, "\x00\x00\x00\x04saltsalt"); // opaque here
    try w.writeAll(&[_]u8{ 0, 0, 0, 1 }); // nkeys
    try messages.writeString(&w, ""); // public blob (unchecked before cipher)
    try messages.writeString(&w, ""); // private section
    try t.expectError(error.UnsupportedCipher, parseEd25519OpenSSH(w.buffered(), "pw"));
}

test "HostKey.fromOpenSSH rejects a non-rsa/ed25519 key type" {
    const t = std.testing;
    var bin: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&bin);
    try w.writeAll("openssh-key-v1\x00");
    try messages.writeString(&w, "none");
    try messages.writeString(&w, "none");
    try messages.writeString(&w, "");
    try w.writeAll(&[_]u8{ 0, 0, 0, 1 });
    var pb: [64]u8 = undefined;
    var pw: std.Io.Writer = .fixed(&pb);
    try messages.writeString(&pw, "ecdsa-sha2-nistp256");
    try messages.writeString(&w, pw.buffered());
    try messages.writeString(&w, "");
    // Wrap as PEM.
    var b64buf: [512]u8 = undefined;
    const enc = std.base64.standard.Encoder;
    const body = enc.encode(&b64buf, w.buffered());
    const text = try std.fmt.allocPrint(
        t.allocator,
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{s}\n-----END OPENSSH PRIVATE KEY-----\n",
        .{body},
    );
    defer t.allocator.free(text);
    try t.expectError(error.UnsupportedKeyType, HostKey.fromOpenSSH(text, null));
}

// ── self-consistency: our client ↔ our server over loopback TCP ─────────────

fn acceptAnyHostKey(key_type: []const u8, key_blob: []const u8) bool {
    _ = key_type;
    _ = key_blob;
    return true;
}

/// Bind a listener on an ephemeral loopback port (retrying on collisions).
fn listenLoopback(io: std.Io, port_out: *u16) !std.Io.net.Server {
    var tries: usize = 0;
    while (tries < 32) : (tries += 1) {
        var pb: [2]u8 = undefined;
        fillRandom(&pb);
        const port: u16 = 20000 + (std.mem.readInt(u16, &pb, .big) % 20000);
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        const server = addr.listen(io, .{ .reuse_address = true }) catch continue;
        port_out.* = port;
        return server;
    }
    return error.SkipZigTest;
}

const SelfTestClient = struct {
    port: u16,
    err: ?anyerror = null,
    session_id: ?[32]u8 = null,

    fn run(self: *SelfTestClient) void {
        self.runInner() catch |e| {
            self.err = e;
        };
    }

    fn runInner(self: *SelfTestClient) !void {
        const gpa = std.testing.allocator;
        var threaded = std.Io.Threaded.init(gpa, .{});
        defer threaded.deinit();
        const io = threaded.io();

        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", self.port);
        var stream: std.Io.net.Stream = blk: {
            var tries: usize = 0;
            while (tries < 60) : (tries += 1) {
                if (addr.connect(io, .{ .mode = .stream })) |s| break :blk s else |_| {}
                var ts = std.os.linux.timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
                _ = std.os.linux.nanosleep(&ts, null);
            }
            return error.ConnectionRefused;
        };
        defer stream.close(io);

        var rbuf: [32 * 1024]u8 = undefined;
        var wbuf: [32 * 1024]u8 = undefined;
        var sr = stream.reader(io, &rbuf);
        var sw = stream.writer(io, &wbuf);
        var t = try transport.connect(&sr.interface, &sw.interface, gpa, acceptAnyHostKey);

        var pbuf: [8192]u8 = undefined;
        try t.requestService("ssh-userauth", &pbuf);

        // Encrypted c2s probe: SSH_MSG_IGNORE with a marker payload.
        var mb: [64]u8 = undefined;
        var mw: std.Io.Writer = .fixed(&mb);
        try mw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_IGNORE));
        try messages.writeString(&mw, "probe-c2s");
        try t.sendPacket(mw.buffered());

        // Encrypted s2c probe back from the server.
        const pkt = try t.recvPacket(&pbuf);
        if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_IGNORE)) return error.ProtocolError;
        if (std.mem.indexOf(u8, pkt.payload, "probe-s2c") == null) return error.ProtocolError;

        self.session_id = t.session_id;
    }
};

fn selfConsistency(host_key: HostKey) !void {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var port: u16 = 0;
    var listener = try listenLoopback(io, &port);
    defer listener.deinit(io);

    var client = SelfTestClient{ .port = port };
    const th = try std.Thread.spawn(.{}, SelfTestClient.run, .{&client});
    var joined = false;
    defer if (!joined) th.join(); // runs after stream.close -> client unblocks

    var stream = try listener.accept(io);
    defer stream.close(io);
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const keys = [_]HostKey{host_key};
    var t = try accept(&sr.interface, &sw.interface, gpa, .{ .host_keys = &keys });

    // The client's encrypted IGNORE probe must decrypt on our side...
    var pbuf: [8192]u8 = undefined;
    const pkt = try t.recvPacket(&pbuf);
    try std.testing.expectEqual(@intFromEnum(messages.MessageType.SSH_MSG_IGNORE), msgType(pkt));
    try std.testing.expect(std.mem.indexOf(u8, pkt.payload, "probe-c2s") != null);

    // ...and ours on the client's.
    var mb: [64]u8 = undefined;
    var mw: std.Io.Writer = .fixed(&mb);
    try mw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_IGNORE));
    try messages.writeString(&mw, "probe-s2c");
    try t.sendPacket(mw.buffered());

    th.join();
    joined = true;
    if (client.err) |e| return e;

    // Both sides must have derived the same session id (= exchange hash H).
    try std.testing.expect(t.session_id != null and client.session_id != null);
    try std.testing.expectEqualSlices(u8, &t.session_id.?, &client.session_id.?);
}

test "self-consistency: our client ↔ our server (ed25519 host key)" {
    const hk = try HostKey.fromOpenSSH(fixture_ed25519_key, null);
    try selfConsistency(hk);
}

test "self-consistency: our client ↔ our server (rsa host key)" {
    const hk = try HostKey.fromOpenSSH(fixture_rsa_key, null);
    try selfConsistency(hk);
}

// ── live interop: real OpenSSH `ssh` client → our server (gated) ────────────

/// Spawn the system OpenSSH client against our in-process server on a
/// loopback port and prove KEX + KDF + cipher + MAC interop: the handshake
/// completes (which includes decrypting the client's encrypted
/// SSH_MSG_SERVICE_REQUEST "ssh-userauth") and the client's subsequent
/// SSH_MSG_USERAUTH_REQUEST decrypts too. The client then fails auth (we
/// never implement userauth in part 1) — that is expected and not asserted.
fn liveOpensshClient(keygen_type: []const u8, hostkey_algo: []const u8, cipher_name: []const u8) !void {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cwd = std.Io.Dir.cwd();

    // Gate on a runnable OpenSSH client.
    cwd.access(io, "/usr/bin/ssh", .{}) catch return error.SkipZigTest;

    // Throwaway temp dir (same pattern as transport.zig's sshd interop test).
    var rnd: [8]u8 = undefined;
    fillRandom(&rnd);
    const hex = std.fmt.bytesToHex(&rnd, .lower);
    const dir_path = try std.fmt.allocPrint(gpa, "/tmp/zig_ssh_srv_test_{s}", .{&hex});
    defer gpa.free(dir_path);
    var work = cwd.createDirPathOpen(io, dir_path, .{}) catch return error.SkipZigTest;
    defer {
        work.close(io);
        cwd.deleteTree(io, dir_path) catch {};
    }

    // Generate an ephemeral unencrypted host key with the real ssh-keygen.
    const hk_path = try std.fmt.allocPrint(gpa, "{s}/hk", .{dir_path});
    defer gpa.free(hk_path);
    {
        var child = std.process.spawn(io, .{
            .argv = &.{ "ssh-keygen", "-q", "-t", keygen_type, "-N", "", "-C", "zig-ssh-live-test", "-f", hk_path },
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch return error.SkipZigTest;
        const term = child.wait(io) catch return error.SkipZigTest;
        switch (term) {
            .exited => |c| if (c != 0) return error.SkipZigTest,
            else => return error.SkipZigTest,
        }
    }

    const key_text = try cwd.readFileAlloc(io, hk_path, gpa, .limited(16384));
    defer gpa.free(key_text);
    var hk = try HostKey.fromOpenSSH(key_text, null);
    if (std.mem.eql(u8, hostkey_algo, "rsa-sha2-512")) hk.rsa.hash = .sha2_512;
    try std.testing.expectEqualStrings(hostkey_algo, hk.algorithmName());

    var port: u16 = 0;
    var listener = try listenLoopback(io, &port);
    defer listener.deinit(io);

    // Spawn the real ssh client. PreferredAuthentications=none + BatchMode
    // make it send exactly one "none" userauth attempt after the handshake.
    const port_str = try std.fmt.allocPrint(gpa, "{d}", .{port});
    defer gpa.free(port_str);
    const ciphers_opt = try std.fmt.allocPrint(gpa, "Ciphers={s}", .{cipher_name});
    defer gpa.free(ciphers_opt);
    const hka_opt = try std.fmt.allocPrint(gpa, "HostKeyAlgorithms={s}", .{hostkey_algo});
    defer gpa.free(hka_opt);
    var ssh_child = std.process.spawn(io, .{
        .argv = &.{
            "/usr/bin/ssh",                  "-p", port_str,                         "-F",
            "/dev/null",                     "-o", "StrictHostKeyChecking=no",       "-o",
            "UserKnownHostsFile=/dev/null",  "-o", "GlobalKnownHostsFile=/dev/null", "-o",
            "PreferredAuthentications=none", "-o", "BatchMode=yes",                  "-o",
            "MACs=hmac-sha2-256",            "-o", "ConnectTimeout=10",              "-o",
            ciphers_opt,                     "-o", hka_opt,                          "test@127.0.0.1",
            "true",
        },
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return error.SkipZigTest;
    defer ssh_child.kill(io);

    var stream = try listener.accept(io);
    defer stream.close(io);
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    // serverHandshake ends by decrypting the client's SERVICE_REQUEST
    // "ssh-userauth" and answering SERVICE_ACCEPT — the KEX/KDF/cipher/MAC
    // proof against the real OpenSSH client.
    const keys = [_]HostKey{hk};
    var t = try accept(&sr.interface, &sw.interface, gpa, .{ .host_keys = &keys });

    // Confirm the cipher we forced is what got installed, both directions.
    inline for (.{ t.read_cipher, t.write_cipher }) |c| {
        switch (c) {
            .chacha20_poly1305 => try std.testing.expectEqualStrings("chacha20-poly1305@openssh.com", cipher_name),
            .aes256_ctr_hmac_sha256 => try std.testing.expectEqualStrings("aes256-ctr", cipher_name),
            .none => return error.ProtocolError,
        }
    }

    // The client's next encrypted packet must decrypt to its userauth
    // request (SSH_MSG_USERAUTH_REQUEST = 50, RFC 4252 — not in this part's
    // MessageType enum, compared numerically).
    var pbuf: [8192]u8 = undefined;
    while (true) {
        const pkt = try t.recvPacket(&pbuf);
        switch (msgType(pkt)) {
            @intFromEnum(messages.MessageType.SSH_MSG_IGNORE),
            @intFromEnum(messages.MessageType.SSH_MSG_DEBUG),
            => continue,
            50 => break, // SSH_MSG_USERAUTH_REQUEST decrypted successfully
            else => return error.ProtocolError,
        }
    }
}

test "live interop: OpenSSH ssh client → our server — ed25519 + chacha20-poly1305" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "chacha20-poly1305@openssh.com");
}

test "live interop: OpenSSH ssh client → our server — ed25519 + aes256-ctr" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "aes256-ctr");
}

test "live interop: OpenSSH ssh client → our server — rsa-sha2-256 + chacha20-poly1305" {
    try liveOpensshClient("rsa", "rsa-sha2-256", "chacha20-poly1305@openssh.com");
}

test "live interop: OpenSSH ssh client → our server — rsa-sha2-512 + aes256-ctr" {
    try liveOpensshClient("rsa", "rsa-sha2-512", "aes256-ctr");
}
