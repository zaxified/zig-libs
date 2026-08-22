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
//! SSH_MSG_CHANNEL_*) are out of scope in THIS FILE — they are implemented,
//! for both roles, in the sibling `userauth.zig` (`serveUserauth`) and
//! `connection.zig` (`serveSession`), which `root.zig` re-exports as real
//! (not placeholder) entry points: `authenticate`/`openSession`/`exec`. See
//! `root.zig`'s module doc comment and the full-stack loopback self-interop
//! test at the bottom of `connection.zig`.
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
const MLKem768 = std.crypto.kem.ml_kem.MLKem768;

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
/// Single shared definition in `messages.zig` (was a local mirror of
/// `transport.zig`'s private `SliceReader`; both are now the same type).
const WireCursor = messages.Cursor;

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

    // Legacy path: `k_enc_len == 0` makes `buildCipher` mpint-encode the raw
    // shared secret (byte-identical to the pre-widening result).
    var res = transport.KexResult{ .shared_secret = shared, .hash_len = 32 };
    @memcpy(res.exchange_hash[0..32], &h);
    return res;
}

/// True for either negotiated curve25519 KEX name. Mirrors transport.zig's
/// private `isCurve25519Kex`.
fn isCurve25519Kex(name: []const u8) bool {
    return std.mem.eql(u8, name, "curve25519-sha256") or
        std.mem.eql(u8, name, "curve25519-sha256@libssh.org");
}

/// Responder side of classic MODP Diffie-Hellman key exchange (RFC 4253 §8.1,
/// RFC 3526 groups `diffie-hellman-group14-sha256` /
/// `diffie-hellman-group16-sha512`), the server-role mirror of
/// `transport.dhGroupKex`: receive SSH_MSG_KEXDH_INIT (`e = g^x mod p`),
/// generate our own `y`/`f = g^y mod p`, compute `K = e^y mod p`, hash
/// `H = HASH(V_C‖V_S‖I_C‖I_S‖K_S‖e‖f‖K)` (SHA-256 group14 / SHA-512 group16),
/// sign `H`, and send SSH_MSG_KEXDH_REPLY (`K_S`, `f`, signature). The RFC 3526
/// primes + digest choice + modexp are reused from `transport.zig` (`DhGroup`,
/// `dhPowModPrime`) — not re-embedded here.
pub fn dhGroupKexServer(
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    cipher: *transport.CipherState,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: HostKey,
    gpa: std.mem.Allocator,
    kex_name: []const u8,
) transport.TransportError!transport.KexResult {
    const group = transport.DhGroup.forName(kex_name) orelse return error.UnsupportedAlgorithm;
    const g = [_]u8{2};

    // SSH_MSG_KEXDH_INIT: byte || mpint e.
    var buf: [16384]u8 = undefined;
    const pkt = try transport.readPacket(r, cipher, &buf);
    if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXDH_INIT)) return error.KexFailed;
    var cur = WireCursor{ .b = pkt.payload[1..] };
    const e = stripLeadingZeros(try cur.string());
    // 1 < e < p-1 (reject degenerate peer values — RFC 4253 §8. `e == p`
    // or `e == p-1` would force a known K on these safe-prime groups).
    if (group.rejectsDegeneratePeerValue(e)) return error.KexFailed;

    // Secret exponent y (full prime-length random; constant-time modexp).
    var y: [transport.dh_max_prime_len]u8 = undefined;
    const yb = y[0..group.prime.len];
    defer std.crypto.secureZero(u8, &y);
    fillRandom(yb);
    yb[0] &= 0x7f;
    yb[yb.len - 1] |= 1;

    // f = g^y mod p, K = e^y mod p.
    var fbuf: [transport.dh_max_prime_len]u8 = undefined;
    const f = try transport.dhPowModPrime(group.prime, &g, yb, &fbuf);
    var kbuf: [transport.dh_max_prime_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &kbuf);
    const k_mag = try transport.dhPowModPrime(group.prime, e, yb, &kbuf);

    const k_s = try host_key.publicBlob(gpa);
    defer gpa.free(k_s);

    var res = transport.KexResult{ .hash_len = if (group.sha512) 64 else 32 };
    if (group.sha512) {
        var sh = Sha512.init(.{});
        transport.hashStringH(Sha512, &sh, client_id);
        transport.hashStringH(Sha512, &sh, server_id);
        transport.hashStringH(Sha512, &sh, client_kexinit_payload);
        transport.hashStringH(Sha512, &sh, server_kexinit_payload);
        transport.hashStringH(Sha512, &sh, k_s);
        transport.hashMpint(Sha512, &sh, e);
        transport.hashMpint(Sha512, &sh, f);
        transport.hashMpint(Sha512, &sh, k_mag);
        sh.final(res.exchange_hash[0..64]);
    } else {
        var sh = Sha256.init(.{});
        transport.hashStringH(Sha256, &sh, client_id);
        transport.hashStringH(Sha256, &sh, server_id);
        transport.hashStringH(Sha256, &sh, client_kexinit_payload);
        transport.hashStringH(Sha256, &sh, server_kexinit_payload);
        transport.hashStringH(Sha256, &sh, k_s);
        transport.hashMpint(Sha256, &sh, e);
        transport.hashMpint(Sha256, &sh, f);
        transport.hashMpint(Sha256, &sh, k_mag);
        sh.final(res.exchange_hash[0..32]);
    }
    {
        var kw: std.Io.Writer = .fixed(&res.k_enc);
        messages.writeMpint(&kw, k_mag) catch return error.KexFailed;
        res.k_enc_len = @intCast(kw.buffered().len);
    }

    const sig = try host_key.sign(gpa, res.hash());
    defer gpa.free(sig);

    // SSH_MSG_KEXDH_REPLY: byte || string K_S || mpint f || string sig.
    var obuf: [8 + transport.dh_max_prime_len + 2048]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&obuf);
    try ow.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_KEXDH_REPLY));
    try messages.writeString(&ow, k_s);
    try messages.writeMpint(&ow, f);
    try messages.writeString(&ow, sig);
    try transport.writePacket(w, cipher, ow.buffered());

    return res;
}

/// Responder side of `mlkem768x25519-sha256` (OpenSSH's post-quantum hybrid),
/// the server-role mirror of `transport.mlkem768x25519Kex`: receive
/// SSH_MSG_KEX_ECDH_INIT with blob `C = ML-KEM_encaps_key(1184) ‖ X25519_pub`,
/// ML-KEM-`encaps` against the client's key + generate our X25519 ephemeral,
/// compute `K = SHA256(K_MLKEM ‖ K_X25519)` (string-encoded), hash
/// `H = SHA256(V_C‖V_S‖I_C‖I_S‖K_S‖C‖S‖string(K))`, sign it, and send the
/// reply with blob `S = ML-KEM_ciphertext(1088) ‖ X25519_server_pub`.
pub fn mlkem768x25519KexServer(
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
    // SSH_MSG_KEX_ECDH_INIT: byte || string C.
    var buf: [16384]u8 = undefined;
    const pkt = try transport.readPacket(r, cipher, &buf);
    if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXDH_INIT)) return error.KexFailed;
    var cur = WireCursor{ .b = pkt.payload[1..] };
    const cinit = try cur.string();
    if (cinit.len != transport.mlkem_cinit_len) return error.KexFailed;

    // ML-KEM encapsulate against the client's encapsulation key.
    var kem_pk_bytes: [transport.mlkem_pk_len]u8 = undefined;
    @memcpy(&kem_pk_bytes, cinit[0..transport.mlkem_pk_len]);
    const kem_pk = MLKem768.PublicKey.fromBytes(&kem_pk_bytes) catch return error.KexFailed;
    var kem_seed: [MLKem768.encaps_seed_length]u8 = undefined;
    fillRandom(&kem_seed);
    defer std.crypto.secureZero(u8, &kem_seed);
    const enc = kem_pk.encapsDeterministic(&kem_seed);
    var kem_shared = enc.shared_secret;
    defer std.crypto.secureZero(u8, &kem_shared);

    // Our X25519 ephemeral + shared with the client's X25519 public.
    var x_client: [32]u8 = undefined;
    @memcpy(&x_client, cinit[transport.mlkem_pk_len..transport.mlkem_cinit_len]);
    var x_seed: [32]u8 = undefined;
    fillRandom(&x_seed);
    defer std.crypto.secureZero(u8, &x_seed);
    const x_kp = X25519.KeyPair.generateDeterministic(x_seed) catch return error.KexFailed;
    var x_shared = X25519.scalarmult(x_kp.secret_key, x_client) catch return error.KexFailed;
    defer std.crypto.secureZero(u8, &x_shared);

    // S = ML-KEM_ciphertext(1088) || X25519_server_pub(32).
    var sreply: [transport.mlkem_sreply_len]u8 = undefined;
    @memcpy(sreply[0..transport.mlkem_ct_len], &enc.ciphertext);
    @memcpy(sreply[transport.mlkem_ct_len..transport.mlkem_sreply_len], &x_kp.public_key);

    const k_s = try host_key.publicBlob(gpa);
    defer gpa.free(k_s);

    var res = transport.KexResult{ .hash_len = 32 };
    const k_raw = transport.mlkemSharedK(&res, kem_shared, x_shared);

    // H = SHA256(V_C || V_S || I_C || I_S || K_S || C || S || string(K)).
    {
        var sh = Sha256.init(.{});
        hashString(&sh, client_id);
        hashString(&sh, server_id);
        hashString(&sh, client_kexinit_payload);
        hashString(&sh, server_kexinit_payload);
        hashString(&sh, k_s);
        hashString(&sh, cinit);
        hashString(&sh, &sreply);
        hashString(&sh, &k_raw);
        sh.final(res.exchange_hash[0..32]);
    }

    const sig = try host_key.sign(gpa, res.hash());
    defer gpa.free(sig);

    // SSH_MSG_KEX_ECDH_REPLY: byte || string K_S || string S || string sig.
    var obuf: [16 + transport.mlkem_sreply_len + 2048]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&obuf);
    try ow.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_KEXDH_REPLY));
    try messages.writeString(&ow, k_s);
    try messages.writeString(&ow, &sreply);
    try messages.writeString(&ow, sig);
    try transport.writePacket(w, cipher, ow.buffered());

    return res;
}

// ── key install (mirrors transport.zig's private deriveKeyBytes/buildCipher) ─

/// RFC 4253 §7.2 KDF for one key letter, parameterized on the KEX method's
/// hash `H` (SHA-256 / SHA-512). Mirrors transport.zig's `deriveKeyBytesH`.
fn deriveKeyBytesH(comptime H: type, out: []u8, letter: u8, k_enc: []const u8, h: []const u8, session_id: []const u8) void {
    const dlen = H.digest_length;
    var first: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &first);
    var s = H.init(.{});
    s.update(k_enc);
    s.update(h);
    s.update(&[_]u8{letter});
    s.update(session_id);
    s.final(first[0..dlen]);
    var written: usize = @min(out.len, dlen);
    @memcpy(out[0..written], first[0..written]);
    while (written < out.len) {
        var s2 = H.init(.{});
        s2.update(k_enc);
        s2.update(h);
        s2.update(out[0..written]);
        var block: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &block);
        s2.final(block[0..dlen]);
        const take = @min(dlen, out.len - written);
        @memcpy(out[written .. written + take], block[0..take]);
        written += take;
    }
}

/// Dispatch the KDF on the KEX method's hash width. Mirrors transport.zig's
/// private `deriveKey`.
fn deriveKey(out: []u8, letter: u8, k_enc: []const u8, h: []const u8, session_id: []const u8, hash_len: u8) void {
    if (hash_len == 64) {
        deriveKeyBytesH(Sha512, out, letter, k_enc, h, session_id);
    } else {
        deriveKeyBytesH(Sha256, out, letter, k_enc, h, session_id);
    }
}

const Direction = enum { c2s, s2c };

/// Build the installed `CipherState` for one direction from a negotiated
/// cipher name and the KEX result. Mirrors transport.zig's private
/// `buildCipher`; the direction letters (A/C/E = client-to-server, B/D/F =
/// server-to-client) are fixed by RFC 4253 §7.2 regardless of which role
/// calls this — the *server* assigns `.s2c` to its WRITE cipher and `.c2s`
/// to its READ cipher (the exact swap of the client's assignment).
fn buildCipher(name: []const u8, dir: Direction, kr: transport.KexResult, sid: []const u8, seq: u32) transport.TransportError!transport.CipherState {
    var kmbuf: [4 + 33]u8 = undefined;
    defer std.crypto.secureZero(u8, &kmbuf);
    const k_enc = if (kr.k_enc_len > 0) kr.k_enc[0..kr.k_enc_len] else encodeMpint(&kmbuf, &kr.shared_secret);
    const h = kr.hash();
    const hl = kr.hash_len;
    if (std.mem.eql(u8, name, "chacha20-poly1305@openssh.com")) {
        var km: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &km);
        deriveKey(&km, if (dir == .c2s) 'C' else 'D', k_enc, h, sid, hl);
        return .{ .chacha20_poly1305 = .{
            .key_main = km[0..32].*,
            .key_header = km[32..64].*,
            .sequence_number = seq,
        } };
    } else if (std.mem.eql(u8, name, "aes256-ctr")) {
        var iv: [16]u8 = undefined;
        var ek: [32]u8 = undefined;
        var mk: [32]u8 = undefined;
        deriveKey(&iv, if (dir == .c2s) 'A' else 'B', k_enc, h, sid, hl);
        deriveKey(&ek, if (dir == .c2s) 'C' else 'D', k_enc, h, sid, hl);
        deriveKey(&mk, if (dir == .c2s) 'E' else 'F', k_enc, h, sid, hl);
        return .{ .aes256_ctr_hmac_sha256 = .{
            .enc_key = ek,
            .enc_iv = iv,
            .mac_key = mk,
            .sequence_number = seq,
        } };
    } else if (std.mem.eql(u8, name, "aes256-gcm@openssh.com") or
        std.mem.eql(u8, name, "aes128-gcm@openssh.com"))
    {
        var iv12: [12]u8 = undefined;
        deriveKey(&iv12, if (dir == .c2s) 'A' else 'B', k_enc, h, sid, hl);
        var key: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &key);
        const is256 = std.mem.eql(u8, name, "aes256-gcm@openssh.com");
        deriveKey(key[0..if (is256) @as(usize, 32) else 16], if (dir == .c2s) 'C' else 'D', k_enc, h, sid, hl);
        return .{ .aes_gcm = .{
            .key = key,
            .key_bits = if (is256) .aes256 else .aes128,
            .fixed_iv = iv12[0..4].*,
            .invocation_counter = std.mem.readInt(u64, iv12[4..12], .big),
            .sequence_number = seq,
        } };
    }
    return error.UnsupportedAlgorithm;
}

/// First name on `preferred` that `available` also lists (RFC 4253 §7.1 —
/// the *client's* list is the preference order, so the server passes the
/// client's list first). Mirrors transport.zig's private `pickFirst`, with
/// one deliberate difference: this always returns the matching entry FROM
/// `available`, never from `preferred`.
///
/// `preferred` is always `client_kex`'s freshly-`decode`d, `gpa`-owned
/// name-list here (`serverHandshake` frees it via `client_kex.deinit(gpa)`
/// before returning), while `available` is always one of this module's own
/// `pub const` static arrays (or, for the host-key case, a
/// `HostKey.algorithmName()` literal). Returning from `preferred` would hand
/// back a pointer into memory `serverHandshake` frees before the caller ever
/// sees it — exactly what `NegotiatedAlgorithms` on `Transport` cannot
/// tolerate, since it must stay valid for the connection's lifetime.
/// Returning from `available` instead costs nothing (the two strings are
/// byte-identical by construction — `std.mem.eql` just confirmed it) and
/// makes every negotiated name here `'static`-equivalent for free.
fn pickFirst(preferred: []const []const u8, available: []const []const u8) ?[]const u8 {
    for (preferred) |p| {
        for (available) |a| {
            if (std.mem.eql(u8, p, a)) return a;
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
/// After this returns, `t` is an encrypted transport ready for userauth —
/// out of scope in THIS FILE, but implemented server-side by
/// `userauth.serveUserauth` (real, not a placeholder; see `root.zig`'s
/// module doc comment).
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
    // MAC only matters for a non-AEAD cipher (mirrors the client's policy),
    // and the name (previously discarded to `_`) is kept for diagnostics.
    const mac_c2s: ?[]const u8 = if (transport.isAeadCipher(cipher_c2s))
        null
    else
        pickFirst(client_kex.mac_algorithms_client_to_server, &transport.mac_algorithms) orelse
            return error.UnsupportedAlgorithm;
    const mac_s2c: ?[]const u8 = if (transport.isAeadCipher(cipher_s2c))
        null
    else
        pickFirst(client_kex.mac_algorithms_server_to_client, &transport.mac_algorithms) orelse
            return error.UnsupportedAlgorithm;

    // Record what got negotiated (RFC 4253 §7.1) on `t` for the connection's
    // lifetime — see `transport.NegotiatedAlgorithms` for why every field
    // here (`kex_name`/`hk.algorithmName()`/`cipher_c2s`/`cipher_s2c` all
    // resolve to a `pickFirst`-returned-from-`available` or static-literal
    // string) is safe to keep past this function returning and freeing
    // `client_kex`.
    t.negotiated = .{
        .kex = kex_name,
        .host_key = hk.algorithmName(),
        .cipher_c2s = cipher_c2s,
        .cipher_s2c = cipher_s2c,
        .mac_c2s = mac_c2s,
        .mac_s2c = mac_s2c,
    };

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
    // `kex_name` only ever comes from `transport.kex_algorithms`; every one of
    // those dispatches to a working responder implementation here.
    var kex_result = if (transport.isMlkemKex(kex_name))
        try mlkem768x25519KexServer(t.reader, t.writer, &none_w, i_c, i_s, v_c, v_s, hk, gpa)
    else if (isCurve25519Kex(kex_name))
        try curve25519KexServer(t.reader, t.writer, &none_w, i_c, i_s, v_c, v_s, hk, gpa)
    else
        try dhGroupKexServer(t.reader, t.writer, &none_w, i_c, i_s, v_c, v_s, hk, gpa, kex_name);
    defer kex_result.zeroize();
    rcvd += 1;
    sent += 1;

    if (t.session_id == null) t.session_id = transport.SessionId.from(kex_result.hash());
    const sid = t.session_id.?.slice();

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

/// These tests dial our OWN server, whose host key the test itself
/// generated, so the trust decision is already discharged by construction.
/// Never a template for real code — see `transport.HostKeyPolicy`.
const accept_any_host_key: transport.HostKeyPolicy = .{ .verifier = .{ .verifyFn = struct {
    fn f(_: *anyopaque, _: transport.HostKeyInfo) transport.HostKeyVerdict {
        return .accept;
    }
}.f }, .host = "127.0.0.1" };

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

/// ⭐ `accept`, but it cannot wait forever. Every accept in this module's tests
/// goes through here.
///
/// THE FAILURE MODE IS NOT A SLOW PEER, IT IS A PEER THAT ALREADY GAVE UP. The
/// live tests below spawn a real `/usr/bin/ssh` and then block in `accept`
/// waiting for it. A client that exits before connecting — a version that
/// rejects one of our `-o` options, a key it declines to load, anything —
/// leaves nobody to connect, and a bare `accept` then blocks for as long as the
/// process lives. That is not a hypothetical: on 2026-08-15 `ssh` was the only
/// module still running in every CI lane, alone for 23 to 64 minutes, and took
/// the six-hour job limit and every other lane's verdict with it. The same
/// tests pass locally in four seconds.
///
/// ⛔ `SO_RCVTIMEO` is NOT the way to do this, though it is the obvious one:
/// `accept` honours it, but `std.Io.Threaded` treats the resulting `EAGAIN` as
/// impossible and panics with "programmer bug caused syscall error: AGAIN".
/// Measured, not guessed. `poll(2)` on the raw handle stays outside `std.Io`
/// entirely, which is why it works — and it is what `opcua`'s interop driver
/// already uses for the same reason.
///
/// Staying outside `std.Io` cuts both ways: `std.posix.poll` also is not a
/// cancellation point. It retries on `EINTR`, and a thread parked in it is
/// never signalled by `Threaded` at all, so the wait runs to its full
/// `timeout_ms` regardless of a pending `Future.cancel` — which would
/// otherwise come back as an ordinary `error.AcceptPollFailed` or, worse, as
/// `error.PeerNeverConnected` indistinguishable from a peer that genuinely
/// never showed up. `checkCanceled` recovers it once the wait ends, on both
/// exit paths.
fn checkCanceled(io: std.Io) error{Canceled}!void {
    // `Io.checkCancel` acknowledges the request and reports it exactly once;
    // the answer has to be converted into an error right here, not asked for
    // again.
    io.checkCancel() catch return error.Canceled;
}

fn acceptBounded(io: std.Io, listener: *std.Io.net.Server, timeout_ms: i32) !std.Io.net.Stream {
    var fds = [_]std.posix.pollfd{.{
        .fd = listener.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const n = std.posix.poll(&fds, timeout_ms) catch {
        try checkCanceled(io);
        return error.AcceptPollFailed;
    };
    if (n == 0) {
        try checkCanceled(io);
        // A connection that never arrives is a FAILURE, not a skip: the peer
        // was present enough to be spawned, so "it did not connect" is a
        // finding.
        return error.PeerNeverConnected;
    }
    return listener.accept(io);
}

test "acceptBounded: a canceled wait surfaces Canceled, not an idle poll timeout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var port: u16 = 0;
    var listener = try listenLoopback(io, &port);
    defer listener.deinit(io);

    // Nobody connects: the poll inside `acceptBounded` is genuinely parked
    // for the whole of this timeout, exactly like the accept wait a real
    // caller would cancel on shutdown.
    var fut = try io.concurrent(acceptBounded, .{ io, &listener, @as(i32, 5000) });
    try io.sleep(.fromMilliseconds(100), .awake);
    try std.testing.expectError(error.Canceled, fut.cancel(io));
}

/// How long any test here waits for a peer it has already started. Generous
/// against a loaded runner, and still four orders of magnitude below the wall
/// this replaces.
const accept_timeout_ms: i32 = 30_000;

/// Does the LOCAL OpenSSH client know this key-exchange algorithm?
///
/// `ssh -Q kex` lists exactly what the installed client can negotiate, so this
/// asks the peer rather than assuming a version. Answering `false` on any
/// hiccup is deliberate: a probe that cannot run is not evidence the algorithm
/// is present, and skipping is the honest verdict.
fn opensshKnowsKex(io: std.Io, gpa: std.mem.Allocator, kex_name: []const u8) bool {
    var child = std.process.spawn(io, .{
        .argv = &.{ "/usr/bin/ssh", "-Q", "kex" },
        .stdout = .pipe,
        .stderr = .ignore,
    }) catch return false;
    var out_reader = child.stdout.?.readerStreaming(io, &.{});
    const listing = out_reader.interface.allocRemaining(gpa, .limited(64 * 1024)) catch {
        _ = child.wait(io) catch {};
        return false;
    };
    defer gpa.free(listing);
    _ = child.wait(io) catch return false;
    // Whole-line match: `ssh -Q kex` prints one algorithm per line, and a
    // substring test would accept `sntrup761x25519-sha512` as evidence for
    // `sntrup761x25519-sha512@openssh.com`.
    var it = std.mem.tokenizeAny(u8, listing, "\r\n");
    while (it.next()) |line| if (std.mem.eql(u8, std.mem.trim(u8, line, " \t"), kex_name)) return true;
    return false;
}

const SelfTestClient = struct {
    port: u16,
    err: ?anyerror = null,
    session_id: ?transport.SessionId = null,

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
        var t = try transport.connect(&sr.interface, &sw.interface, gpa, accept_any_host_key);

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

    var stream = try acceptBounded(io, &listener, accept_timeout_ms);
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
    try std.testing.expectEqualSlices(u8, t.session_id.?.slice(), client.session_id.?.slice());
}

test "self-consistency: our client ↔ our server (ed25519 host key)" {
    const hk = try HostKey.fromOpenSSH(fixture_ed25519_key, null);
    try selfConsistency(hk);
}

test "self-consistency: our client ↔ our server (rsa host key)" {
    const hk = try HostKey.fromOpenSSH(fixture_rsa_key, null);
    try selfConsistency(hk);
}

// The default handshake above negotiates `mlkem768x25519-sha256` (first in
// `transport.kex_algorithms`) + `chacha20-poly1305@openssh.com`, so those two
// self-consistency tests already exercise our client's + server's post-quantum
// hybrid KEX end-to-end. The direct-KEX tests below force each classic MODP DH
// group (which negotiation never picks over mlkem/curve25519) by calling the
// role-paired KEX functions directly over a loopback socket with a plaintext
// (`.none`) cipher — exactly the pre-NEWKEYS transport state — and assert both
// sides derive the same exchange hash `H` and the same encoded shared secret.

const dkx_v_c = "SSH-2.0-zig_dkx_client";
const dkx_v_s = "SSH-2.0-zig_dkx_server";
const dkx_i_c = "I_C direct-kex client kexinit payload (opaque here)";
const dkx_i_s = "I_S direct-kex server kexinit payload (opaque here)";

const DirectKexClient = struct {
    port: u16,
    kex_name: []const u8,
    /// What the client claims it negotiated for the host-key algorithm.
    /// Defaults to the algorithm `directDhConsistency`'s server side
    /// actually signs with (`fixture_ed25519_key`); a test that wants to
    /// exercise a MISMATCH (server signs one algorithm, client claims it
    /// negotiated another) overrides this.
    negotiated_host_key_algorithm: []const u8 = "ssh-ed25519",
    err: ?anyerror = null,
    hash: [64]u8 = undefined,
    hash_len: u8 = 0,
    k_enc: [transport.max_k_enc_len]u8 = undefined,
    k_enc_len: u16 = 0,

    fn run(self: *DirectKexClient) void {
        self.runInner() catch |e| {
            self.err = e;
        };
    }

    fn runInner(self: *DirectKexClient) !void {
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
        var none: transport.CipherState = .none;
        var res = try transport.dhGroupKex(&sr.interface, &sw.interface, &none, dkx_i_c, dkx_i_s, dkx_v_c, dkx_v_s, accept_any_host_key, self.kex_name, self.negotiated_host_key_algorithm);
        defer res.zeroize();
        self.hash_len = res.hash_len;
        @memcpy(self.hash[0..res.hash_len], res.hash());
        self.k_enc_len = res.k_enc_len;
        @memcpy(self.k_enc[0..res.k_enc_len], res.k_enc[0..res.k_enc_len]);
    }
};

fn directDhConsistency(kex_name: []const u8) !void {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var port: u16 = 0;
    var listener = try listenLoopback(io, &port);
    defer listener.deinit(io);

    var client = DirectKexClient{ .port = port, .kex_name = kex_name };
    const th = try std.Thread.spawn(.{}, DirectKexClient.run, .{&client});
    var joined = false;
    defer if (!joined) th.join();

    var stream = try acceptBounded(io, &listener, accept_timeout_ms);
    defer stream.close(io);
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const hk = try HostKey.fromOpenSSH(fixture_ed25519_key, null);
    var none: transport.CipherState = .none;
    var res = try dhGroupKexServer(&sr.interface, &sw.interface, &none, dkx_i_c, dkx_i_s, dkx_v_c, dkx_v_s, hk, gpa, kex_name);
    defer res.zeroize();

    th.join();
    joined = true;
    if (client.err) |e| return e;

    // Both roles must derive the same H and the same encoded K.
    try std.testing.expectEqual(res.hash_len, client.hash_len);
    try std.testing.expectEqualSlices(u8, res.hash(), client.hash[0..client.hash_len]);
    try std.testing.expectEqualSlices(u8, res.k_enc[0..res.k_enc_len], client.k_enc[0..client.k_enc_len]);
}

test "self-consistency (direct KEX): diffie-hellman-group14-sha256" {
    try directDhConsistency("diffie-hellman-group14-sha256");
}

test "self-consistency (direct KEX): diffie-hellman-group16-sha512" {
    try directDhConsistency("diffie-hellman-group16-sha512");
}

test "dhGroupKex (client): rejects a genuine rsa-sha2-256 host-key signature when rsa-sha2-512 was negotiated (RFC 8332 three-way check)" {
    // End-to-end proof, not just a unit test of the helper: the server here
    // signs with its real, correctly-typed `rsa-sha2-256` key — nothing on
    // the wire is forged. The only thing "wrong" is what the CLIENT claims
    // it negotiated. Before `checkHostKeyAlgorithmAgreement` existed,
    // `dhGroupKex` never looked at the negotiated name at all, so this
    // handshake would have completed "successfully" while silently
    // accepting a weaker hash than the one supposedly agreed in KEXINIT.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var port: u16 = 0;
    var listener = try listenLoopback(io, &port);
    defer listener.deinit(io);

    const kex_name = "diffie-hellman-group14-sha256";
    var client = DirectKexClient{
        .port = port,
        .kex_name = kex_name,
        .negotiated_host_key_algorithm = "rsa-sha2-512",
    };
    const th = try std.Thread.spawn(.{}, DirectKexClient.run, .{&client});
    var joined = false;
    defer if (!joined) th.join();

    var stream = try acceptBounded(io, &listener, accept_timeout_ms);
    defer stream.close(io);
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    // Freshly loaded, `.hash` is pinned to `.sha2_256` (see `HostKey.
    // fromOpenSSH`'s doc comment) — this key signs "rsa-sha2-256", never
    // "rsa-sha2-512".
    const hk = try HostKey.fromOpenSSH(fixture_rsa_key, null);
    try std.testing.expectEqualStrings("rsa-sha2-256", hk.algorithmName());
    var none: transport.CipherState = .none;
    var res = try dhGroupKexServer(&sr.interface, &sw.interface, &none, dkx_i_c, dkx_i_s, dkx_v_c, dkx_v_s, hk, gpa, kex_name);
    defer res.zeroize();

    th.join();
    joined = true;
    try std.testing.expectEqual(@as(?anyerror, error.HostKeyVerificationFailed), client.err);
}

/// Builds a raw (unencrypted, `.none` cipher) `SSH_MSG_KEXDH_INIT` packet
/// carrying `e_mag` as the peer's DH public value, written into `out` — the
/// server-role mirror of `transport.zig`'s `fakeKexdhReply` test helper.
fn fakeKexdhInit(e_mag: []const u8, out: []u8) ![]const u8 {
    var payload_buf: [4096 + 64]u8 = undefined;
    var pw: std.Io.Writer = .fixed(&payload_buf);
    try pw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_KEXDH_INIT));
    try messages.writeMpint(&pw, e_mag);

    var none: transport.CipherState = .none;
    var w: std.Io.Writer = .fixed(out);
    try transport.writePacket(&w, &none, pw.buffered());
    return w.buffered();
}

test "dhGroupKexServer: rejects a KEXDH_INIT carrying e == p or e == p-1 (F1 regression)" {
    const kex_name = "diffie-hellman-group14-sha256";
    const group = transport.DhGroup.forName(kex_name).?;
    const hk = try HostKey.fromOpenSSH(fixture_ed25519_key, null);
    const gpa = std.testing.allocator;

    for ([_][]const u8{ group.prime, group.prime_minus_1 }) |degenerate_e| {
        var init_buf: [1024]u8 = undefined;
        const init_pkt = try fakeKexdhInit(degenerate_e, &init_buf);

        var r: std.Io.Reader = .fixed(init_pkt);
        var out_scratch: [8192]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out_scratch);
        var none: transport.CipherState = .none;

        try std.testing.expectError(
            error.KexFailed,
            dhGroupKexServer(&r, &w, &none, "I_C", "I_S", "V_C", "V_S", hk, gpa, kex_name),
        );
    }
}

// ── live interop: real OpenSSH `ssh` client → our server (gated) ────────────

/// Spawn the system OpenSSH client against our in-process server on a
/// loopback port and prove KEX + KDF + cipher + MAC interop: the handshake
/// completes (which includes decrypting the client's encrypted
/// SSH_MSG_SERVICE_REQUEST "ssh-userauth") and the client's subsequent
/// SSH_MSG_USERAUTH_REQUEST decrypts too. The client then fails auth (we
/// never implement userauth in part 1) — that is expected and not asserted.
fn liveOpensshClient(keygen_type: []const u8, hostkey_algo: []const u8, kex_name: []const u8, cipher_name: []const u8) !void {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cwd = std.Io.Dir.cwd();

    // Gate on a runnable OpenSSH client.
    cwd.access(io, "/usr/bin/ssh", .{}) catch return error.SkipZigTest;

    // ⭐ …AND on that client actually knowing the algorithm under test. This is
    // not defensive tidiness: `mlkem768x25519-sha256` arrived in OpenSSH 9.9,
    // this host runs 10.2p1 and the GitHub ubuntu-24.04 runner runs 9.6, so on
    // 2026-08-15 the runner's `ssh` refused the `-o KexAlgorithms` line and
    // exited before opening a socket. Four sibling tests naming other KEX
    // algorithms passed on that same runner, which is what isolates the cause.
    //
    // The old shape then blocked in `accept` for the life of the process: it
    // was the whole reason every CI lane ran into the six-hour job limit. The
    // bounded accept turns that into a failure, but a failure is still the
    // wrong verdict — an algorithm the local client cannot speak is an
    // ENVIRONMENT gap, not a defect in our server. Ask, and skip loudly.
    if (!opensshKnowsKex(io, gpa, kex_name)) return error.SkipZigTest;

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
    const kex_opt = try std.fmt.allocPrint(gpa, "KexAlgorithms={s}", .{kex_name});
    defer gpa.free(kex_opt);
    var ssh_child = std.process.spawn(io, .{
        .argv = &.{
            "/usr/bin/ssh",                  "-p",             port_str,                         "-F",
            "/dev/null",                     "-o",             "StrictHostKeyChecking=no",       "-o",
            "UserKnownHostsFile=/dev/null",  "-o",             "GlobalKnownHostsFile=/dev/null", "-o",
            "PreferredAuthentications=none", "-o",             "BatchMode=yes",                  "-o",
            "MACs=hmac-sha2-256",            "-o",             "ConnectTimeout=10",              "-o",
            ciphers_opt,                     "-o",             hka_opt,                          "-o",
            kex_opt,                         "test@127.0.0.1", "true",
        },
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return error.SkipZigTest;
    defer ssh_child.kill(io);

    var stream = try acceptBounded(io, &listener, accept_timeout_ms);
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
            .aes_gcm => |st| switch (st.key_bits) {
                .aes256 => try std.testing.expectEqualStrings("aes256-gcm@openssh.com", cipher_name),
                .aes128 => try std.testing.expectEqualStrings("aes128-gcm@openssh.com", cipher_name),
            },
            .none => return error.ProtocolError,
        }
    }

    // `Transport.negotiated` must report exactly what the real `ssh` client
    // was forced (via `-o KexAlgorithms=.../-o Ciphers=.../-o
    // HostKeyAlgorithms=...`) to negotiate — the server-side counterpart of
    // the client-side check in transport.zig's `liveInterop`, and likewise
    // checked against a real independent SSH implementation.
    const neg = t.negotiated orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings(kex_name, neg.kex);
    try std.testing.expectEqualStrings(hostkey_algo, neg.host_key);
    try std.testing.expectEqualStrings(cipher_name, neg.cipher_c2s);
    try std.testing.expectEqualStrings(cipher_name, neg.cipher_s2c);
    if (transport.isAeadCipher(cipher_name)) {
        try std.testing.expect(neg.mac_c2s == null);
        try std.testing.expect(neg.mac_s2c == null);
    } else {
        try std.testing.expectEqualStrings("hmac-sha2-256", neg.mac_c2s.?);
        try std.testing.expectEqualStrings("hmac-sha2-256", neg.mac_s2c.?);
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

test "live interop: OpenSSH ssh client → our server — curve25519 + ed25519 + chacha20-poly1305" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "curve25519-sha256", "chacha20-poly1305@openssh.com");
}

test "live interop: OpenSSH ssh client → our server — curve25519 + ed25519 + aes256-ctr" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "curve25519-sha256", "aes256-ctr");
}

test "live interop: OpenSSH ssh client → our server — curve25519 + rsa-sha2-256 + chacha20-poly1305" {
    try liveOpensshClient("rsa", "rsa-sha2-256", "curve25519-sha256", "chacha20-poly1305@openssh.com");
}

test "live interop: OpenSSH ssh client → our server — curve25519 + rsa-sha2-512 + aes256-ctr" {
    try liveOpensshClient("rsa", "rsa-sha2-512", "curve25519-sha256", "aes256-ctr");
}

test "live interop: OpenSSH ssh client → our server — diffie-hellman-group14-sha256" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "diffie-hellman-group14-sha256", "aes256-ctr");
}

test "live interop: OpenSSH ssh client → our server — diffie-hellman-group16-sha512" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "diffie-hellman-group16-sha512", "aes256-ctr");
}

test "live interop: OpenSSH ssh client → our server — mlkem768x25519-sha256" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "mlkem768x25519-sha256", "chacha20-poly1305@openssh.com");
}

test "live interop: OpenSSH ssh client → our server — aes256-gcm@openssh.com" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "curve25519-sha256", "aes256-gcm@openssh.com");
}

test "live interop: OpenSSH ssh client → our server — aes128-gcm@openssh.com" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "curve25519-sha256", "aes128-gcm@openssh.com");
}
