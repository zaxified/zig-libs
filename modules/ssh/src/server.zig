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
//! A few small private helpers of `transport.zig` (`hashString`/
//! `encodeMpint`, the per-letter `deriveKeyBytes` and the cipher-install
//! `buildCipher`, `pickFirst`) are not `pub` there and
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
const burn = @import("burn.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const X25519 = std.crypto.dh.X25519;
const MLKem768 = std.crypto.kem.ml_kem.MLKem768;

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
///
/// A `HostKey` holds the private key BY VALUE (the `rsa` variant is ~12 KiB),
/// so it lives in one place — the caller's storage, `ServerConfig.host_keys`
/// — and everything here takes `*const HostKey`: a by-value pass copied the
/// whole key into every frame on the way, and nothing ever wiped those
/// copies (2026-10-09 stack probe). `sign` and `fromOpenSSH` run one frame
/// down and zero the stack they dirtied (`burn.zig`).
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
    /// `ecdsa-sha2-nistp384` (RFC 5656), the same shape on P-384 / SHA-384.
    ecdsa_p384: EcdsaP384.KeyPair,

    pub const RsaHash = enum { sha2_256, sha2_512 };

    /// The IANA/RFC algorithm name this host key signs with (matches an
    /// entry in `transport.server_host_key_algorithms`), and the wire
    /// key-type name embedded in `K_S` (RFC 4253 §7.1's "server_host_key
    /// algorithms" name-list intentionally equals the key-blob type name for
    /// every algorithm this module offers, except rsa-sha2-* whose key blob
    /// is still typed `"ssh-rsa"` per RFC 8332 §3).
    pub fn algorithmName(self: *const HostKey) []const u8 {
        return self.algorithmNameFor(null);
    }

    /// `algorithmName`, with an rsa key named for `rsa_hash` instead of its
    /// own `.hash` (`null`: its own). Other key types ignore `rsa_hash`.
    pub fn algorithmNameFor(self: *const HostKey, rsa_hash: ?RsaHash) []const u8 {
        return switch (self.*) {
            .ed25519 => "ssh-ed25519",
            .rsa => |*r| switch (rsa_hash orelse r.hash) {
                .sha2_256 => "rsa-sha2-256",
                .sha2_512 => "rsa-sha2-512",
            },
            .ecdsa_p256 => "ecdsa-sha2-nistp256",
            .ecdsa_p384 => "ecdsa-sha2-nistp384",
        };
    }

    pub const FromOpenSSHError = rsa.FromOpenSSHError || error{
        /// The container parsed structurally but names a key type this
        /// module does not load (only `ssh-rsa`, `ssh-ed25519`,
        /// `ecdsa-sha2-nistp256` and `-nistp384` — also covers an ecdsa
        /// container whose curve is not the one its type names).
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
    /// routes to `parseEd25519OpenSSH`, `"ecdsa-sha2-nistp256"` to
    /// `parseEcdsaP256OpenSSH`; all three key types read plain and
    /// passphrase-protected containers (bcrypt rounds capped at
    /// `rsa.max_openssh_kdf_rounds`, as in Go's x/crypto/ssh).
    ///
    /// The key is written to `out` (no copy of it is returned through the
    /// stack); on error `out` is zeroed.
    pub fn fromOpenSSH(out: *HostKey, text: []const u8, passphrase: ?[]const u8) FromOpenSSHError!void {
        burn.run(burn.load_burn, FromOpenSSHError!void, fromOpenSSHBody, .{ out, text, passphrase }) catch |e| {
            std.crypto.secureZero(u8, std.mem.asBytes(out));
            return e;
        };
    }

    fn fromOpenSSHBody(out: *HostKey, text: []const u8, passphrase: ?[]const u8) FromOpenSSHError!void {
        var bin_buf: [16 * 1024]u8 = undefined;
        defer std.crypto.secureZero(u8, &bin_buf);
        const bin = try pemDecodeOpensshBlock(text, &bin_buf);
        const hdr = try parseContainerHeader(bin);

        var pk_cur = WireCursor{ .b = hdr.public_blob };
        const key_type = pk_cur.string() catch return error.InvalidOpenSSH;

        if (std.mem.eql(u8, key_type, "ssh-rsa")) {
            out.* = .{ .rsa = undefined };
            const r = &out.rsa;
            const sk = &r.secret_key;
            try rsa.fromOpenSSH(sk, text, passphrase orelse "");
            // Public (e, n) from the container's (always-plaintext) public
            // blob: string "ssh-rsa" || mpint e || mpint n.
            const e_wire = pk_cur.string() catch return error.InvalidOpenSSH;
            const n_wire = pk_cur.string() catch return error.InvalidOpenSSH;
            const pk = rsa.PublicKey.fromBytes(n_wire, e_wire) catch return error.InvalidOpenSSH;
            // Cross-check: the public blob's (n, e) must be the secret key's.
            // n alone was checked until 2026-10-09; SSH_FUZZ `ssh-keyload`
            // found a container whose public `e` was damaged (65537 ->
            // 0x018101) load as a host key advertising a public key its own
            // signatures do not verify under.
            var n_sk: [rsa.max_modulus_len]u8 = undefined;
            sk.n.toBytes(&n_sk, .big) catch return error.InvalidPrivateKey;
            if (!std.mem.eql(u8, stripLeadingZeros(&n_sk), stripLeadingZeros(n_wire)))
                return error.InvalidPrivateKey;
            var e_sk: [rsa.max_modulus_len]u8 = undefined;
            sk.e.toBytes(&e_sk, .big) catch return error.InvalidPrivateKey;
            if (!std.mem.eql(u8, stripLeadingZeros(&e_sk), stripLeadingZeros(e_wire)))
                return error.InvalidPrivateKey;
            r.public_key = pk;
            r.hash = .sha2_256;
            return;
        }
        if (std.mem.eql(u8, key_type, "ssh-ed25519")) {
            out.* = .{ .ed25519 = undefined };
            return parseEd25519Body(&out.ed25519, bin, passphrase orelse "");
        }
        if (std.mem.eql(u8, key_type, "ecdsa-sha2-nistp256")) {
            out.* = .{ .ecdsa_p256 = undefined };
            return parseEcdsaP256Body(&out.ecdsa_p256, bin, passphrase orelse "");
        }
        if (std.mem.eql(u8, key_type, "ecdsa-sha2-nistp384")) {
            out.* = .{ .ecdsa_p384 = undefined };
            return parseEcdsaP384Body(&out.ecdsa_p384, bin, passphrase orelse "");
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
    pub fn publicBlob(self: *const HostKey, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var buf: [1024]u8 = undefined; // rsa-4096 K_S is ~535 bytes; others far less
        var w: std.Io.Writer = .fixed(&buf);
        switch (self.*) {
            .ed25519 => |*kp| {
                messages.writeString(&w, "ssh-ed25519") catch unreachable;
                messages.writeString(&w, &kp.public_key.toBytes()) catch unreachable;
            },
            .rsa => |*r| {
                var eb: [rsa.max_modulus_len]u8 = undefined;
                var nb: [rsa.max_modulus_len]u8 = undefined;
                r.public_key.e.toBytes(&eb, .big) catch unreachable;
                r.public_key.n.toBytes(&nb, .big) catch unreachable;
                messages.writeString(&w, "ssh-rsa") catch unreachable;
                messages.writeMpint(&w, &eb) catch unreachable;
                messages.writeMpint(&w, &nb) catch unreachable;
            },
            .ecdsa_p256 => |*kp| {
                const q = kp.public_key.toUncompressedSec1();
                messages.writeString(&w, "ecdsa-sha2-nistp256") catch unreachable;
                messages.writeString(&w, "nistp256") catch unreachable;
                messages.writeString(&w, &q) catch unreachable;
            },
            .ecdsa_p384 => |*kp| {
                const q = kp.public_key.toUncompressedSec1();
                messages.writeString(&w, "ecdsa-sha2-nistp384") catch unreachable;
                messages.writeString(&w, "nistp384") catch unreachable;
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
    pub fn sign(self: *const HostKey, gpa: std.mem.Allocator, exchange_hash: []const u8) std.mem.Allocator.Error![]u8 {
        return self.signWithHash(gpa, exchange_hash, null);
    }

    /// `sign`, with an rsa key signing under `rsa_hash` instead of its own
    /// `.hash` (`null`: its own) — how `userauth` honours RFC 8308
    /// `server-sig-algs` without copying the key. Other key types ignore it.
    pub fn signWithHash(self: *const HostKey, gpa: std.mem.Allocator, data: []const u8, rsa_hash: ?RsaHash) std.mem.Allocator.Error![]u8 {
        var buf: [1024]u8 = undefined; // rsa-4096 signature blob is ~532 bytes
        const blob = burn.run(burn.sign_burn, []const u8, signBody, .{ self, data, rsa_hash, &buf });
        return gpa.dupe(u8, blob);
    }

    fn signBody(self: *const HostKey, data: []const u8, rsa_hash: ?RsaHash, buf: *[1024]u8) []const u8 {
        var w: std.Io.Writer = .fixed(buf);
        switch (self.*) {
            .ed25519 => |*kp| {
                const sig = kp.sign(data, null) catch
                    @panic("ed25519 host-key signing failed on a validated key");
                messages.writeString(&w, "ssh-ed25519") catch unreachable;
                messages.writeString(&w, &sig.toBytes()) catch unreachable;
            },
            .rsa => |*r| {
                var sbuf: [rsa.max_modulus_len]u8 = undefined;
                const raw = switch (rsa_hash orelse r.hash) {
                    .sha2_256 => rsa.signPkcs1v15(&r.secret_key, Sha256, data, &sbuf),
                    .sha2_512 => rsa.signPkcs1v15(&r.secret_key, Sha512, data, &sbuf),
                } catch @panic("rsa host-key signing failed on a validated key");
                messages.writeString(&w, self.algorithmNameFor(rsa_hash)) catch unreachable;
                messages.writeString(&w, raw) catch unreachable;
            },
            .ecdsa_p256 => |*kp| signEcdsa(kp, "ecdsa-sha2-nistp256", data, &w),
            .ecdsa_p384 => |*kp| signEcdsa(kp, "ecdsa-sha2-nistp384", data, &w),
        }
        return w.buffered();
    }
};

/// RFC 5656 §3.1.2 signature blob: `string name || string(mpint r || mpint s)`
/// (NOT the fixed-width form; `transport.verifyEcdsa` reads it back).
fn signEcdsa(kp: anytype, comptime name: []const u8, data: []const u8, w: *std.Io.Writer) void {
    const sig = kp.sign(data, null) catch
        @panic("ecdsa host-key signing failed on a validated key");
    var inner_buf: [128]u8 = undefined;
    var iw: std.Io.Writer = .fixed(&inner_buf);
    messages.writeMpint(&iw, &sig.r) catch unreachable;
    messages.writeMpint(&iw, &sig.s) catch unreachable;
    messages.writeString(w, name) catch unreachable;
    messages.writeString(w, iw.buffered()) catch unreachable;
}

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

/// Parse an ed25519 private key from an openssh-key-v1 container, plain
/// (cipher/kdf `"none"`, what deployed host keys like
/// `/etc/ssh/ssh_host_ed25519_key` use) or passphrase-protected (bcrypt +
/// aes256-ctr/-cbc, `ssh-keygen -N`; since 2026-10-09, decrypted by the
/// sibling `rsa` module's `opensshDecryptSection` as Go's x/crypto/ssh
/// does for every key type). A wrong or empty passphrase is
/// `error.IncorrectPassphrase`.
///
/// Private-keys section layout (all RFC 4251 §5 primitives): `uint32`
/// checkint1 == `uint32` checkint2, `string` keytype `"ssh-ed25519"`,
/// `string` 32-byte pubkey, `string` 64-byte (seed || pubkey) — exactly the
/// `std.crypto.sign.Ed25519.SecretKey` encoding — `string` comment, then
/// deterministic padding bytes `0x01, 0x02, ...`.
///
/// The key pair is written to `out`; on error `out` is zeroed.
pub fn parseEd25519OpenSSH(out: *Ed25519.KeyPair, bin: []const u8, passphrase: []const u8) HostKey.FromOpenSSHError!void {
    burn.run(burn.load_burn, HostKey.FromOpenSSHError!void, parseEd25519Body, .{ out, bin, passphrase }) catch |e| {
        std.crypto.secureZero(u8, std.mem.asBytes(out));
        return e;
    };
}

fn parseEd25519Body(out: *Ed25519.KeyPair, bin: []const u8, passphrase: []const u8) HostKey.FromOpenSSHError!void {
    const hdr = try parseContainerHeader(bin);
    var dec_buf: [16 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &dec_buf);
    const sec = try rsa.opensshDecryptSection(&dec_buf, hdr.ciphername, hdr.kdfname, hdr.kdfoptions, hdr.private_section, passphrase);

    var cur = WireCursor{ .b = sec.plain };
    if (cur.b.len < 8) return error.InvalidOpenSSH;
    const check1 = std.mem.readInt(u32, cur.b[0..4], .big);
    const check2 = std.mem.readInt(u32, cur.b[4..8], .big);
    cur.i = 8;
    // Matching checkints are how OpenSSH detects a good passphrase; in a
    // plain container a mismatch can only be corruption.
    if (check1 != check2) return if (sec.encrypted) error.IncorrectPassphrase else error.InvalidOpenSSH;

    const keytype = cur.string() catch return error.InvalidOpenSSH;
    if (!std.mem.eql(u8, keytype, "ssh-ed25519")) return error.UnsupportedKeyType;
    const pub_bytes = cur.string() catch return error.InvalidOpenSSH;
    const priv_bytes = cur.string() catch return error.InvalidOpenSSH;
    _ = cur.string() catch return error.InvalidOpenSSH; // comment
    if (pub_bytes.len != 32 or priv_bytes.len != 64) return error.InvalidPrivateKey;
    // priv = 32-byte seed || 32-byte public key; the copies must agree.
    if (!std.mem.eql(u8, priv_bytes[32..64], pub_bytes)) return error.InvalidPrivateKey;
    // Deterministic padding to the cipher block size (8 for "none", 16 for AES).
    const pad = cur.b[cur.i..];
    if (pad.len >= sec.block_len) return error.InvalidOpenSSH;
    for (pad, 0..) |b, i| {
        if (b != @as(u8, @intCast(i + 1))) return error.InvalidOpenSSH;
    }

    const sk = Ed25519.SecretKey.fromBytes(priv_bytes[0..64].*) catch
        return error.InvalidPrivateKey;
    out.* = Ed25519.KeyPair.fromSecretKey(sk) catch return error.InvalidPrivateKey;
    // fromSecretKey re-derives the public key from the seed; require it to
    // match the container's copy.
    if (!std.mem.eql(u8, &out.public_key.toBytes(), pub_bytes)) return error.InvalidPrivateKey;
}

/// Parse an `ecdsa-sha2-nistp256` private key from an openssh-key-v1
/// container, plain or passphrase-protected — same container handling as
/// `parseEd25519OpenSSH` right above.
///
/// Private-keys section layout (RFC 5656 §3.1 + OpenSSH `PROTOCOL.key`):
/// `uint32` checkint1 == `uint32` checkint2, `string` keytype
/// `"ecdsa-sha2-nistp256"`, `string` curve name `"nistp256"`, `string` Q
/// (uncompressed SEC1 public point — re-derived from `d` below and checked
/// against this, not trusted directly), `string` d (the private scalar, big
/// -endian mpint-style with an optional leading zero byte), `string`
/// comment, then deterministic padding.
///
/// A1/yaml.md sibling finding — this is `A1/examples/ssh.md` S4+S5: `HostKey`
/// already has the `.ecdsa_p256` variant and `publicBlob`/`sign` already
/// implement it; the loader was the only gap. `example-apps/ssh-demo` grew
/// its own copy of exactly this parser to work around it (`main.zig`'s
/// `parseEcdsaP256OpenSSH`, marked "MODULE GAP, worked around here rather
/// than fought") — this closes the gap at its source instead.
///
/// The key pair is written to `out`; on error `out` is zeroed.
pub fn parseEcdsaP256OpenSSH(out: *EcdsaP256.KeyPair, bin: []const u8, passphrase: []const u8) HostKey.FromOpenSSHError!void {
    burn.run(burn.load_burn, HostKey.FromOpenSSHError!void, parseEcdsaP256Body, .{ out, bin, passphrase }) catch |e| {
        std.crypto.secureZero(u8, std.mem.asBytes(out));
        return e;
    };
}

/// `parseEcdsaP256OpenSSH` for `ecdsa-sha2-nistp384`.
pub fn parseEcdsaP384OpenSSH(out: *EcdsaP384.KeyPair, bin: []const u8, passphrase: []const u8) HostKey.FromOpenSSHError!void {
    burn.run(burn.load_burn, HostKey.FromOpenSSHError!void, parseEcdsaP384Body, .{ out, bin, passphrase }) catch |e| {
        std.crypto.secureZero(u8, std.mem.asBytes(out));
        return e;
    };
}

fn parseEcdsaP256Body(out: *EcdsaP256.KeyPair, bin: []const u8, passphrase: []const u8) HostKey.FromOpenSSHError!void {
    return parseEcdsaBody(EcdsaP256, "ecdsa-sha2-nistp256", "nistp256", out, bin, passphrase);
}

fn parseEcdsaP384Body(out: *EcdsaP384.KeyPair, bin: []const u8, passphrase: []const u8) HostKey.FromOpenSSHError!void {
    return parseEcdsaBody(EcdsaP384, "ecdsa-sha2-nistp384", "nistp384", out, bin, passphrase);
}

fn parseEcdsaBody(
    comptime E: type,
    comptime key_name: []const u8,
    comptime curve_name: []const u8,
    out: *E.KeyPair,
    bin: []const u8,
    passphrase: []const u8,
) HostKey.FromOpenSSHError!void {
    const hdr = try parseContainerHeader(bin);
    var dec_buf: [16 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &dec_buf);
    const sec = try rsa.opensshDecryptSection(&dec_buf, hdr.ciphername, hdr.kdfname, hdr.kdfoptions, hdr.private_section, passphrase);

    var cur = WireCursor{ .b = sec.plain };
    if (cur.b.len < 8) return error.InvalidOpenSSH;
    const check1 = std.mem.readInt(u32, cur.b[0..4], .big);
    const check2 = std.mem.readInt(u32, cur.b[4..8], .big);
    cur.i = 8;
    if (check1 != check2) return if (sec.encrypted) error.IncorrectPassphrase else error.InvalidOpenSSH;

    const keytype = cur.string() catch return error.InvalidOpenSSH;
    if (!std.mem.eql(u8, keytype, key_name)) return error.UnsupportedKeyType;
    const curve = cur.string() catch return error.InvalidOpenSSH;
    // The curve must be the one the type names — same "unsupported, not
    // malformed" verdict the type dispatch above uses.
    if (!std.mem.eql(u8, curve, curve_name)) return error.UnsupportedKeyType;
    _ = cur.string() catch return error.InvalidOpenSSH; // Q — rebuilt from d below, not trusted
    const d_wire = cur.string() catch return error.InvalidOpenSSH;
    _ = cur.string() catch return error.InvalidOpenSSH; // comment
    // Deterministic padding to the cipher block size — same check as
    // parseEd25519OpenSSH above.
    const pad = cur.b[cur.i..];
    if (pad.len >= sec.block_len) return error.InvalidOpenSSH;
    for (pad, 0..) |b, i| {
        if (b != @as(u8, @intCast(i + 1))) return error.InvalidOpenSSH;
    }

    // `d` is mpint-encoded: big-endian magnitude, with a leading zero byte
    // only when the top bit would otherwise read as a sign bit. Strip it and
    // right-align into the fixed-width scalar `SecretKey.fromBytes` wants.
    var scalar: [E.SecretKey.encoded_length]u8 = @splat(0);
    const trimmed = std.mem.trimStart(u8, d_wire, &.{0});
    if (trimmed.len > scalar.len or trimmed.len == 0) return error.InvalidPrivateKey;
    @memcpy(scalar[scalar.len - trimmed.len ..], trimmed);
    defer std.crypto.secureZero(u8, &scalar);

    const sk = E.SecretKey.fromBytes(scalar) catch return error.InvalidPrivateKey;
    out.* = E.KeyPair.fromSecretKey(sk) catch return error.InvalidPrivateKey;
    // Do not trust the parsed `d` (or the container's own `Q`, which is never
    // even read into a value above): rebuild K_S through publicBlob and
    // require it to equal the container's plaintext public blob byte for
    // byte, the same cross-check `fromOpenSSH`'s rsa branch already does for
    // (e, n) and this file's own `parseEd25519OpenSSH` does for the seed.
    var pb_buf: [1024]u8 = undefined;
    var pb_w: std.Io.Writer = .fixed(&pb_buf);
    messages.writeString(&pb_w, key_name) catch unreachable;
    messages.writeString(&pb_w, curve_name) catch unreachable;
    messages.writeString(&pb_w, &out.public_key.toUncompressedSec1()) catch unreachable;
    if (!std.mem.eql(u8, pb_w.buffered(), hdr.public_blob)) return error.InvalidPrivateKey;
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
    /// RFC 8308 §3.1 `server-sig-algs`: the public-key signature algorithms
    /// this server will accept for RFC 4252 `publickey` authentication, sent
    /// in SSH_MSG_EXT_INFO to any client that advertised `ext-info-c`.
    ///
    /// The default is everything `userauth.serveUserauth` can verify. Narrow
    /// it — do not widen it — when the caller's own `AuthorizedKeyCheck`
    /// refuses some of them: §3.1 says the server "MUST enumerate all public
    /// key algorithms it might accept", and a name here that the hook then
    /// refuses is worse than silence, because a client that owns only such a
    /// key will offer it, be rejected, and have no second choice. A server
    /// whose policy is "rsa-sha2-512 only" sets this to that one name and an
    /// OpenSSH client signs with SHA-512 the first time.
    ///
    /// Set to an empty slice to suppress the extension entirely (no
    /// SSH_MSG_EXT_INFO is sent at all — an empty `server-sig-algs` would
    /// claim this server accepts no public key, which is a different and
    /// false statement).
    server_sig_algs: []const []const u8 = &transport.public_key_algorithms,
    /// KEX methods, ciphers and MACs this server offers, most-preferred first
    /// (Go `ServerConfig.Config`); `serverHandshake` installs it as
    /// `Transport.algorithms`. `host_keys` in it is ignored here — the server
    /// offers the algorithms of the keys in `host_keys` above.
    algorithms: transport.Algorithms = .{},
};

// ── server-side (responder-role) key exchange ───────────────────────────────

/// curve25519-sha256 server side (see the body below).
///
/// The result goes to `out` (never returned by value: it holds `K`); the body
/// runs one frame down and the stack it dirtied is zeroed after it, std's
/// X25519 / ML-KEM / modexp frames included.
pub fn curve25519KexServer(
    out: *transport.KexResult,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
) transport.TransportError!void {
    return burn.run(burn.kex_x25519_burn, transport.TransportError!void, curve25519KexServerInto, .{ out, r, w, ciphers, entropy, client_kexinit_payload, server_kexinit_payload, client_id, server_id, host_key, gpa });
}

fn curve25519KexServerInto(
    out: *transport.KexResult,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
) transport.TransportError!void {
    out.* = try curve25519KexServerBody(r, w, ciphers, entropy, client_kexinit_payload, server_kexinit_payload, client_id, server_id, host_key, gpa);
}

/// Run the server side of curve25519-sha256 key exchange (RFC 8731): receive
/// SSH_MSG_KEX_ECDH_INIT (`Q_C`, the client's ephemeral public value),
/// generate our own ephemeral keypair (`Q_S`, seeded from `entropy`),
/// compute the shared secret `K` and exchange hash `H`
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
fn curve25519KexServerBody(
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
) transport.TransportError!transport.KexResult {
    // SSH_MSG_KEX_ECDH_INIT: byte || string Q_C.
    var buf: [16384]u8 = undefined;
    const pkt = try transport.readKexPacket(r, ciphers, &buf);
    if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXDH_INIT)) return error.KexFailed;
    var cur = WireCursor{ .b = pkt.payload[1..] };
    const q_c = try cur.string();
    if (q_c.len != 32) return error.KexFailed;
    var q_c_arr: [32]u8 = undefined;
    @memcpy(&q_c_arr, q_c);

    // Our ephemeral X25519 keypair (seed from the OS CSPRNG, zeroed after).
    var seed: [32]u8 = undefined;
    entropy.fill(&seed);
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
    try transport.writePacket(w, ciphers.w, entropy, ow.buffered());

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

/// ecdh-sha2-nistp256 / -nistp384 server side (see the body below).
///
/// The result goes to `out` (never returned by value: it holds `K`); the body
/// runs one frame down and the stack it dirtied is zeroed after it.
pub fn ecdhNistKexServer(
    out: *transport.KexResult,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
    kex_name: []const u8,
) transport.TransportError!void {
    return burn.run(burn.kex_ecdh_burn, transport.TransportError!void, ecdhNistKexServerInto, .{ out, r, w, ciphers, entropy, client_kexinit_payload, server_kexinit_payload, client_id, server_id, host_key, gpa, kex_name });
}

fn ecdhNistKexServerInto(
    out: *transport.KexResult,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
    kex_name: []const u8,
) transport.TransportError!void {
    switch (transport.EcdhNist.forName(kex_name) orelse return error.UnsupportedAlgorithm) {
        inline else => |c| try ecdhNistKexServerBody(c, out, r, w, ciphers, entropy, client_kexinit_payload, server_kexinit_payload, client_id, server_id, host_key, gpa),
    }
}

/// Run the server side of RFC 5656 §4 ECDH: receive SSH_MSG_KEX_ECDH_INIT
/// (`Q_C`), validate it, generate our ephemeral pair (`Q_S`), compute `K` and
/// `H` (`transport.ecdhNistFinish`, the client's formula), sign `H` with
/// `host_key`, send SSH_MSG_KEX_ECDH_REPLY (`K_S`, `Q_S`, signature).
fn ecdhNistKexServerBody(
    comptime c: transport.EcdhNist,
    out: *transport.KexResult,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
) transport.TransportError!void {
    // SSH_MSG_KEX_ECDH_INIT: byte || string Q_C.
    var buf: [16384]u8 = undefined;
    const pkt = try transport.readKexPacket(r, ciphers, &buf);
    if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXDH_INIT)) return error.KexFailed;
    var cur = WireCursor{ .b = pkt.payload[1..] };
    const q_c = try cur.string();

    var kp = try transport.EcdhNistKeyPair(c).generate(entropy);
    defer kp.zeroize();
    var shared = try transport.ecdhNistShared(c, &kp.secret, q_c);
    defer std.crypto.secureZero(u8, &shared);

    const k_s = try host_key.publicBlob(gpa);
    defer gpa.free(k_s);

    out.* = .{};
    try transport.ecdhNistFinish(c, out, &shared, client_id, server_id, client_kexinit_payload, server_kexinit_payload, k_s, q_c, &kp.public);

    const sig = try host_key.sign(gpa, out.hash());
    defer gpa.free(sig);

    // SSH_MSG_KEX_ECDH_REPLY: byte || string K_S || string Q_S || string sig.
    var obuf: [2048]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&obuf);
    try ow.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_KEXDH_REPLY));
    try messages.writeString(&ow, k_s);
    try messages.writeString(&ow, &kp.public);
    try messages.writeString(&ow, sig);
    try transport.writePacket(w, ciphers.w, entropy, ow.buffered());
}

/// diffie-hellman-group14/16 server side (see the body below).
///
/// The result goes to `out` (never returned by value: it holds `K`); the body
/// runs one frame down and the stack it dirtied is zeroed after it, std's
/// X25519 / ML-KEM / modexp frames included.
pub fn dhGroupKexServer(
    out: *transport.KexResult,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
    kex_name: []const u8,
) transport.TransportError!void {
    return burn.run(burn.kex_dh_burn, transport.TransportError!void, dhGroupKexServerInto, .{ out, r, w, ciphers, entropy, client_kexinit_payload, server_kexinit_payload, client_id, server_id, host_key, gpa, kex_name });
}

fn dhGroupKexServerInto(
    out: *transport.KexResult,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
    kex_name: []const u8,
) transport.TransportError!void {
    out.* = try dhGroupKexServerBody(r, w, ciphers, entropy, client_kexinit_payload, server_kexinit_payload, client_id, server_id, host_key, gpa, kex_name);
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
fn dhGroupKexServerBody(
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
    kex_name: []const u8,
) transport.TransportError!transport.KexResult {
    const group = transport.DhGroup.forName(kex_name) orelse return error.UnsupportedAlgorithm;
    const g = [_]u8{2};

    // SSH_MSG_KEXDH_INIT: byte || mpint e.
    var buf: [16384]u8 = undefined;
    const pkt = try transport.readKexPacket(r, ciphers, &buf);
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
    entropy.fill(yb);
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
    try transport.writePacket(w, ciphers.w, entropy, ow.buffered());

    return res;
}

/// diffie-hellman-group-exchange-sha256 server side (see the body below).
///
/// The result goes to `out` (never returned by value: it holds `K`); the body
/// runs one frame down and the stack it dirtied is zeroed after it.
pub fn dhGexKexServer(
    out: *transport.KexResult,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
) transport.TransportError!void {
    return burn.run(burn.kex_gex_burn, transport.TransportError!void, dhGexKexServerBody, .{ out, r, w, ciphers, entropy, client_kexinit_payload, server_kexinit_payload, client_id, server_id, host_key, gpa });
}

/// Which of this module's fixed groups answers a GEX_REQUEST (min, n, max):
/// the RFC 3526 group14 (2048) or group16 (4096) prime, whichever the
/// request admits and lies closer to `n` (RFC 4419 §3: "the server should
/// select a group that best matches the client's request"). No moduli file:
/// like Go's server, this one offers fixed, well-known safe primes only.
pub fn gexServerGroup(min: u32, n: u32, max: u32) ?transport.DhGroup {
    if (min > n or n > max) return null;
    const g14 = transport.DhGroup.forName("diffie-hellman-group14-sha256").?;
    const g16 = transport.DhGroup.forName("diffie-hellman-group16-sha512").?;
    const ok14 = min <= 2048 and 2048 <= max;
    const ok16 = min <= 4096 and 4096 <= max;
    if (ok14 and (!ok16 or n <= 3072)) return g14;
    if (ok16) return g16;
    return null;
}

/// RFC 4419 §3 server: GEX_REQUEST → GEX_GROUP(p, 2) → GEX_INIT(e), checked
/// `1 < e < p-1` → GEX_REPLY(K_S, f, sig over H).
fn dhGexKexServerBody(
    out: *transport.KexResult,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
) transport.TransportError!void {
    const g = [_]u8{2};

    // SSH_MSG_KEX_DH_GEX_REQUEST: byte || uint32 min || uint32 n || uint32 max.
    var rbuf: [256]u8 = undefined;
    const rpkt = try transport.readKexPacket(r, ciphers, &rbuf);
    if (msgType(rpkt) != transport.msg_kex_dh_gex_request) return error.KexFailed;
    var rcur = WireCursor{ .b = rpkt.payload[1..] };
    const req = [3]u32{ try rcur.uint32(), try rcur.uint32(), try rcur.uint32() };
    const group = gexServerGroup(req[0], req[1], req[2]) orelse return error.KexFailed;

    // SSH_MSG_KEX_DH_GEX_GROUP: byte || mpint p || mpint g.
    {
        var gbuf: [16 + transport.dh_max_prime_len]u8 = undefined;
        var gw: std.Io.Writer = .fixed(&gbuf);
        try gw.writeByte(transport.msg_kex_dh_gex_group);
        try messages.writeMpint(&gw, group.prime);
        try messages.writeMpint(&gw, &g);
        try transport.writePacket(w, ciphers.w, entropy, gw.buffered());
    }

    // SSH_MSG_KEX_DH_GEX_INIT: byte || mpint e.
    var buf: [16384]u8 = undefined;
    const pkt = try transport.readKexPacket(r, ciphers, &buf);
    if (msgType(pkt) != transport.msg_kex_dh_gex_init) return error.KexFailed;
    var cur = WireCursor{ .b = pkt.payload[1..] };
    const e = stripLeadingZeros(try cur.string());
    if (group.rejectsDegeneratePeerValue(e)) return error.KexFailed;

    // Secret y, f = g^y, K = e^y (the fixed groups' constant-time modexp).
    var y: [transport.dh_max_prime_len]u8 = undefined;
    const yb = y[0..group.prime.len];
    defer std.crypto.secureZero(u8, &y);
    entropy.fill(yb);
    yb[0] &= 0x7f;
    yb[yb.len - 1] |= 1;
    var fbuf: [transport.dh_max_prime_len]u8 = undefined;
    const f = try transport.dhPowModPrime(group.prime, &g, yb, &fbuf);
    var kbuf: [transport.dh_max_prime_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &kbuf);
    const k_mag = try transport.dhPowModPrime(group.prime, e, yb, &kbuf);

    const k_s = try host_key.publicBlob(gpa);
    defer gpa.free(k_s);

    out.* = .{};
    try transport.gexFinish(out, client_id, server_id, client_kexinit_payload, server_kexinit_payload, k_s, req, group.prime, &g, e, f, k_mag);

    const sig = try host_key.sign(gpa, out.hash());
    defer gpa.free(sig);

    // SSH_MSG_KEX_DH_GEX_REPLY: byte || string K_S || mpint f || string sig.
    var obuf: [8 + transport.dh_max_prime_len + 2048]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&obuf);
    try ow.writeByte(transport.msg_kex_dh_gex_reply);
    try messages.writeString(&ow, k_s);
    try messages.writeMpint(&ow, f);
    try messages.writeString(&ow, sig);
    try transport.writePacket(w, ciphers.w, entropy, ow.buffered());
}

/// mlkem768x25519-sha256 server side (see the body below).
///
/// The result goes to `out` (never returned by value: it holds `K`); the body
/// runs one frame down and the stack it dirtied is zeroed after it, std's
/// X25519 / ML-KEM / modexp frames included.
pub fn mlkem768x25519KexServer(
    out: *transport.KexResult,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
) transport.TransportError!void {
    return burn.run(burn.kex_mlkem_burn, transport.TransportError!void, mlkem768x25519KexServerInto, .{ out, r, w, ciphers, entropy, client_kexinit_payload, server_kexinit_payload, client_id, server_id, host_key, gpa });
}

fn mlkem768x25519KexServerInto(
    out: *transport.KexResult,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
) transport.TransportError!void {
    out.* = try mlkem768x25519KexServerBody(r, w, ciphers, entropy, client_kexinit_payload, server_kexinit_payload, client_id, server_id, host_key, gpa);
}

/// Responder side of `mlkem768x25519-sha256` (OpenSSH's post-quantum hybrid),
/// the server-role mirror of `transport.mlkem768x25519Kex`: receive
/// SSH_MSG_KEX_ECDH_INIT with blob `C = ML-KEM_encaps_key(1184) ‖ X25519_pub`,
/// ML-KEM-`encaps` against the client's key + generate our X25519 ephemeral,
/// compute `K = SHA256(K_MLKEM ‖ K_X25519)` (string-encoded), hash
/// `H = SHA256(V_C‖V_S‖I_C‖I_S‖K_S‖C‖S‖string(K))`, sign it, and send the
/// reply with blob `S = ML-KEM_ciphertext(1088) ‖ X25519_server_pub`.
fn mlkem768x25519KexServerBody(
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    ciphers: transport.CipherPair,
    entropy: transport.Entropy,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    host_key: *const HostKey,
    gpa: std.mem.Allocator,
) transport.TransportError!transport.KexResult {
    // SSH_MSG_KEX_ECDH_INIT: byte || string C.
    var buf: [16384]u8 = undefined;
    const pkt = try transport.readKexPacket(r, ciphers, &buf);
    if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXDH_INIT)) return error.KexFailed;
    var cur = WireCursor{ .b = pkt.payload[1..] };
    const cinit = try cur.string();
    if (cinit.len != transport.mlkem_cinit_len) return error.KexFailed;

    // ML-KEM encapsulate against the client's encapsulation key.
    var kem_pk_bytes: [transport.mlkem_pk_len]u8 = undefined;
    @memcpy(&kem_pk_bytes, cinit[0..transport.mlkem_pk_len]);
    const kem_pk = MLKem768.PublicKey.fromBytes(&kem_pk_bytes) catch return error.KexFailed;
    var kem_seed: [MLKem768.encaps_seed_length]u8 = undefined;
    entropy.fill(&kem_seed);
    defer std.crypto.secureZero(u8, &kem_seed);
    const enc = kem_pk.encapsDeterministic(&kem_seed);
    var kem_shared = enc.shared_secret;
    defer std.crypto.secureZero(u8, &kem_shared);

    // Our X25519 ephemeral + shared with the client's X25519 public.
    var x_client: [32]u8 = undefined;
    @memcpy(&x_client, cinit[transport.mlkem_pk_len..transport.mlkem_cinit_len]);
    var x_seed: [32]u8 = undefined;
    entropy.fill(&x_seed);
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
    try transport.writePacket(w, ciphers.w, entropy, ow.buffered());

    return res;
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

/// `pickFirst` from the client's list against ours (`t.algorithms`, a
/// caller-owned list), returned as the module's own constant so it may be
/// kept in `Transport.negotiated`.
fn pickTheirs(client: []const []const u8, ours: []const []const u8, supported: []const []const u8) transport.TransportError![]const u8 {
    const name = pickFirst(client, ours) orelse return error.UnsupportedAlgorithm;
    return transport.canonicalName(supported, name) orelse error.UnsupportedAlgorithm;
}

// ── full server handshake ───────────────────────────────────────────────────

/// Full server (responder) handshake — the mirror of
/// `transport.Transport.clientHandshake`, taking a `ServerConfig` instead of
/// a `HostKeyVerifier`. Operates on an already-`transport.Transport.init`-ed
/// connection (same struct the client side uses — NOT duplicated here).
///
/// Sequence: version exchange (reused `transport.exchangeVersions` —
/// role-symmetric) → `serverKexRound` (KEXINIT exchange with our host-key
/// list built from `config.host_keys`, plus RFC 8308's `ext-info-s` and
/// strict KEX's `kex-strict-s-v00@openssh.com` → client-preference
/// negotiation → responder KEX → NEWKEYS both ways → cipher install with the
/// server direction mapping, write = s2c, read = c2s) → RFC 8308
/// SSH_MSG_EXT_INFO with `server-sig-algs`, if the client advertised
/// `ext-info-c` → respond to the client's SSH_MSG_SERVICE_REQUEST
/// `"ssh-userauth"` with SSH_MSG_SERVICE_ACCEPT.
///
/// ⚠ `config.host_keys` must outlive `t`: a key re-exchange (RFC 4253 §9),
/// which the client may start at any time, signs with them again.
///
/// After this returns, `t` is an encrypted transport ready for userauth —
/// out of scope in THIS FILE, but implemented server-side by
/// `userauth.serveUserauth` (real, not a placeholder; see `root.zig`'s
/// module doc comment).
pub fn serverHandshake(t: *transport.Transport, gpa: std.mem.Allocator, config: ServerConfig) transport.TransportError!void {
    if (config.host_keys.len == 0) return error.UnsupportedAlgorithm;
    t.role = .server;
    t.gpa = gpa;
    t.server_host_keys = config.host_keys;
    t.algorithms = config.algorithms;
    try t.algorithms.validate(); // before the version exchange: nothing sent yet

    // 1. Version exchange (role-symmetric; we speak first, which is the
    // conventional server behavior anyway).
    const local_id = transport.IdentificationString{ .softwareversion = config.server_software };
    const v_c = try transport.exchangeVersions(gpa, t.reader, t.writer, local_id);
    defer gpa.free(v_c);
    try t.v_c.set(v_c);
    var vsbuf: [255]u8 = undefined;
    try t.v_s.set(std.fmt.bufPrint(&vsbuf, "SSH-2.0-{s}", .{config.server_software}) catch
        return error.VersionExchangeFailed);

    // 2-6. The initial key exchange.
    const outcome = try serverKexRound(t, gpa, .initial, null, null);
    t.finishKex();

    // 6b. RFC 8308 §2.4, the server's FIRST opportunity: SSH_MSG_EXT_INFO
    // "following the server's first SSH_MSG_NEWKEYS message", i.e. the first
    // packet we encrypt. It has to be here and not later: `server-sig-algs`
    // is what tells a client which signature algorithm to use for a key whose
    // blob type does not name one, and an OpenSSH client decides that before
    // it sends its first SSH_MSG_USERAUTH_REQUEST — without this it logs
    // "send_pubkey_test: no mutual signature algorithm" and never offers an
    // RSA key at all. The RFC's second opportunity (immediately before
    // SSH_MSG_USERAUTH_SUCCESS) exists for extensions that only make sense
    // once the user is known; `server-sig-algs` is not one, so we use the
    // first and only the first.
    if (outcome.client_wants_ext_info and config.server_sig_algs.len > 0) {
        var ebuf: [1024]u8 = undefined;
        var ew: std.Io.Writer = .fixed(&ebuf);
        try transport.encodeServerSigAlgs(&ew, config.server_sig_algs);
        try t.sendPacket(ew.buffered());
    }

    // 7. SSH_MSG_SERVICE_REQUEST "ssh-userauth" → SSH_MSG_SERVICE_ACCEPT
    // (responder mirror of `transport.Transport.requestService`).
    const scratch = try gpa.alloc(u8, 64 * 1024);
    defer gpa.free(scratch);
    while (true) {
        const pkt = try t.recvPacket(scratch);
        switch (@as(messages.MessageType, @enumFromInt(msgType(pkt)))) {
            // The client's own RFC 8308 §2.4 opportunity — OpenSSH always
            // takes it once we advertise `ext-info-s`, sending
            // `publickey-hostbound@openssh.com` and `ping@openssh.com`. This
            // module implements no client-sent extension, and §2.5 says to
            // ignore what we do not recognize; what it must NOT do is treat
            // the message as a protocol error, which is what having promised
            // `ext-info-s` and then refusing the reply would be.
            .SSH_MSG_EXT_INFO => continue,
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

/// What the initial exchange learned that the handshake still needs.
pub const ServerKexOutcome = struct {
    /// The client advertised RFC 8308 `ext-info-c`.
    client_wants_ext_info: bool,
};

/// One complete responder key exchange over `t` with `t.server_host_keys`:
/// the initial one, or a re-exchange (`peer_kexinit` already received;
/// `ours` set when we sent our KEXINIT first, i.e. `Transport.rekey`).
/// Called by `serverHandshake` and by `transport.Transport` for a rekey.
pub fn serverKexRound(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    round: transport.KexRound,
    peer_kexinit: ?[]const u8,
    ours: ?[]const u8,
) transport.TransportError!ServerKexOutcome {
    // Body one frame down, its stack (`K`, derived keys, std's frames) zeroed
    // after it.
    return burn.run(burn.round_burn, transport.TransportError!ServerKexOutcome, serverKexRoundBody, .{ t, gpa, round, peer_kexinit, ours });
}

fn serverKexRoundBody(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    round: transport.KexRound,
    peer_kexinit: ?[]const u8,
    ours: ?[]const u8,
) transport.TransportError!ServerKexOutcome {
    if (t.server_host_keys.len == 0) return error.UnsupportedAlgorithm;
    const scratch = try gpa.alloc(u8, 64 * 1024);
    defer {
        // A re-exchange may queue channel data through it.
        std.crypto.secureZero(u8, scratch);
        gpa.free(scratch);
    }
    const ciphers = transport.CipherPair{ .r = &t.read_cipher, .w = &t.write_cipher, .skip_generic = round == .rekey };

    // 2. Our KEXINIT (I_S): host-key algorithms restricted to keys we hold.
    var i_s_owned: ?[]u8 = null;
    defer if (i_s_owned) |b| gpa.free(b);
    const i_s = ours orelse blk: {
        const b = try t.buildKexInit(gpa, round);
        i_s_owned = b;
        try transport.writePacket(t.writer, ciphers.w, t.entropy, b);
        break :blk b;
    };

    // The client's KEXINIT (I_C).
    var i_c_owned: ?[]u8 = null;
    defer if (i_c_owned) |b| gpa.free(b);
    const i_c = peer_kexinit orelse blk: {
        const cpkt = try transport.readKexPacket(t.reader, ciphers, scratch);
        if (msgType(cpkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXINIT)) return error.ProtocolError;
        const b = try gpa.dupe(u8, cpkt.payload);
        i_c_owned = b;
        break :blk b;
    };

    var creader: std.Io.Reader = .fixed(i_c[1..]);
    var client_kex = try transport.KexInit.decode(gpa, &creader);
    defer client_kex.deinit(gpa);

    // RFC 8308 §2.2: SSH_MSG_EXT_INFO may be sent ONLY to a peer that
    // advertised the indicator for its role. A client that did not must see
    // no EXT_INFO at all — not an empty one — because to such a client
    // message 7 is an unknown transport message it would answer
    // SSH_MSG_UNIMPLEMENTED.
    const client_wants_ext_info = transport.offersExtInfo(client_kex.kex_algorithms, transport.ext_info_c);
    if (round == .initial) t.strict_kex = t.offer_strict_kex and transport.offersExtInfo(client_kex.kex_algorithms, transport.kex_strict_c);

    // 3. Negotiate (client-preference order per RFC 4253 §7.1) against
    // `t.algorithms` (validated by `buildKexInit` above or by the round that
    // sent `ours`).
    const algs = t.algorithms;
    const kex_name = try pickTheirs(client_kex.kex_algorithms, algs.kex, &transport.supported_kex_algorithms);
    var host_key: ?*const HostKey = null;
    outer: for (client_kex.server_host_key_algorithms) |name| {
        for (t.server_host_keys) |*hk| {
            if (std.mem.eql(u8, name, hk.algorithmName())) {
                host_key = hk;
                break :outer;
            }
        }
    }
    const hk = host_key orelse return error.UnsupportedAlgorithm;
    const cipher_c2s = try pickTheirs(client_kex.encryption_algorithms_client_to_server, algs.ciphers, &transport.supported_encryption_algorithms);
    const cipher_s2c = try pickTheirs(client_kex.encryption_algorithms_server_to_client, algs.ciphers, &transport.supported_encryption_algorithms);
    // MAC only matters for a non-AEAD cipher (mirrors the client's policy),
    // and the name (previously discarded to `_`) is kept for diagnostics.
    const mac_c2s: ?[]const u8 = if (transport.isAeadCipher(cipher_c2s))
        null
    else
        try pickTheirs(client_kex.mac_algorithms_client_to_server, algs.macs, &transport.supported_mac_algorithms);
    const mac_s2c: ?[]const u8 = if (transport.isAeadCipher(cipher_s2c))
        null
    else
        try pickTheirs(client_kex.mac_algorithms_server_to_client, algs.macs, &transport.supported_mac_algorithms);
    // RFC 4253 §7.1 negotiates compression the same as every other
    // name-list and requires a disconnect on no overlap — mirrors the
    // client-side fix in `transport.negotiate`.
    const comp_c2s = pickFirst(client_kex.compression_algorithms_client_to_server, &transport.compression_algorithms) orelse
        return error.UnsupportedAlgorithm;
    const comp_s2c = pickFirst(client_kex.compression_algorithms_server_to_client, &transport.compression_algorithms) orelse
        return error.UnsupportedAlgorithm;

    // Record what got negotiated (RFC 4253 §7.1) on `t` — see
    // `transport.NegotiatedAlgorithms` for why every field here (`kex_name`/
    // `hk.algorithmName()`/`cipher_c2s`/`cipher_s2c` all resolve to a
    // `pickFirst`-returned-from-`available` or static-literal string) is safe
    // to keep past this function returning and freeing `client_kex`.
    t.negotiated = .{
        .kex = kex_name,
        .host_key = hk.algorithmName(),
        .cipher_c2s = cipher_c2s,
        .cipher_s2c = cipher_s2c,
        .mac_c2s = mac_c2s,
        .mac_s2c = mac_s2c,
        .compression_c2s = comp_c2s,
        .compression_s2c = comp_s2c,
    };

    // RFC 4253 §7: a wrongly-guessed first KEX packet must be discarded
    // (OpenSSH never guesses; this is spec completeness). It still advances
    // the read sequence number.
    if (client_kex.first_kex_packet_follows) {
        const guess_ok = client_kex.kex_algorithms.len > 0 and
            std.mem.eql(u8, client_kex.kex_algorithms[0], kex_name) and
            client_kex.server_host_key_algorithms.len > 0 and
            std.mem.eql(u8, client_kex.server_host_key_algorithms[0], hk.algorithmName());
        if (!guess_ok) {
            _ = try transport.readKexPacket(t.reader, ciphers, scratch);
        }
    }

    // 4. Responder-side KEX (reads KEX_ECDH_INIT, writes KEX_ECDH_REPLY).
    // `kex_name` only ever comes from `transport.kex_algorithms`; every one of
    // those dispatches to a working responder implementation here.
    var v_c_copy = t.v_c;
    var v_s_copy = t.v_s;
    const v_c = v_c_copy.slice();
    const v_s = v_s_copy.slice();
    var kex_result: transport.KexResult = .{};
    defer kex_result.zeroize();
    if (transport.isMlkemKex(kex_name))
        try mlkem768x25519KexServer(&kex_result, t.reader, t.writer, ciphers, t.entropy, i_c, i_s, v_c, v_s, hk, gpa)
    else if (isCurve25519Kex(kex_name))
        try curve25519KexServer(&kex_result, t.reader, t.writer, ciphers, t.entropy, i_c, i_s, v_c, v_s, hk, gpa)
    else if (transport.isEcdhNistKex(kex_name))
        try ecdhNistKexServer(&kex_result, t.reader, t.writer, ciphers, t.entropy, i_c, i_s, v_c, v_s, hk, gpa, kex_name)
    else if (transport.isDhGexKex(kex_name))
        try dhGexKexServer(&kex_result, t.reader, t.writer, ciphers, t.entropy, i_c, i_s, v_c, v_s, hk, gpa)
    else
        try dhGroupKexServer(&kex_result, t.reader, t.writer, ciphers, t.entropy, i_c, i_s, v_c, v_s, hk, gpa, kex_name);

    if (t.session_id == null) t.session_id = transport.SessionId.from(kex_result.hash());

    // 5-6. NEWKEYS both ways; SERVER direction mapping: we ENCRYPT with the
    // server-to-client keys ('B'/'D'/'F') and DECRYPT with the
    // client-to-server keys ('A'/'C'/'E'), the exact swap of the client's.
    try transport.writePacket(t.writer, ciphers.w, t.entropy, &[_]u8{@intFromEnum(messages.MessageType.SSH_MSG_NEWKEYS)});
    try t.installCipher(.write, cipher_s2c, mac_s2c, .s2c, &kex_result);
    const nk = try transport.readKexPacket(t.reader, ciphers, scratch);
    if (msgType(nk) != @intFromEnum(messages.MessageType.SSH_MSG_NEWKEYS)) return error.ProtocolError;
    try t.installCipher(.read, cipher_c2s, mac_c2s, .c2s, &kex_result);

    return .{ .client_wants_ext_info = client_wants_ext_info };
}

/// Convenience: `transport.Transport.init` followed by `serverHandshake` —
/// the responder-side mirror of `transport.connect`.
// secret-api-ok: thin wrapper of Transport.init + serverHandshake (kex and round burns); ServerConfig holds slices of the host keys, so a by-value copy copies pointers only.
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

fn testFillRandom(buf: []u8) void {
    const os: transport.Entropy = .os;
    os.fill(buf);
}

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

// Host-key fixtures, shared with `stackprobe_test.zig`.
const vectors = @import("hostkey_vectors.zig");
const fixture_ed25519_key = vectors.ed25519_key;
const fixture_ed25519_pub_b64 = vectors.ed25519_pub_b64;
const fixture_rsa_key = vectors.rsa_key;
const fixture_rsa_pub_b64 = vectors.rsa_pub_b64;
const fixture_ecdsa_p256_key = vectors.ecdsa_p256_key;
const fixture_ecdsa_p256_pub_b64 = vectors.ecdsa_p256_pub_b64;
const fixture_ecdsa_p384_key = vectors.ecdsa_p384_key;
const fixture_ecdsa_p384_pub_b64 = vectors.ecdsa_p384_pub_b64;

fn decodeFixturePub(b64: []const u8, buf: []u8) ![]u8 {
    const dec = std.base64.standard.Decoder;
    const n = try dec.calcSizeForSlice(b64);
    try dec.decode(buf[0..n], b64);
    return buf[0..n];
}

test "HostKey.fromOpenSSH: ed25519 fixture parses; K_S matches ssh-keygen's .pub blob" {
    const t = std.testing;
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_ed25519_key, null);
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
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_rsa_key, null);
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

test "HostKey.fromOpenSSH: ecdsa-p256 fixture parses; K_S matches ssh-keygen's .pub blob (A1/examples/ssh.md S4+S5)" {
    // Before this fix, `HostKey.fromOpenSSH` returned `error.UnsupportedKeyType`
    // on exactly this fixture (an `ssh-keygen -t ecdsa -b 256` container) even
    // though `HostKey.ecdsa_p256`, `publicBlob`, and `sign` already handled
    // the variant fully -- the loader was the only gap. `example-apps/ssh-demo`
    // carried its own copy of this parser to work around it.
    const t = std.testing;
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_ecdsa_p256_key, null);
    try t.expectEqualStrings("ecdsa-sha2-nistp256", hk.algorithmName());

    const blob = try hk.publicBlob(t.allocator);
    defer t.allocator.free(blob);
    var pubbuf: [256]u8 = undefined;
    const expected = try decodeFixturePub(fixture_ecdsa_p256_pub_b64, &pubbuf);
    try t.expectEqualSlices(u8, expected, blob);

    // Sign + verify round-trip through the wire blob, same mpint(r)||mpint(s)
    // decode the "wire shape verifies" test below uses.
    const pk = hk.ecdsa_p256.public_key;
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

test "HostKey.fromOpenSSH: ecdsa-p384 fixture parses; K_S matches ssh-keygen's .pub blob; signature verifies via transport" {
    const t = std.testing;
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_ecdsa_p384_key, null);
    try t.expectEqualStrings("ecdsa-sha2-nistp384", hk.algorithmName());

    const blob = try hk.publicBlob(t.allocator);
    defer t.allocator.free(blob);
    var pubbuf: [256]u8 = undefined;
    const expected = try decodeFixturePub(fixture_ecdsa_p384_pub_b64, &pubbuf);
    try t.expectEqualSlices(u8, expected, blob);

    // The client's verifier accepts it, and refuses it under the wrong curve
    // name, a flipped octet of H, and as a P-256 key.
    const h = [_]u8{0x3C} ** 48;
    const sig_blob = try hk.sign(t.allocator, &h);
    defer t.allocator.free(sig_blob);
    try transport.verifySignature("ecdsa-sha2-nistp384", blob, sig_blob, &h);
    var h2 = h;
    h2[0] ^= 1;
    try t.expectError(error.HostKeyVerificationFailed, transport.verifySignature("ecdsa-sha2-nistp384", blob, sig_blob, &h2));
    try t.expectError(error.HostKeyVerificationFailed, transport.verifySignature("ecdsa-sha2-nistp256", blob, sig_blob, &h));
}

test "parseEcdsaP256OpenSSH: a curve other than nistp256 is UnsupportedKeyType, not accepted" {
    // Synthetic container (same construction style as the "rejects a key
    // type none of the three loaders handle" test above), naming a curve
    // this module has no `HostKey` variant for. `HostKey` only carries
    // `ecdsa_p256`, so nistp384/521 must be refused, not silently truncated
    // or misread as p256.
    const t = std.testing;
    var priv_buf: [256]u8 = undefined;
    var pw: std.Io.Writer = .fixed(&priv_buf);
    try pw.writeAll(&[_]u8{ 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 }); // checkint1 == checkint2
    try messages.writeString(&pw, "ecdsa-sha2-nistp256");
    try messages.writeString(&pw, "nistp384"); // wrong curve, same key-type string
    try messages.writeString(&pw, "");
    try messages.writeString(&pw, "");
    try messages.writeString(&pw, ""); // comment
    // No padding needed: "none" cipher block size is 8, and this body's
    // length already lands on an 8-byte boundary by construction below.

    var bin: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&bin);
    try w.writeAll("openssh-key-v1\x00");
    try messages.writeString(&w, "none");
    try messages.writeString(&w, "none");
    try messages.writeString(&w, "");
    try w.writeAll(&[_]u8{ 0, 0, 0, 1 });
    try messages.writeString(&w, ""); // public blob (unchecked before the curve check)
    try messages.writeString(&w, pw.buffered());

    var kp: EcdsaP256.KeyPair = undefined;
    try t.expectError(error.UnsupportedKeyType, parseEcdsaP256OpenSSH(&kp, w.buffered(), ""));
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

test "parseEd25519OpenSSH: a cipher OpenSSH keys do not use is UnsupportedCipher" {
    const t = std.testing;
    // aes128-ctr is a transport cipher, never a private-key one (OpenSSH and
    // Go's x/crypto/ssh read aes256-ctr and aes256-cbc only).
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("openssh-key-v1\x00");
    try messages.writeString(&w, "aes128-ctr");
    try messages.writeString(&w, "bcrypt");
    try messages.writeString(&w, "\x00\x00\x00\x04salt\x00\x00\x00\x04");
    try w.writeAll(&[_]u8{ 0, 0, 0, 1 }); // nkeys
    try messages.writeString(&w, ""); // public blob
    try messages.writeString(&w, "0123456789abcdef"); // private section
    var kp: Ed25519.KeyPair = undefined;
    try t.expectError(error.UnsupportedCipher, parseEd25519OpenSSH(&kp, w.buffered(), "pw"));
}

test "HostKey.fromOpenSSH: passphrase-protected ed25519 (ctr, cbc) and ecdsa-p256 load; wrong or no passphrase refused" {
    const t = std.testing;
    const v = @import("hostkey_vectors.zig");
    const Case = struct { text: []const u8, pub_b64: []const u8 };
    const cases = [_]Case{
        .{ .text = v.ed25519_enc_ctr_key, .pub_b64 = v.ed25519_enc_ctr_pub_b64 },
        .{ .text = v.ed25519_enc_cbc_key, .pub_b64 = v.ed25519_enc_cbc_pub_b64 },
        .{ .text = v.ecdsa_p256_enc_ctr_key, .pub_b64 = v.ecdsa_p256_enc_ctr_pub_b64 },
    };
    for (cases) |c| {
        var hk: HostKey = undefined;
        try HostKey.fromOpenSSH(&hk, c.text, v.enc_passphrase);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&hk));
        const blob = try hk.publicBlob(t.allocator);
        defer t.allocator.free(blob);
        var want_buf: [256]u8 = undefined;
        const dec = std.base64.standard.Decoder;
        const want = want_buf[0..try dec.calcSizeForSlice(c.pub_b64)];
        try dec.decode(want, c.pub_b64);
        try t.expectEqualSlices(u8, want, blob);

        var bad: HostKey = undefined;
        try t.expectError(error.IncorrectPassphrase, HostKey.fromOpenSSH(&bad, c.text, "not the passphrase"));
        try t.expectError(error.IncorrectPassphrase, HostKey.fromOpenSSH(&bad, c.text, null));
    }
}

test "HostKey.fromOpenSSH rejects a key type none of the three loaders handle" {
    // `ssh-dss` (DSA) is a real OpenSSH container key-type name this module
    // has never implemented for any of the three loaders (rsa, ed25519,
    // ecdsa-p256) -- unlike `ecdsa-sha2-nistp256`, which used to be this
    // test's example before `parseEcdsaP256OpenSSH` closed A1/examples/ssh.md
    // S4+S5 (that type now has to route to a *different* error than this
    // one, see the fixture/mutation tests above).
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
    try messages.writeString(&pw, "ssh-dss");
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
    var hk: HostKey = undefined;
    try t.expectError(error.UnsupportedKeyType, HostKey.fromOpenSSH(&hk, text, null));
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
        testFillRandom(&pb);
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
    algs: transport.Algorithms = .{},
    err: ?anyerror = null,
    session_id: ?transport.SessionId = null,
    negotiated: ?transport.NegotiatedAlgorithms = null,

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
        var t = transport.Transport.init(&sr.interface, &sw.interface);
        t.algorithms = self.algs;
        try t.clientHandshake(gpa, accept_any_host_key);
        self.negotiated = t.negotiated;

        var pbuf: [8192]u8 = undefined;
        try t.requestService("ssh-userauth", &pbuf);

        // Encrypted c2s probe: a marker no layer acts on. Not SSH_MSG_IGNORE —
        // `recvPacket` absorbs transport-generic messages — but a
        // want_reply=false SSH_MSG_GLOBAL_REQUEST, which reaches the caller.
        var mb: [64]u8 = undefined;
        var mw: std.Io.Writer = .fixed(&mb);
        try mw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_GLOBAL_REQUEST));
        try messages.writeString(&mw, "probe-c2s");
        try mw.writeByte(0);
        try t.sendPacket(mw.buffered());

        // Encrypted s2c probe back from the server.
        const pkt = try t.recvPacket(&pbuf);
        if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_GLOBAL_REQUEST)) return error.ProtocolError;
        if (std.mem.indexOf(u8, pkt.payload, "probe-s2c") == null) return error.ProtocolError;

        self.session_id = t.session_id;
    }
};

fn selfConsistency(host_key: *const HostKey) !void {
    _ = try selfConsistencyWith(host_key, .{}, .{});
}

/// `selfConsistency` with each side's `Algorithms`; returns what the server
/// negotiated after checking the client recorded the same names.
fn selfConsistencyWith(host_key: *const HostKey, client_algs: transport.Algorithms, server_algs: transport.Algorithms) !transport.NegotiatedAlgorithms {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var port: u16 = 0;
    var listener = try listenLoopback(io, &port);
    defer listener.deinit(io);

    var client = SelfTestClient{ .port = port, .algs = client_algs };
    const th = try std.Thread.spawn(.{}, SelfTestClient.run, .{&client});
    var joined = false;
    defer if (!joined) th.join(); // runs after stream.close -> client unblocks

    var stream = try acceptBounded(io, &listener, accept_timeout_ms);
    defer stream.close(io);
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const keys: []const HostKey = host_key[0..1];
    var t = try accept(&sr.interface, &sw.interface, gpa, .{ .host_keys = keys, .algorithms = server_algs });

    // The client's encrypted probe must decrypt on our side...
    var pbuf: [8192]u8 = undefined;
    const pkt = try t.recvPacket(&pbuf);
    try std.testing.expectEqual(@intFromEnum(messages.MessageType.SSH_MSG_GLOBAL_REQUEST), msgType(pkt));
    try std.testing.expect(std.mem.indexOf(u8, pkt.payload, "probe-c2s") != null);

    // ...and ours on the client's.
    var mb: [64]u8 = undefined;
    var mw: std.Io.Writer = .fixed(&mb);
    try mw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_GLOBAL_REQUEST));
    try messages.writeString(&mw, "probe-s2c");
    try mw.writeByte(0);
    try t.sendPacket(mw.buffered());

    th.join();
    joined = true;
    if (client.err) |e| return e;

    // Both sides must have derived the same session id (= exchange hash H).
    try std.testing.expect(t.session_id != null and client.session_id != null);
    try std.testing.expectEqualSlices(u8, t.session_id.?.slice(), client.session_id.?.slice());
    const ours = t.negotiated.?;
    const theirs = client.negotiated.?;
    try std.testing.expectEqualStrings(ours.kex, theirs.kex);
    try std.testing.expectEqualStrings(ours.cipher_c2s, theirs.cipher_c2s);
    try std.testing.expectEqualStrings(ours.cipher_s2c, theirs.cipher_s2c);
    return ours;
}

test "self-consistency: our client ↔ our server (ed25519 host key)" {
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_ed25519_key, null);
    try selfConsistency(&hk);
}

test "self-consistency: our client ↔ our server (rsa host key)" {
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_rsa_key, null);
    try selfConsistency(&hk);
}

test "Algorithms: the client's order decides, the server's list restricts; negotiated names are the module's constants" {
    const gpa = std.testing.allocator;
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_ed25519_key, null);

    // The server's lists live in caller memory freed right after the
    // handshake: `Transport.negotiated` must not point into them.
    const kex0 = try gpa.dupe(u8, "curve25519-sha256");
    defer gpa.free(kex0);
    const c0 = try gpa.dupe(u8, "chacha20-poly1305@openssh.com");
    defer gpa.free(c0);
    const c1 = try gpa.dupe(u8, "aes128-gcm@openssh.com");
    defer gpa.free(c1);
    const server_kex = [_][]const u8{kex0};
    const server_ciphers = [_][]const u8{ c0, c1 };
    const client_ciphers = [_][]const u8{ "aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com" };

    const neg = try selfConsistencyWith(
        &hk,
        .{ .ciphers = &client_ciphers },
        .{ .kex = &server_kex, .ciphers = &server_ciphers },
    );
    // The client prefers mlkem768x25519 by default; the server only allows
    // curve25519-sha256.
    try std.testing.expectEqualStrings("curve25519-sha256", neg.kex);
    // Client order wins over the server's (RFC 4253 §7.1).
    try std.testing.expectEqualStrings("aes128-gcm@openssh.com", neg.cipher_c2s);
    try std.testing.expectEqualStrings("aes128-gcm@openssh.com", neg.cipher_s2c);
    try std.testing.expect(neg.kex.ptr != kex0.ptr);
    try std.testing.expect(neg.cipher_c2s.ptr == transport.canonicalName(&transport.supported_encryption_algorithms, "aes128-gcm@openssh.com").?.ptr);
}

test "Algorithms: a client restricted to a non-AEAD cipher negotiates its MAC" {
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_ed25519_key, null);
    const only_ctr = [_][]const u8{"aes256-ctr"};
    const neg = try selfConsistencyWith(&hk, .{ .ciphers = &only_ctr }, .{});
    try std.testing.expectEqualStrings("aes256-ctr", neg.cipher_c2s);
    try std.testing.expectEqualStrings(transport.mac_algorithms[0], neg.mac_c2s.?);
    try std.testing.expectEqualStrings(transport.mac_algorithms[0], neg.mac_s2c.?);
}

test "Algorithms REJECT: disjoint cipher lists end the handshake with UnsupportedAlgorithm" {
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_ed25519_key, null);
    const client_ciphers = [_][]const u8{"chacha20-poly1305@openssh.com"};
    const server_ciphers = [_][]const u8{"aes256-gcm@openssh.com"};
    try std.testing.expectError(error.UnsupportedAlgorithm, selfConsistencyWith(
        &hk,
        .{ .ciphers = &client_ciphers },
        .{ .ciphers = &server_ciphers },
    ));
}

test "serverHandshake REJECT: an unsupported configured name is refused before anything is sent" {
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_ed25519_key, null);
    var rbuf: [16]u8 = undefined;
    var r: std.Io.Reader = .fixed(rbuf[0..0]);
    var wbuf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wbuf);
    var t = transport.Transport.init(&r, &w);
    const bogus = [_][]const u8{"3des-cbc"};
    try std.testing.expectError(error.UnsupportedAlgorithm, serverHandshake(&t, std.testing.allocator, .{
        .host_keys = (&hk)[0..1],
        .algorithms = .{ .ciphers = &bogus },
    }));
    try std.testing.expectEqual(@as(usize, 0), w.end);
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
        var none: transport.CipherState = .plaintext;
        var res: transport.KexResult = .{};
        if (transport.isDhGexKex(self.kex_name))
            try transport.dhGexKex(&res, &sr.interface, &sw.interface, .single(&none), .os, dkx_i_c, dkx_i_s, dkx_v_c, dkx_v_s, accept_any_host_key, self.negotiated_host_key_algorithm)
        else if (transport.isEcdhNistKex(self.kex_name))
            try transport.ecdhNistKex(&res, &sr.interface, &sw.interface, .single(&none), .os, dkx_i_c, dkx_i_s, dkx_v_c, dkx_v_s, accept_any_host_key, self.kex_name, self.negotiated_host_key_algorithm)
        else
            try transport.dhGroupKex(&res, &sr.interface, &sw.interface, .single(&none), .os, dkx_i_c, dkx_i_s, dkx_v_c, dkx_v_s, accept_any_host_key, self.kex_name, self.negotiated_host_key_algorithm);
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

    var hk: HostKey = undefined;

    try HostKey.fromOpenSSH(&hk, fixture_ed25519_key, null);
    var none: transport.CipherState = .plaintext;
    var res: transport.KexResult = .{};
    if (transport.isDhGexKex(kex_name))
        try dhGexKexServer(&res, &sr.interface, &sw.interface, .single(&none), .os, dkx_i_c, dkx_i_s, dkx_v_c, dkx_v_s, &hk, gpa)
    else if (transport.isEcdhNistKex(kex_name))
        try ecdhNistKexServer(&res, &sr.interface, &sw.interface, .single(&none), .os, dkx_i_c, dkx_i_s, dkx_v_c, dkx_v_s, &hk, gpa, kex_name)
    else
        try dhGroupKexServer(&res, &sr.interface, &sw.interface, .single(&none), .os, dkx_i_c, dkx_i_s, dkx_v_c, dkx_v_s, &hk, gpa, kex_name);
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

test "self-consistency (direct KEX): diffie-hellman-group-exchange-sha256" {
    try directDhConsistency("diffie-hellman-group-exchange-sha256");
}

test "gexServerGroup: picks the fixed group closest to n inside [min, max], or none" {
    const t = std.testing;
    try t.expectEqual(@as(usize, 256), gexServerGroup(2048, 2048, 8192).?.prime.len);
    try t.expectEqual(@as(usize, 256), gexServerGroup(1024, 3072, 8192).?.prime.len);
    try t.expectEqual(@as(usize, 512), gexServerGroup(2048, 4096, 8192).?.prime.len);
    try t.expectEqual(@as(usize, 512), gexServerGroup(3072, 3072, 8192).?.prime.len);
    try t.expect(gexServerGroup(6144, 7680, 8192) == null);
    try t.expect(gexServerGroup(4096, 2048, 8192) == null); // min > n
}

test "self-consistency (direct KEX): ecdh-sha2-nistp256" {
    try directDhConsistency("ecdh-sha2-nistp256");
}

test "self-consistency (direct KEX): ecdh-sha2-nistp384" {
    try directDhConsistency("ecdh-sha2-nistp384");
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
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_rsa_key, null);
    try std.testing.expectEqualStrings("rsa-sha2-256", hk.algorithmName());
    var none: transport.CipherState = .plaintext;
    var res: transport.KexResult = .{};
    try dhGroupKexServer(&res, &sr.interface, &sw.interface, .single(&none), .os, dkx_i_c, dkx_i_s, dkx_v_c, dkx_v_s, &hk, gpa, kex_name);
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

    var none: transport.CipherState = .plaintext;
    var w: std.Io.Writer = .fixed(out);
    try transport.writePacket(&w, &none, .os, pw.buffered());
    return w.buffered();
}

test "dhGroupKexServer: rejects a KEXDH_INIT carrying e == p or e == p-1 (F1 regression)" {
    const kex_name = "diffie-hellman-group14-sha256";
    const group = transport.DhGroup.forName(kex_name).?;
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_ed25519_key, null);
    const gpa = std.testing.allocator;

    for ([_][]const u8{ group.prime, group.prime_minus_1 }) |degenerate_e| {
        var init_buf: [1024]u8 = undefined;
        const init_pkt = try fakeKexdhInit(degenerate_e, &init_buf);

        var r: std.Io.Reader = .fixed(init_pkt);
        var out_scratch: [8192]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out_scratch);
        var none: transport.CipherState = .plaintext;
        var kr: transport.KexResult = .{};

        try std.testing.expectError(
            error.KexFailed,
            dhGroupKexServer(&kr, &r, &w, .single(&none), .os, "I_C", "I_S", "V_C", "V_S", &hk, gpa, kex_name),
        );
    }
}

// ── RFC 4253 §7 wrongly-guessed first KEX packet (client side) ─────────────

const GuessingClient = struct {
    port: u16,
    err: ?anyerror = null,
    got_probe: bool = false,
    negotiated_kex: [64]u8 = undefined,
    negotiated_kex_len: usize = 0,

    fn run(self: *GuessingClient) void {
        self.runInner() catch |e| {
            self.err = e;
        };
    }

    fn runInner(self: *GuessingClient) !void {
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
        if (t.negotiated) |neg| {
            self.negotiated_kex_len = @min(neg.kex.len, self.negotiated_kex.len);
            @memcpy(self.negotiated_kex[0..self.negotiated_kex_len], neg.kex[0..self.negotiated_kex_len]);
        }
        // The first encrypted packet: decrypts only if the read sequence
        // number counted the discarded guess.
        var pbuf: [1024]u8 = undefined;
        const pkt = try t.recvPacket(&pbuf);
        if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_GLOBAL_REQUEST)) return error.ProtocolError;
        self.got_probe = std.mem.indexOf(u8, pkt.payload, "after-guess") != null;
    }
};

// Regression for the `ssh` A1 audit finding "`clientHandshake` ignores the
// server's `first_kex_packet_follows`" (RFC 4253 §7): a server may set that
// flag on its KEXINIT and immediately follow it with an optimistically
// "guessed" first KEX packet. When the guess is WRONG (the negotiated
// algorithm differs from what the server assumed), RFC 4253 §7 requires
// that guessed packet be silently discarded — otherwise it sits on the wire
// exactly where the client's real KEX reply belongs, and the KEX function
// reads garbage instead.
//
// This drives a hand-rolled "server" (not `serverHandshake`, which never
// guesses) through the real client entry point `transport.connect` →
// `clientHandshake`. The server offers `diffie-hellman-group16-sha512`
// FIRST and `diffie-hellman-group14-sha256` second, with no mlkem/curve25519
// at all; the client's OWN preference order (mlkem > curve25519 >
// curve25519@libssh.org > group14 > group16) then negotiates group14 — so a
// `first_kex_packet_follows` guess of group16 is wrong by construction, and
// the server sends one throwaway `SSH_MSG_IGNORE` as that "guessed" packet
// before performing the REAL group14 KEX honestly.
test "clientHandshake discards a server's wrongly-guessed first KEX packet instead of desyncing on it (RFC 4253 §7)" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var port: u16 = 0;
    var listener = try listenLoopback(io, &port);
    defer listener.deinit(io);

    var client = GuessingClient{ .port = port };
    const th = try std.Thread.spawn(.{}, GuessingClient.run, .{&client});
    var joined = false;
    defer if (!joined) th.join();

    var stream = try acceptBounded(io, &listener, accept_timeout_ms);
    defer stream.close(io);
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    // 1. Version exchange (server speaks first, as `serverHandshake` does).
    const local_id = transport.IdentificationString{ .softwareversion = "zig_ssh_guess_test_srv" };
    const v_c = try transport.exchangeVersions(gpa, &sr.interface, &sw.interface, local_id);
    defer gpa.free(v_c);
    const v_s = "SSH-2.0-zig_ssh_guess_test_srv";

    var scratch: [64 * 1024]u8 = undefined;
    var none_r: transport.CipherState = .plaintext;
    var none_w: transport.CipherState = .plaintext;

    // 2. Read the client's real KEXINIT.
    const cpkt = try transport.readPacket(&sr.interface, &none_r, &scratch);
    const i_c = try gpa.dupe(u8, cpkt.payload);
    defer gpa.free(i_c);

    // 3. Spoofed server KEXINIT: wrong guess, as described above.
    var cookie: [16]u8 = undefined;
    testFillRandom(&cookie);
    const empty: []const []const u8 = &.{};
    const wrong_guess_kex = [_][]const u8{ "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256" };
    const host_key_names = [_][]const u8{"ssh-ed25519"};
    const spoofed_kex = transport.KexInit{
        .cookie = cookie,
        .kex_algorithms = &wrong_guess_kex,
        .server_host_key_algorithms = &host_key_names,
        .encryption_algorithms_client_to_server = &transport.encryption_algorithms,
        .encryption_algorithms_server_to_client = &transport.encryption_algorithms,
        .mac_algorithms_client_to_server = &transport.mac_algorithms,
        .mac_algorithms_server_to_client = &transport.mac_algorithms,
        .compression_algorithms_client_to_server = &transport.compression_algorithms,
        .compression_algorithms_server_to_client = &transport.compression_algorithms,
        .languages_client_to_server = empty,
        .languages_server_to_client = empty,
        .first_kex_packet_follows = true,
        .reserved = 0,
    };
    var isbuf: [2048]u8 = undefined;
    var isw: std.Io.Writer = .fixed(&isbuf);
    try spoofed_kex.encode(&isw);
    const i_s = try gpa.dupe(u8, isw.buffered());
    defer gpa.free(i_s);
    try transport.writePacket(&sw.interface, &none_w, .os, i_s);

    // 4. The "guessed" first KEX packet — under the WRONG algorithm, so a
    // spec-correct client discards it sight unseen. Anything left unconsumed
    // here sits exactly where the real KEXDH_REPLY belongs in step 5.
    var junk_buf: [16]u8 = undefined;
    var jw: std.Io.Writer = .fixed(&junk_buf);
    try jw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_IGNORE));
    try messages.writeString(&jw, "x");
    try transport.writePacket(&sw.interface, &none_w, .os, jw.buffered());

    // 5. The REAL KEX, honestly, under group14 — the algorithm the client
    // actually negotiates. Proves the discard ate exactly one packet, not
    // zero and not two.
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, fixture_ed25519_key, null);
    var res: transport.KexResult = .{};
    try dhGroupKexServer(&res, &sr.interface, &sw.interface, .{ .r = &none_r, .w = &none_w }, .os, i_c, i_s, v_c, v_s, &hk, gpa, "diffie-hellman-group14-sha256");
    defer res.zeroize();

    // 6. NEWKEYS both ways.
    try transport.writePacket(&sw.interface, &none_w, .os, &[_]u8{@intFromEnum(messages.MessageType.SSH_MSG_NEWKEYS)});
    const nk = try transport.readPacket(&sr.interface, &none_r, &scratch);
    try std.testing.expectEqual(@intFromEnum(messages.MessageType.SSH_MSG_NEWKEYS), msgType(nk));

    // 7. One encrypted packet. This server sent FOUR plaintext packets
    // (KEXINIT, the guess, KEXDH_REPLY, NEWKEYS) and no strict-KEX
    // indicator, so its first encrypted packet carries sequence number 4
    // (RFC 4253 §6.4: every packet counts, a discarded one too). The client
    // used to seed its read cipher with a fixed 3 and failed this packet's
    // MAC; nothing before this step encrypted anything, so it went unseen.
    var st = transport.Transport.init(&sr.interface, &sw.interface);
    st.write_cipher = none_w;
    try std.testing.expectEqual(@as(u32, 4), st.write_cipher.sequenceNumber());
    st.session_id = transport.SessionId.from(res.hash());
    try st.installCipher(.write, "chacha20-poly1305@openssh.com", null, .s2c, &res);
    var probe: [32]u8 = undefined;
    var pw: std.Io.Writer = .fixed(&probe);
    try pw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_GLOBAL_REQUEST));
    try messages.writeString(&pw, "after-guess");
    try pw.writeByte(0);
    try st.sendPacket(pw.buffered());

    th.join();
    joined = true;
    // Before the fix: `client.err` is `error.KexFailed` (`dhGroupKex` reads
    // the leftover `SSH_MSG_IGNORE` back as its KEXDH_REPLY and rejects the
    // message type) — a full handshake never completes at all. After the
    // fix: no error, and the negotiated algorithm really is group14 — the
    // client never entertained the server's group16 guess.
    try std.testing.expectEqual(@as(?anyerror, null), client.err);
    try std.testing.expectEqualStrings("diffie-hellman-group14-sha256", client.negotiated_kex[0..client.negotiated_kex_len]);
    try std.testing.expect(client.got_probe);
}

// ── live interop: real OpenSSH `ssh` client → our server (gated) ────────────

/// Spawn the system OpenSSH client against our in-process server on a
/// loopback port and prove KEX + KDF + cipher + MAC interop: the handshake
/// completes (which includes decrypting the client's encrypted
/// SSH_MSG_SERVICE_REQUEST "ssh-userauth") and the client's subsequent
/// SSH_MSG_USERAUTH_REQUEST decrypts too. The client then fails auth (we
/// never implement userauth in part 1) — that is expected and not asserted.
fn liveOpensshClient(keygen_type: []const u8, hostkey_algo: []const u8, kex_name: []const u8, cipher_name: []const u8) !void {
    return liveOpensshClientMac(keygen_type, hostkey_algo, kex_name, cipher_name, "hmac-sha2-256");
}

/// `liveOpensshClient` with the client forced to `MACs=<mac_name>` (only
/// meaningful for a non-AEAD cipher).
fn liveOpensshClientMac(keygen_type: []const u8, hostkey_algo: []const u8, kex_name: []const u8, cipher_name: []const u8, mac_name: []const u8) !void {
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
    testFillRandom(&rnd);
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
            .argv = if (std.mem.eql(u8, keygen_type, "ecdsa384"))
                &.{ "ssh-keygen", "-q", "-t", "ecdsa", "-b", "384", "-N", "", "-C", "zig-ssh-live-test", "-f", hk_path }
            else
                &.{ "ssh-keygen", "-q", "-t", keygen_type, "-N", "", "-C", "zig-ssh-live-test", "-f", hk_path },
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
    var hk: HostKey = undefined;
    try HostKey.fromOpenSSH(&hk, key_text, null);
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
    const macs_opt = try std.fmt.allocPrint(gpa, "MACs={s}", .{mac_name});
    defer gpa.free(macs_opt);
    var ssh_child = std.process.spawn(io, .{
        .argv = &.{
            "/usr/bin/ssh",                  "-p",             port_str,                         "-F",
            "/dev/null",                     "-o",             "StrictHostKeyChecking=no",       "-o",
            "UserKnownHostsFile=/dev/null",  "-o",             "GlobalKnownHostsFile=/dev/null", "-o",
            "PreferredAuthentications=none", "-o",             "BatchMode=yes",                  "-o",
            macs_opt,                        "-o",             "ConnectTimeout=10",              "-o",
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
            .aes_ctr_hmac => try std.testing.expect(std.mem.endsWith(u8, cipher_name, "-ctr")),
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
        try std.testing.expectEqualStrings(mac_name, neg.mac_c2s.?);
        try std.testing.expectEqualStrings(mac_name, neg.mac_s2c.?);
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

test "live interop: OpenSSH ssh client → our server — aes128-ctr × every MAC (EtM and not)" {
    for (transport.mac_algorithms) |mac| {
        try liveOpensshClientMac("ed25519", "ssh-ed25519", "curve25519-sha256", "aes128-ctr", mac);
    }
}

test "live interop: OpenSSH ssh client → our server — aes256-ctr + hmac-sha2-512-etm@openssh.com" {
    try liveOpensshClientMac("ed25519", "ssh-ed25519", "curve25519-sha256", "aes256-ctr", "hmac-sha2-512-etm@openssh.com");
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

test "live interop: OpenSSH ssh client → our server — ecdsa-sha2-nistp384 host key" {
    try liveOpensshClient("ecdsa384", "ecdsa-sha2-nistp384", "ecdh-sha2-nistp384", "aes256-gcm@openssh.com");
}

test "live interop: OpenSSH ssh client → our server — diffie-hellman-group-exchange-sha256" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "diffie-hellman-group-exchange-sha256", "aes256-ctr");
}

test "live interop: OpenSSH ssh client → our server — ecdh-sha2-nistp256" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "ecdh-sha2-nistp256", "aes256-ctr");
}

test "live interop: OpenSSH ssh client → our server — ecdh-sha2-nistp384" {
    try liveOpensshClient("ed25519", "ssh-ed25519", "ecdh-sha2-nistp384", "chacha20-poly1305@openssh.com");
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
