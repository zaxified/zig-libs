// SPDX-License-Identifier: MIT
//! minisign — the minisign signature file format: Ed25519 sign/verify over the
//! `untrusted comment:` / base64-payload text framing used by
//! jedisct1/minisign, a compact GPG alternative for signing files/releases.
//!
//! **Wire format (confirmed against the minisign 0.12 C reference source
//! and cross-checked against real output from that binary — see
//! `kat_vectors.zig`):**
//!
//! - A **public key file** is 2 lines: `untrusted comment: ...` then
//!   base64(`RawPublicKey`) — `sig_alg(2) || key_number(8) || key(32)` = 42
//!   raw bytes, `sig_alg` always `"Ed"`.
//! - A **secret key file** is 2 lines: `untrusted comment: ...` then
//!   base64(`RawSecretKey`) — `sig_alg(2) || kdf_alg(2) || chk_alg(2) ||
//!   salt(32) || ops_limit_le(8) || mem_limit_le(8) || key_number(8) ||
//!   secret_key(64) || checksum(32)` = 158 raw bytes. `kdf_alg` is `"Sc"`
//!   (scrypt-encrypted) or all-zero (plaintext, `-W`); `chk_alg` is always
//!   `"B2"` (BLAKE2b-256).
//! - A **signature file** is 4 lines: `untrusted comment: ...`,
//!   base64(`RawSignature`) (`sig_alg(2) || key_number(8) || signature(64)`
//!   = 74 raw bytes), `trusted comment: ...`, base64(global signature, 64
//!   raw bytes).
//!
//! Two signature algorithms share the same key pair: **legacy `"Ed"`** signs
//! the raw file bytes directly; the modern default **prehashed `"ED"`**
//! signs the unkeyed **BLAKE2b-512** digest of the file instead (`-l` on the
//! CLI selects legacy; the CLI's `-H` flag *requires* the modern one). The
//! **global/"comment" signature** is a second, ordinary deterministic Ed25519
//! signature over `signature.signature (64 bytes) || trusted_comment_bytes`
//! (in that order, trusted comment has no trailing newline) — this is what
//! authenticates the trusted comment.
//!
//! A **secret key's checksum** (`chk`, BLAKE2b-256 over
//! `sig_alg || key_number || secret_key`, all plaintext) is computed **only
//! when a password is set**; an unencrypted (`-W`) secret key file has an
//! all-zero `chk` field that is never checked (this exactly matches the
//! reference `minisign.c`, which only calls `seckey_compute_chk` from inside
//! `encrypt_key`). Encryption XORs `key_number || secret_key || chk` (104
//! bytes) with a keystream of the same length from
//! `scrypt(password, salt)`; the file stores `ops_limit`/`mem_limit` as
//! 8-byte little-endian integers, **not** scrypt's own `(N, r, p)` — those
//! are derived from the two limits via libsodium's `pickparams` algorithm,
//! which Zig std already implements identically as
//! `std.crypto.pwhash.scrypt.Params.fromLimits` (this module reuses it
//! as-is; nothing is re-derived).
//!
//! **std recon (0.16.0)**: every primitive is already in std and used
//! directly — `std.crypto.sign.Ed25519` (KeyPair/Signature, deterministic
//! signing via `noise = null`, and its raw 64-byte `SecretKey` layout
//! `seed(32) || pubkey(32)` matches minisign's `sk` field byte-for-byte),
//! `std.crypto.hash.blake2.Blake2b512`/`Blake2b256`, `std.crypto.pwhash.
//! scrypt.{Params, kdf}` (RFC 7914 scrypt; `Params.fromLimits` already
//! matches libsodium's ops/mem-limit → N/r/p algorithm), and
//! `std.base64.standard` (RFC 4648 alphabet with `=` padding — the same
//! alphabet minisign's own hand-rolled `base64.c` uses). Nothing here is a
//! gap; no sibling module is needed.
//!
//! Note: multi-part incremental signing (`Ed25519.KeyPair.signer`/
//! `signerWithBaseNonce`) is deliberately **not** used for the global
//! signature — that API mixes in an extra random/caller-supplied base nonce
//! (needed for its own safety), so it does **not** reproduce the plain
//! deterministic `sign()` result over the same concatenated bytes. The
//! global signature is computed as one `sign()` call over a small
//! allocator-backed concatenation instead, which is what makes it byte-exact
//! against real `minisign`-generated fixtures.
//!
//! Provenance: clean-room from the minisign wire-format facts in
//! jedisct1/minisign's `minisign.h`/`minisign.c` (ISC License) — struct
//! layouts and algorithm-tag bytes are uncopyrightable format facts (merger
//! doctrine), independently re-derived and cross-checked byte-exact against
//! the real `minisign` 0.12 binary. ONE function is not clean-room: the
//! `isPrintableComment` control-character/UTF-8 validity check is a port of
//! minisign.c's `is_printable`, and `../NOTICE` carries the ISC attribution
//! it owes.

const std = @import("std");
const entropy = @import("entropy");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "jedisct1/minisign (C reference, ISC) + jedisct1/zig-minisign (ISC)",
    // entropy: the Ed25519 seed in `KeyPair.generate` — the only secret this
    // module mints. Everything else is std: std.crypto.sign.Ed25519,
    // std.crypto.hash.blake2, std.crypto.pwhash.scrypt, std.base64.
    .deps = .{"entropy"},
};

// ── field sizes (all format facts from minisign.h) ──────────────────────────

pub const key_number_length = 8;
pub const seed_length = 32;
pub const public_key_length = 32;
/// Ed25519 "sk" as libsodium/minisign lay it out: 32-byte seed || 32-byte
/// public key — identical to `std.crypto.sign.Ed25519.SecretKey`'s own byte
/// layout, so no repacking is needed in either direction.
pub const secret_key_length = 64;
pub const signature_length = 64;
/// BLAKE2b-256 checksum length (libsodium `crypto_generichash_BYTES`).
pub const checksum_length = 32;
/// scrypt salt length (libsodium `crypto_pwhash_scryptsalsa208sha256_SALTBYTES`).
pub const salt_length = 32;
/// BLAKE2b-512 prehash length (libsodium `crypto_generichash_BYTES_MAX`),
/// used as the signed message when `Algorithm.prehashed` is selected.
pub const prehash_length = 64;

// ── 2-byte algorithm tags (exact wire bytes) ─────────────────────────────────

pub const sig_alg_legacy: [2]u8 = "Ed".*;
pub const sig_alg_prehashed: [2]u8 = "ED".*;
pub const kdf_alg_scrypt: [2]u8 = "Sc".*;
pub const kdf_alg_none: [2]u8 = .{ 0, 0 };
pub const chk_alg_blake2b: [2]u8 = "B2".*;

/// Which bytes an individual (file) signature actually covers.
pub const Algorithm = enum {
    /// `"Ed"` — sign the raw file bytes directly (the CLI's `-l` flag).
    legacy,
    /// `"ED"` — sign the unkeyed BLAKE2b-512 digest of the file (the
    /// default since minisign 0.9; the CLI's `-H` flag requires this one).
    prehashed,

    pub fn tag(self: Algorithm) [2]u8 {
        return switch (self) {
            .legacy => sig_alg_legacy,
            .prehashed => sig_alg_prehashed,
        };
    }

    pub fn fromTag(t: [2]u8) ?Algorithm {
        if (std.mem.eql(u8, &t, &sig_alg_legacy)) return .legacy;
        if (std.mem.eql(u8, &t, &sig_alg_prehashed)) return .prehashed;
        return null;
    }
};

/// scrypt ops/mem limits as stored on the wire (the file does NOT store
/// `(N, r, p)` — see `std.crypto.pwhash.scrypt.Params.fromLimits`).
pub const ops_limit_interactive: u64 = 524288;
pub const mem_limit_interactive: usize = 16777216;
pub const ops_limit_sensitive: u64 = 33554432;
pub const mem_limit_sensitive: usize = 1073741824;

// ── raw on-wire structs (manual byte packing — no reliance on Zig struct layout) ──

pub const RawPublicKey = struct {
    sig_alg: [2]u8,
    key_number: [key_number_length]u8,
    key: [public_key_length]u8,

    pub const wire_length = 2 + key_number_length + public_key_length; // 42

    pub fn toBytes(self: RawPublicKey) [wire_length]u8 {
        var out: [wire_length]u8 = undefined;
        out[0..2].* = self.sig_alg;
        out[2..10].* = self.key_number;
        out[10..42].* = self.key;
        return out;
    }

    pub fn fromBytes(bytes: [wire_length]u8) RawPublicKey {
        return .{
            .sig_alg = bytes[0..2].*,
            .key_number = bytes[2..10].*,
            .key = bytes[10..42].*,
        };
    }
};

pub const RawSignature = struct {
    sig_alg: [2]u8,
    key_number: [key_number_length]u8,
    signature: [signature_length]u8,

    pub const wire_length = 2 + key_number_length + signature_length; // 74

    pub fn toBytes(self: RawSignature) [wire_length]u8 {
        var out: [wire_length]u8 = undefined;
        out[0..2].* = self.sig_alg;
        out[2..10].* = self.key_number;
        out[10..74].* = self.signature;
        return out;
    }

    pub fn fromBytes(bytes: [wire_length]u8) RawSignature {
        return .{
            .sig_alg = bytes[0..2].*,
            .key_number = bytes[2..10].*,
            .signature = bytes[10..74].*,
        };
    }
};

pub const RawSecretKey = struct {
    sig_alg: [2]u8,
    kdf_alg: [2]u8,
    chk_alg: [2]u8,
    salt: [salt_length]u8,
    ops_limit: u64,
    mem_limit: u64,
    key_number: [key_number_length]u8,
    /// Plaintext seed||pubkey if `kdf_alg == kdf_alg_none`, otherwise the
    /// scrypt-keystream-XORed ciphertext.
    secret_key: [secret_key_length]u8,
    /// All-zero if never encrypted (see the module doc comment); otherwise
    /// the (also XORed) BLAKE2b-256 self-check value.
    checksum: [checksum_length]u8,

    pub const wire_length = 2 + 2 + 2 + salt_length + 8 + 8 + key_number_length + secret_key_length + checksum_length; // 158

    pub fn toBytes(self: RawSecretKey) [wire_length]u8 {
        var out: [wire_length]u8 = undefined;
        var i: usize = 0;
        out[i..][0..2].* = self.sig_alg;
        i += 2;
        out[i..][0..2].* = self.kdf_alg;
        i += 2;
        out[i..][0..2].* = self.chk_alg;
        i += 2;
        out[i..][0..salt_length].* = self.salt;
        i += salt_length;
        std.mem.writeInt(u64, out[i..][0..8], self.ops_limit, .little);
        i += 8;
        std.mem.writeInt(u64, out[i..][0..8], self.mem_limit, .little);
        i += 8;
        out[i..][0..key_number_length].* = self.key_number;
        i += key_number_length;
        out[i..][0..secret_key_length].* = self.secret_key;
        i += secret_key_length;
        out[i..][0..checksum_length].* = self.checksum;
        i += checksum_length;
        std.debug.assert(i == wire_length);
        return out;
    }

    pub fn fromBytes(bytes: [wire_length]u8) RawSecretKey {
        var i: usize = 0;
        var out: RawSecretKey = undefined;
        out.sig_alg = bytes[i..][0..2].*;
        i += 2;
        out.kdf_alg = bytes[i..][0..2].*;
        i += 2;
        out.chk_alg = bytes[i..][0..2].*;
        i += 2;
        out.salt = bytes[i..][0..salt_length].*;
        i += salt_length;
        out.ops_limit = std.mem.readInt(u64, bytes[i..][0..8], .little);
        i += 8;
        out.mem_limit = std.mem.readInt(u64, bytes[i..][0..8], .little);
        i += 8;
        out.key_number = bytes[i..][0..key_number_length].*;
        i += key_number_length;
        out.secret_key = bytes[i..][0..secret_key_length].*;
        i += secret_key_length;
        out.checksum = bytes[i..][0..checksum_length].*;
        i += checksum_length;
        std.debug.assert(i == wire_length);
        return out;
    }
};

/// A fixed-size-binary <-> standard-base64 codec (RFC 4648 alphabet, `=`
/// padding — matches minisign's own hand-rolled `base64.c`).
fn Base64Codec(comptime wire_length: usize) type {
    const Encoder = std.base64.standard.Encoder;
    const Decoder = std.base64.standard.Decoder;
    return struct {
        pub const encoded_length = Encoder.calcSize(wire_length);

        pub fn encode(bytes: [wire_length]u8) [encoded_length]u8 {
            var out: [encoded_length]u8 = undefined;
            _ = Encoder.encode(&out, &bytes);
            return out;
        }

        pub fn decode(text: []const u8) error{ WrongLength, InvalidBase64 }![wire_length]u8 {
            if (text.len != encoded_length) return error.WrongLength;
            const decoded_len = Decoder.calcSizeForSlice(text) catch return error.InvalidBase64;
            if (decoded_len != wire_length) return error.InvalidBase64;
            var out: [wire_length]u8 = undefined;
            Decoder.decode(&out, text) catch return error.InvalidBase64;
            return out;
        }
    };
}

const PublicKeyCodec = Base64Codec(RawPublicKey.wire_length);
const SecretKeyCodec = Base64Codec(RawSecretKey.wire_length);
const SignatureCodec = Base64Codec(RawSignature.wire_length);
const GlobalSignatureCodec = Base64Codec(signature_length);

// ── text file framing ────────────────────────────────────────────────────────

pub const untrusted_comment_prefix = "untrusted comment: ";
pub const trusted_comment_prefix = "trusted comment: ";
pub const default_signature_comment = "signature from minisign secret key";
pub const default_secret_key_comment = "minisign encrypted secret key";
pub const public_key_comment_prefix = "minisign public key ";

/// Errors from parsing the line-based text format. Malformed input always
/// returns one of these — parsing never panics.
pub const FormatError = error{
    MissingLine,
    MissingUntrustedCommentPrefix,
    MissingTrustedCommentPrefix,
    WrongLength,
    InvalidBase64,
    UnsupportedAlgorithm,
    UnprintableComment,
    EmbeddedNewline,
};

fn trimCr(line: []const u8) []const u8 {
    if (line.len > 0 and line[line.len - 1] == '\r') return line[0 .. line.len - 1];
    return line;
}

fn nextLine(it: *std.mem.SplitIterator(u8, .scalar)) FormatError![]const u8 {
    const raw = it.next() orelse return error.MissingLine;
    return trimCr(raw);
}

fn containsNewline(text: []const u8) bool {
    for (text) |c| {
        if (c == '\n' or c == '\r') return true;
    }
    return false;
}

/// Faithful port of minisign.c's `is_printable`: ASCII tab/0x20-0x7E, or a
/// structurally-valid (non-overlong, non-surrogate) UTF-8 sequence; any
/// other control byte (including a bare high bit that doesn't start a valid
/// sequence) is rejected. Used to keep a maliciously-crafted trusted
/// comment from smuggling terminal escape sequences into a verifier's
/// output.
pub fn isPrintableComment(text: []const u8) bool {
    var i: usize = 0;
    while (i < text.len) {
        const c = text[i];
        if (c == '\t') {
            i += 1;
            continue;
        } else if (c >= 0x20 and c <= 0x7e) {
            i += 1;
            continue;
        } else if (c < 0x20 or c == 0x7f) {
            return false;
        }
        const need: usize = if (c >= 0xc2 and c <= 0xdf)
            1
        else if (c >= 0xe0 and c <= 0xef)
            2
        else if (c >= 0xf0 and c <= 0xf4)
            3
        else
            return false;
        if (i + need >= text.len) return false;
        var j: usize = 1;
        while (j <= need) : (j += 1) {
            const cc = text[i + j];
            if (cc == 0 or (cc & 0xc0) != 0x80) return false;
        }
        const p0 = text[i + 1];
        if ((c == 0xe0 and p0 < 0xa0) or (c == 0xed and p0 > 0x9f) or
            (c == 0xf0 and p0 < 0x90) or (c == 0xf4 and p0 > 0x8f)) return false;
        var cp: u32 = c & (if (need == 1) @as(u32, 0x1f) else if (need == 2) @as(u32, 0x0f) else @as(u32, 0x07));
        j = 1;
        while (j <= need) : (j += 1) cp = (cp << 6) | (text[i + j] & 0x3f);
        if (cp <= 0x1f or (cp >= 0x7f and cp <= 0x9f)) return false;
        i += need + 1;
    }
    return true;
}

pub const ParsedPublicKey = struct {
    untrusted_comment: []const u8,
    key: RawPublicKey,
};

/// Parse a 2-line public key file (`untrusted comment: ...` + base64). The
/// returned comment is a slice into `text` — valid as long as `text` lives.
pub fn parsePublicKeyFile(text: []const u8) FormatError!ParsedPublicKey {
    var it = std.mem.splitScalar(u8, text, '\n');
    const comment_line = try nextLine(&it);
    if (!std.mem.startsWith(u8, comment_line, untrusted_comment_prefix))
        return error.MissingUntrustedCommentPrefix;
    const b64_line = try nextLine(&it);
    const key = RawPublicKey.fromBytes(try PublicKeyCodec.decode(b64_line));
    if (!std.mem.eql(u8, &key.sig_alg, &sig_alg_legacy)) return error.UnsupportedAlgorithm;
    return .{ .untrusted_comment = comment_line[untrusted_comment_prefix.len..], .key = key };
}

/// Parse the compact `-P <base64>` inline public key form (no comment
/// framing, just the base64 struct).
pub fn parsePublicKeyBase64(text: []const u8) FormatError!RawPublicKey {
    const key = RawPublicKey.fromBytes(try PublicKeyCodec.decode(text));
    if (!std.mem.eql(u8, &key.sig_alg, &sig_alg_legacy)) return error.UnsupportedAlgorithm;
    return key;
}

pub const ParsedSecretKey = struct {
    untrusted_comment: []const u8,
    key: RawSecretKey,
};

/// Parse a 2-line secret key file. Does not decrypt — see `openSecretKey`.
pub fn parseSecretKeyFile(text: []const u8) FormatError!ParsedSecretKey {
    var it = std.mem.splitScalar(u8, text, '\n');
    const comment_line = try nextLine(&it);
    if (!std.mem.startsWith(u8, comment_line, untrusted_comment_prefix))
        return error.MissingUntrustedCommentPrefix;
    const b64_line = try nextLine(&it);
    const key = RawSecretKey.fromBytes(try SecretKeyCodec.decode(b64_line));
    if (!std.mem.eql(u8, &key.sig_alg, &sig_alg_legacy)) return error.UnsupportedAlgorithm;
    if (!std.mem.eql(u8, &key.chk_alg, &chk_alg_blake2b)) return error.UnsupportedAlgorithm;
    if (!std.mem.eql(u8, &key.kdf_alg, &kdf_alg_scrypt) and !std.mem.eql(u8, &key.kdf_alg, &kdf_alg_none))
        return error.UnsupportedAlgorithm;
    return .{ .untrusted_comment = comment_line[untrusted_comment_prefix.len..], .key = key };
}

pub const ParsedSignature = struct {
    untrusted_comment: []const u8,
    signature: RawSignature,
    algorithm: Algorithm,
    trusted_comment: []const u8,
    global_signature: [signature_length]u8,
};

/// Parse a 4-line signature file. The trusted comment is validated with
/// `isPrintableComment` (matching the reference's own guard before it is
/// ever echoed to a terminal).
pub fn parseSignatureFile(text: []const u8) FormatError!ParsedSignature {
    var it = std.mem.splitScalar(u8, text, '\n');
    const comment_line = try nextLine(&it);
    if (!std.mem.startsWith(u8, comment_line, untrusted_comment_prefix))
        return error.MissingUntrustedCommentPrefix;
    const sig_b64 = try nextLine(&it);
    const signature = RawSignature.fromBytes(try SignatureCodec.decode(sig_b64));
    const algorithm = Algorithm.fromTag(signature.sig_alg) orelse return error.UnsupportedAlgorithm;

    const trusted_line = try nextLine(&it);
    if (!std.mem.startsWith(u8, trusted_line, trusted_comment_prefix))
        return error.MissingTrustedCommentPrefix;
    const trusted_comment = trusted_line[trusted_comment_prefix.len..];
    if (!isPrintableComment(trusted_comment)) return error.UnprintableComment;

    const gsig_b64 = try nextLine(&it);
    const global_signature = try GlobalSignatureCodec.decode(gsig_b64);

    return .{
        .untrusted_comment = comment_line[untrusted_comment_prefix.len..],
        .signature = signature,
        .algorithm = algorithm,
        .trusted_comment = trusted_comment,
        .global_signature = global_signature,
    };
}

// ── writers (encode side) ────────────────────────────────────────────────────

fn checkComment(comment: []const u8) FormatError!void {
    if (containsNewline(comment)) return error.EmbeddedNewline;
}

pub fn writePublicKeyFile(w: *std.Io.Writer, untrusted_comment: []const u8, key: RawPublicKey) !void {
    try checkComment(untrusted_comment);
    try w.print("{s}{s}\n", .{ untrusted_comment_prefix, untrusted_comment });
    try w.print("{s}\n", .{PublicKeyCodec.encode(key.toBytes())});
}

pub fn writeSecretKeyFile(w: *std.Io.Writer, untrusted_comment: []const u8, key: RawSecretKey) !void {
    try checkComment(untrusted_comment);
    try w.print("{s}{s}\n", .{ untrusted_comment_prefix, untrusted_comment });
    try w.print("{s}\n", .{SecretKeyCodec.encode(key.toBytes())});
}

pub fn writeSignatureFile(
    w: *std.Io.Writer,
    untrusted_comment: []const u8,
    signature: RawSignature,
    trusted_comment: []const u8,
    global_signature: [signature_length]u8,
) !void {
    try checkComment(untrusted_comment);
    try checkComment(trusted_comment);
    if (!isPrintableComment(trusted_comment)) return error.UnprintableComment;
    try w.print("{s}{s}\n", .{ untrusted_comment_prefix, untrusted_comment });
    try w.print("{s}\n", .{SignatureCodec.encode(signature.toBytes())});
    try w.print("{s}{s}\n", .{ trusted_comment_prefix, trusted_comment });
    try w.print("{s}\n", .{GlobalSignatureCodec.encode(global_signature)});
}

/// Format a key number as the uppercase 16-hex-digit key id the CLI prints
/// (`le64_load(key_number)`, i.e. the bytes read as a little-endian u64).
pub fn formatKeyId(key_number: [key_number_length]u8) [16]u8 {
    const v = std.mem.readInt(u64, &key_number, .little);
    var out: [16]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{X:0>16}", .{v}) catch unreachable;
    return out;
}

// ── checksum ──────────────────────────────────────────────────────────────────

fn computeChecksum(
    out: *[checksum_length]u8,
    sig_alg: [2]u8,
    key_number: [key_number_length]u8,
    secret_key: [secret_key_length]u8,
) void {
    var h = std.crypto.hash.blake2.Blake2b256.init(.{});
    h.update(&sig_alg);
    h.update(&key_number);
    h.update(&secret_key);
    h.final(out);
}

// ── key pair ──────────────────────────────────────────────────────────────────

pub const KeyPair = struct {
    key_number: [key_number_length]u8,
    ed25519: std.crypto.sign.Ed25519.KeyPair,

    /// Generate a fresh random key pair (fresh random key number too).
    ///
    /// The two draws below are deliberately NOT the same call. `key_number`
    /// is published in the clear in every `.pub`/`.sig` file — it is an
    /// identifier, not a secret, and `io.random` is the right source for
    /// it. The Ed25519 seed is the signing key for every release this key
    /// will ever sign, so it is fail-closed (CONVENTIONS.md §2.2).
    pub fn generate(io: std.Io) KeyPair {
        var key_number: [key_number_length]u8 = undefined;
        io.random(&key_number);

        // std's `Ed25519.KeyPair.generate`, verbatim except that the seed
        // comes from `entropy.fill` rather than `io.random`.
        var seed: [std.crypto.sign.Ed25519.KeyPair.seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        while (true) {
            entropy.fill(io, &seed);
            const ed25519 = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch {
                @branchHint(.unlikely);
                continue;
            };
            return .{ .key_number = key_number, .ed25519 = ed25519 };
        }
    }

    pub fn publicKey(self: KeyPair) RawPublicKey {
        return .{
            .sig_alg = sig_alg_legacy,
            .key_number = self.key_number,
            .key = self.ed25519.public_key.toBytes(),
        };
    }

    /// The on-disk secret key struct for an unencrypted (`-W`) key: `chk`
    /// is left all-zero (see the module doc comment — the reference never
    /// computes it in this path, and never checks it either).
    pub fn toRawSecretKeyPlain(self: KeyPair) RawSecretKey {
        return .{
            .sig_alg = sig_alg_legacy,
            .kdf_alg = kdf_alg_none,
            .chk_alg = chk_alg_blake2b,
            .salt = std.mem.zeroes([salt_length]u8),
            .ops_limit = 0,
            .mem_limit = 0,
            .key_number = self.key_number,
            .secret_key = self.ed25519.secret_key.toBytes(),
            .checksum = std.mem.zeroes([checksum_length]u8),
        };
    }

    /// Destroy the long-term Ed25519 secret key held by this struct
    /// (CONVENTIONS §2.1 Z1). Call it once signing is finished — a `KeyPair`
    /// recovered by `openSecretKey` is the decrypted form of the on-disk key,
    /// and it lives exactly as long as the caller keeps this value.
    ///
    /// The public key and key number are left intact: neither is secret, and
    /// both stay useful for logging which key was retired.
    pub fn wipe(self: *KeyPair) void {
        std.crypto.secureZero(u8, &self.ed25519.secret_key.bytes);
    }
};

/// scrypt-keystream length: `key_number || secret_key || checksum`.
const encrypted_block_length = key_number_length + secret_key_length + checksum_length; // 104

/// Encrypt `key_pair` with `password` into the on-disk `RawSecretKey` form.
/// `ops_limit`/`mem_limit` pick the scrypt cost (`ops_limit_sensitive`/
/// `mem_limit_sensitive` are the CLI's own defaults); the wire format stores
/// these two limits, not derived `(N, r, p)` — see the module doc comment.
pub fn sealSecretKey(
    allocator: std.mem.Allocator,
    key_pair: KeyPair,
    password: []const u8,
    salt: [salt_length]u8,
    ops_limit: u64,
    mem_limit: usize,
) !RawSecretKey {
    const plain_key_number = key_pair.key_number;
    // CONVENTIONS §2.1 Z1: our own copies of the plaintext secret key, its
    // checksum, and the scrypt keystream that encrypts them. Every `defer` is
    // registered before the fallible `kdf` call so no error path skips one.
    var plain_sk = key_pair.ed25519.secret_key.toBytes();
    defer std.crypto.secureZero(u8, &plain_sk);
    var plain_chk: [checksum_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain_chk);
    computeChecksum(&plain_chk, sig_alg_legacy, plain_key_number, plain_sk);

    const params = std.crypto.pwhash.scrypt.Params.fromLimits(ops_limit, mem_limit);
    var stream: [encrypted_block_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &stream);
    try std.crypto.pwhash.scrypt.kdf(allocator, &stream, password, &salt, params);

    var raw: RawSecretKey = .{
        .sig_alg = sig_alg_legacy,
        .kdf_alg = kdf_alg_scrypt,
        .chk_alg = chk_alg_blake2b,
        .salt = salt,
        .ops_limit = ops_limit,
        .mem_limit = mem_limit,
        .key_number = undefined,
        .secret_key = undefined,
        .checksum = undefined,
    };
    for (&raw.key_number, 0..) |*b, i| b.* = plain_key_number[i] ^ stream[i];
    for (&raw.secret_key, 0..) |*b, i| b.* = plain_sk[i] ^ stream[key_number_length + i];
    for (&raw.checksum, 0..) |*b, i| b.* = plain_chk[i] ^ stream[key_number_length + secret_key_length + i];
    return raw;
}

pub const OpenSecretKeyError = error{
    UnsupportedSignatureAlgorithm,
    UnsupportedChecksumAlgorithm,
    UnsupportedKdf,
    PasswordRequired,
    WrongPassword,
};

/// Decrypt (if needed) and load a `RawSecretKey`. Pass `password = null`
/// only for an unencrypted (`kdf_alg_none`) key — its `chk` is not checked,
/// exactly like the reference. A wrong password is a typed
/// `error.WrongPassword`, never a panic or silently-wrong key.
pub fn openSecretKey(
    allocator: std.mem.Allocator,
    raw: RawSecretKey,
    password: ?[]const u8,
) !KeyPair {
    if (!std.mem.eql(u8, &raw.sig_alg, &sig_alg_legacy)) return error.UnsupportedSignatureAlgorithm;
    if (!std.mem.eql(u8, &raw.chk_alg, &chk_alg_blake2b)) return error.UnsupportedChecksumAlgorithm;

    var key_number = raw.key_number;
    // CONVENTIONS §2.1 Z1 — the recovered plaintext secret key. The `defer`
    // runs after the return operand is built, so the returned `KeyPair` still
    // carries the key while this frame's copy does not.
    var sk_bytes = raw.secret_key;
    defer std.crypto.secureZero(u8, &sk_bytes);

    if (std.mem.eql(u8, &raw.kdf_alg, &kdf_alg_none)) {
        // Plaintext; chk intentionally unchecked (see module doc comment).
    } else if (std.mem.eql(u8, &raw.kdf_alg, &kdf_alg_scrypt)) {
        const pw = password orelse return error.PasswordRequired;
        const params = std.crypto.pwhash.scrypt.Params.fromLimits(raw.ops_limit, raw.mem_limit);
        var stream: [encrypted_block_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &stream);
        try std.crypto.pwhash.scrypt.kdf(allocator, &stream, pw, &raw.salt, params);

        var plain_key_number: [key_number_length]u8 = undefined;
        var plain_sk: [secret_key_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain_sk);
        var plain_chk: [checksum_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain_chk);
        for (&plain_key_number, 0..) |*b, i| b.* = raw.key_number[i] ^ stream[i];
        for (&plain_sk, 0..) |*b, i| b.* = raw.secret_key[i] ^ stream[key_number_length + i];
        for (&plain_chk, 0..) |*b, i| b.* = raw.checksum[i] ^ stream[key_number_length + secret_key_length + i];

        var computed_chk: [checksum_length]u8 = undefined;
        computeChecksum(&computed_chk, raw.sig_alg, plain_key_number, plain_sk);
        if (!std.crypto.timing_safe.eql([checksum_length]u8, computed_chk, plain_chk))
            return error.WrongPassword;

        key_number = plain_key_number;
        sk_bytes = plain_sk;
    } else return error.UnsupportedKdf;

    const secret_key = try std.crypto.sign.Ed25519.SecretKey.fromBytes(sk_bytes);
    return .{ .key_number = key_number, .ed25519 = try std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) };
}

// ── message signing / verification ───────────────────────────────────────────

fn prehash(message: []const u8) [prehash_length]u8 {
    var digest: [prehash_length]u8 = undefined;
    std.crypto.hash.blake2.Blake2b512.hash(message, &digest, .{});
    return digest;
}

/// Sign `message` (deterministic Ed25519 — `noise = null`, matching the
/// reference's own deterministic `crypto_sign_detached`).
pub fn signMessage(key_pair: KeyPair, message: []const u8, algorithm: Algorithm) !RawSignature {
    const signed_bytes: []const u8 = switch (algorithm) {
        .legacy => message,
        .prehashed => &prehash(message),
    };
    const sig = try key_pair.ed25519.sign(signed_bytes, null);
    return .{ .sig_alg = algorithm.tag(), .key_number = key_pair.key_number, .signature = sig.toBytes() };
}

pub const VerifyMessageError = error{KeyIdMismatch} || error{UnsupportedAlgorithm} ||
    std.crypto.sign.Ed25519.Signature.VerifyError || std.crypto.errors.EncodingError;

/// Verify `sig` was produced by `public_key` over `message`. Checks the key
/// id too (a mismatched id is `error.KeyIdMismatch`, distinct from a bad
/// signature).
pub fn verifyMessage(public_key: RawPublicKey, message: []const u8, sig: RawSignature) VerifyMessageError!void {
    if (!std.mem.eql(u8, &sig.key_number, &public_key.key_number)) return error.KeyIdMismatch;
    const algorithm = Algorithm.fromTag(sig.sig_alg) orelse return error.UnsupportedAlgorithm;
    const pk = try std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key.key);
    const signature = std.crypto.sign.Ed25519.Signature.fromBytes(sig.signature);
    const signed_bytes: []const u8 = switch (algorithm) {
        .legacy => message,
        .prehashed => &prehash(message),
    };
    try signature.verify(signed_bytes, pk);
}

/// Sign the trusted comment: a second, ordinary deterministic Ed25519
/// signature over `signature.signature (64 bytes) || trusted_comment`, in
/// that order. Allocates a small scratch buffer for the concatenation
/// (needed for byte-exact parity with the reference's single `sign()` call
/// — see the module doc comment on why the incremental `Signer` API is not
/// used here).
pub fn signTrustedComment(
    allocator: std.mem.Allocator,
    key_pair: KeyPair,
    signature: RawSignature,
    trusted_comment: []const u8,
) ![signature_length]u8 {
    const buf = try allocator.alloc(u8, signature_length + trusted_comment.len);
    defer allocator.free(buf);
    @memcpy(buf[0..signature_length], &signature.signature);
    @memcpy(buf[signature_length..], trusted_comment);
    const sig = try key_pair.ed25519.sign(buf, null);
    return sig.toBytes();
}

/// Verify the global (trusted-comment) signature.
pub fn verifyTrustedComment(
    allocator: std.mem.Allocator,
    public_key: RawPublicKey,
    signature: RawSignature,
    trusted_comment: []const u8,
    global_signature: [signature_length]u8,
) !void {
    const buf = try allocator.alloc(u8, signature_length + trusted_comment.len);
    defer allocator.free(buf);
    @memcpy(buf[0..signature_length], &signature.signature);
    @memcpy(buf[signature_length..], trusted_comment);
    const pk = try std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key.key);
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(global_signature);
    try sig.verify(buf, pk);
}

pub const SignedFile = struct {
    signature: RawSignature,
    global_signature: [signature_length]u8,
};

/// Sign both layers at once: the message (under `algorithm`) and the
/// trusted comment. Pass the result + `trusted_comment` to
/// `writeSignatureFile`.
pub fn signFile(
    allocator: std.mem.Allocator,
    key_pair: KeyPair,
    message: []const u8,
    algorithm: Algorithm,
    trusted_comment: []const u8,
) !SignedFile {
    const sig = try signMessage(key_pair, message, algorithm);
    const gsig = try signTrustedComment(allocator, key_pair, sig, trusted_comment);
    return .{ .signature = sig, .global_signature = gsig };
}

/// Verify both layers of a parsed signature file against `message`: the
/// message/key-id layer, then the trusted-comment layer.
pub fn verifyFile(
    allocator: std.mem.Allocator,
    public_key: RawPublicKey,
    message: []const u8,
    parsed: ParsedSignature,
) !void {
    try verifyMessage(public_key, message, parsed.signature);
    try verifyTrustedComment(
        allocator,
        public_key,
        parsed.signature,
        parsed.trusted_comment,
        parsed.global_signature,
    );
}

// ── tests ────────────────────────────────────────────────────────────────────

test "RawPublicKey/RawSignature/RawSecretKey byte round-trip" {
    var pk: RawPublicKey = .{ .sig_alg = sig_alg_legacy, .key_number = undefined, .key = undefined };
    for (&pk.key_number, 0..) |*b, i| b.* = @intCast(i);
    for (&pk.key, 0..) |*b, i| b.* = @intCast(0xa0 + i);
    try std.testing.expectEqual(pk, RawPublicKey.fromBytes(pk.toBytes()));

    var sig: RawSignature = .{ .sig_alg = sig_alg_prehashed, .key_number = pk.key_number, .signature = undefined };
    for (&sig.signature, 0..) |*b, i| b.* = @intCast(i);
    try std.testing.expectEqual(sig, RawSignature.fromBytes(sig.toBytes()));

    var sk: RawSecretKey = .{
        .sig_alg = sig_alg_legacy,
        .kdf_alg = kdf_alg_scrypt,
        .chk_alg = chk_alg_blake2b,
        .salt = undefined,
        .ops_limit = ops_limit_sensitive,
        .mem_limit = mem_limit_sensitive,
        .key_number = pk.key_number,
        .secret_key = undefined,
        .checksum = undefined,
    };
    for (&sk.salt, 0..) |*b, i| b.* = @intCast(i);
    for (&sk.secret_key, 0..) |*b, i| b.* = @intCast(i);
    for (&sk.checksum, 0..) |*b, i| b.* = @intCast(i);
    try std.testing.expectEqual(sk, RawSecretKey.fromBytes(sk.toBytes()));
}

test "sign/verify round-trip, both algorithms, plus tamper + wrong-key-id" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const kp = KeyPair.generate(io);
    const pk = kp.publicKey();
    const msg = "round-trip message";

    inline for ([_]Algorithm{ .legacy, .prehashed }) |algo| {
        const signed = try signFile(gpa, kp, msg, algo, "trusted comment");
        try verifyMessage(pk, msg, signed.signature);
        try verifyTrustedComment(gpa, pk, signed.signature, "trusted comment", signed.global_signature);

        // tampered payload
        try std.testing.expectError(error.SignatureVerificationFailed, verifyMessage(pk, "tampered message", signed.signature));
        // tampered trusted comment
        try std.testing.expectError(
            error.SignatureVerificationFailed,
            verifyTrustedComment(gpa, pk, signed.signature, "different comment", signed.global_signature),
        );
        // wrong key id
        var wrong_sig = signed.signature;
        wrong_sig.key_number[0] ^= 0xff;
        try std.testing.expectError(error.KeyIdMismatch, verifyMessage(pk, msg, wrong_sig));
    }
}

test "unencrypted secret key: seal is a no-op wrapper, chk stays zero, openSecretKey needs no password" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const kp = KeyPair.generate(io);
    const raw = kp.toRawSecretKeyPlain();
    try std.testing.expectEqualSlices(u8, &kdf_alg_none, &raw.kdf_alg);
    try std.testing.expectEqual(std.mem.zeroes([checksum_length]u8), raw.checksum);

    const opened = try openSecretKey(gpa, raw, null);
    try std.testing.expectEqual(kp.key_number, opened.key_number);
    try std.testing.expectEqual(kp.ed25519.secret_key.toBytes(), opened.ed25519.secret_key.toBytes());
}

test "encrypted secret key: seal + open round-trip, wrong password rejected" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const kp = KeyPair.generate(io);
    var salt: [salt_length]u8 = undefined;
    io.random(&salt);

    // Cheapest legal scrypt cost so the test runs fast (`OPSLIMIT_MIN` per
    // libsodium is 32768; pair it with a small memlimit so `fromLimits`
    // lands on a tiny N).
    const raw = try sealSecretKey(gpa, kp, "correct password", salt, 32768, 1 << 16);
    try std.testing.expectEqualSlices(u8, &kdf_alg_scrypt, &raw.kdf_alg);

    const opened = try openSecretKey(gpa, raw, "correct password");
    try std.testing.expectEqual(kp.key_number, opened.key_number);
    try std.testing.expectEqual(kp.ed25519.secret_key.toBytes(), opened.ed25519.secret_key.toBytes());

    try std.testing.expectError(error.WrongPassword, openSecretKey(gpa, raw, "wrong password"));
    try std.testing.expectError(error.PasswordRequired, openSecretKey(gpa, raw, null));
}

test "openSecretKey rejects an unrecognized sig_alg/chk_alg/kdf_alg tag" {
    // Three typed rejections, none of which any earlier test ever drove:
    // `UnsupportedSignatureAlgorithm`/`UnsupportedChecksumAlgorithm`/
    // `UnsupportedKdf` all guard fields that come straight off the wire
    // (an attacker- or corruption-controlled key file), so "delete the
    // check" is a real, silent reachable bug class here, not just
    // defense-in-depth against this module's own constructors.
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const kp = KeyPair.generate(io);
    const raw = kp.toRawSecretKeyPlain();

    var bad_sig_alg = raw;
    bad_sig_alg.sig_alg = .{ 'X', 'X' };
    try std.testing.expectError(error.UnsupportedSignatureAlgorithm, openSecretKey(gpa, bad_sig_alg, null));

    var bad_chk_alg = raw;
    bad_chk_alg.chk_alg = .{ 'X', 'X' };
    try std.testing.expectError(error.UnsupportedChecksumAlgorithm, openSecretKey(gpa, bad_chk_alg, null));

    var bad_kdf_alg = raw;
    bad_kdf_alg.kdf_alg = .{ 'X', 'X' };
    try std.testing.expectError(error.UnsupportedKdf, openSecretKey(gpa, bad_kdf_alg, "some password"));
}

// Regression (audit W2 `minisign` F3): only `openSecretKey`'s three tag
// rejections had a test; the signature-file and public-key-file
// `UnsupportedAlgorithm` reject paths (`parseSignatureFile`'s `sig_alg`
// dispatch, `parsePublicKeyFile`'s `sig_alg` check) had none. Not exploitable
// today — `verifyMessage` re-derives the algorithm from the tag independently
// and fails closed on its own — but an untested reject path is a real gap:
// deleting either check would have gone unnoticed.
test "parseSignatureFile rejects an unrecognized sig_alg tag" {
    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const sig: RawSignature = .{ .sig_alg = .{ 'X', 'X' }, .key_number = @splat(0), .signature = @splat(0) };
    try writeSignatureFile(&w, "comment", sig, "trusted comment", @splat(0));
    try std.testing.expectError(error.UnsupportedAlgorithm, parseSignatureFile(w.buffered()));
}

test "parsePublicKeyFile rejects an unrecognized sig_alg tag" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const pk: RawPublicKey = .{ .sig_alg = .{ 'X', 'X' }, .key_number = @splat(0), .key = @splat(0) };
    try writePublicKeyFile(&w, "comment", pk);
    try std.testing.expectError(error.UnsupportedAlgorithm, parsePublicKeyFile(w.buffered()));
}

test "parsePublicKeyBase64 rejects an unrecognized sig_alg tag" {
    const pk: RawPublicKey = .{ .sig_alg = .{ 'X', 'X' }, .key_number = @splat(0), .key = @splat(0) };
    const b64 = PublicKeyCodec.encode(pk.toBytes());
    try std.testing.expectError(error.UnsupportedAlgorithm, parsePublicKeyBase64(&b64));
}

test "parse: truncated / missing-line signature file, missing prefixes" {
    // Empty text still yields one (empty) "line" from the split iterator,
    // so this fails the prefix check, not a missing-line check.
    try std.testing.expectError(error.MissingUntrustedCommentPrefix, parseSignatureFile(""));
    // One real line with no trailing newline: the b64 line is genuinely
    // absent (the iterator returns null, not an empty final segment).
    try std.testing.expectError(error.MissingLine, parseSignatureFile("untrusted comment: x"));
    try std.testing.expectError(
        error.MissingUntrustedCommentPrefix,
        parseSignatureFile("not the prefix\nAAAA\ntrusted comment: x\nAAAA\n"),
    );
}

test "writePublicKeyFile / writeSignatureFile reject embedded newlines" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const pk: RawPublicKey = .{ .sig_alg = sig_alg_legacy, .key_number = @splat(0), .key = @splat(0) };
    try std.testing.expectError(error.EmbeddedNewline, writePublicKeyFile(&w, "bad\ncomment", pk));

    const sig: RawSignature = .{ .sig_alg = sig_alg_prehashed, .key_number = @splat(0), .signature = @splat(0) };
    try std.testing.expectError(
        error.EmbeddedNewline,
        writeSignatureFile(&w, "ok", sig, "bad\ntrusted", @splat(0)),
    );
}

test "isPrintableComment: control chars and truncated UTF-8 rejected, valid UTF-8 accepted" {
    try std.testing.expect(isPrintableComment("plain ASCII, a tab\there"));
    try std.testing.expect(isPrintableComment("caf\xc3\xa9")); // "café", valid 2-byte UTF-8
    try std.testing.expect(!isPrintableComment("bad\x01byte"));
    try std.testing.expect(!isPrintableComment("del\x7f"));
    try std.testing.expect(!isPrintableComment("truncated\xc3"));
    try std.testing.expect(!isPrintableComment("overlong\xc0\x80"));
}

test "formatKeyId matches the CLI's le64-hex convention" {
    // Bytes as they appear on the wire for key id "5903374ED1B3A96B" (a real
    // fixture key number — see kat_vectors.zig).
    const key_number: [8]u8 = .{ 0x6b, 0xa9, 0xb3, 0xd1, 0x4e, 0x37, 0x03, 0x59 };
    try std.testing.expectEqualStrings("5903374ED1B3A96B", &formatKeyId(key_number));
}

// ── fuzz: parseSignatureFile never panics on an arbitrary signature file ──
//
// A `.minisig` file is exactly what an attacker hands a verifier: 4
// newline-separated lines (comment/base64-signature/comment/base64-
// global-signature) that `parseSignatureFile` splits and base64-decodes
// with no prior validation. Plain random bytes would almost always die on
// the very first `MissingUntrustedCommentPrefix` check -- so this harness
// builds a structurally-real 4-line skeleton (correct line prefixes, a
// real base64-encoded `RawSignature`/global-signature payload built via
// this file's own codecs) and only randomizes the comment text and the
// two payloads' actual bytes/lengths, which is what drives the parser
// into the base64-length/algorithm-tag/printable-comment checks instead
// of bouncing off the first line every time.
test "fuzz: parseSignatureFile never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzParseSignatureFile, .{});
}

fn fuzzB64Line(smith: *std.testing.Smith, comptime wire_length: usize, out: *[Base64Codec(wire_length).encoded_length]u8) []const u8 {
    const Codec = Base64Codec(wire_length);
    if (smith.value(bool)) {
        // A real base64-encoded payload of correct length, random content.
        var raw: [wire_length]u8 = undefined;
        smith.bytes(&raw);
        out.* = Codec.encode(raw);
        return out;
    }
    // Garbage of arbitrary length -- exercises WrongLength/InvalidBase64.
    var buf: [Codec.encoded_length + 16]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    @memcpy(out[0..@min(len, out.len)], buf[0..@min(len, out.len)]);
    return out[0..@min(len, out.len)];
}

fn fuzzParseSignatureFile(_: void, smith: *std.testing.Smith) !void {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(std.testing.allocator);
    const allocator = std.testing.allocator;

    try text.appendSlice(allocator, untrusted_comment_prefix);
    var comment_buf: [32]u8 = undefined;
    smith.bytes(&comment_buf);
    const comment_len: usize = smith.valueRangeAtMost(u8, 0, comment_buf.len);
    try text.appendSlice(allocator, comment_buf[0..comment_len]);
    try text.append(allocator, '\n');

    var sig_out: [SignatureCodec.encoded_length]u8 = undefined;
    try text.appendSlice(allocator, fuzzB64Line(smith, RawSignature.wire_length, &sig_out));
    try text.append(allocator, '\n');

    try text.appendSlice(allocator, trusted_comment_prefix);
    var trusted_buf: [32]u8 = undefined;
    smith.bytes(&trusted_buf);
    const trusted_len: usize = smith.valueRangeAtMost(u8, 0, trusted_buf.len);
    try text.appendSlice(allocator, trusted_buf[0..trusted_len]);
    try text.append(allocator, '\n');

    var gsig_out: [GlobalSignatureCodec.encoded_length]u8 = undefined;
    try text.appendSlice(allocator, fuzzB64Line(smith, signature_length, &gsig_out));
    if (smith.value(bool)) try text.append(allocator, '\n');

    _ = parseSignatureFile(text.items) catch return;
}

// ── fuzz: isPrintableComment never panics/OOB-reads on arbitrary bytes ───
//
// A hand-rolled UTF-8 validator (ported from minisign.c's `is_printable`)
// with its own byte-length/continuation-byte bookkeeping (`i + need >=
// text.len`, overlong/surrogate range checks) -- exactly the shape of
// parser most prone to an off-by-one OOB read, and it runs directly over
// the trusted-comment bytes of an attacker-supplied signature file before
// `parseSignatureFile` ever echoes them anywhere.
test "fuzz: isPrintableComment never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzIsPrintableComment, .{});
}

fn fuzzIsPrintableComment(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    _ = isPrintableComment(buf[0..len]);
}

test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "KeyPair.wipe destroys the long-term secret key, leaving the public half usable" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const kp = KeyPair.generate(io);
    var salt: [salt_length]u8 = undefined;
    io.random(&salt);

    const raw = try sealSecretKey(gpa, kp, "pw", salt, 32768, 1 << 16);
    var opened = try openSecretKey(gpa, raw, "pw");

    // Precondition: the recovered key really is the on-disk key, so the
    // assertion below is about the wipe and not about a key that was never
    // there in the first place.
    const zero = std.mem.zeroes([std.crypto.sign.Ed25519.SecretKey.encoded_length]u8);
    try std.testing.expectEqual(kp.ed25519.secret_key.toBytes(), opened.ed25519.secret_key.toBytes());
    try std.testing.expect(!std.mem.eql(u8, &zero, &opened.ed25519.secret_key.bytes));

    opened.wipe();

    try std.testing.expectEqualSlices(u8, &zero, &opened.ed25519.secret_key.bytes);
    // Not secret — the wipe must leave the identity of the retired key legible.
    try std.testing.expectEqual(kp.key_number, opened.key_number);
    try std.testing.expectEqual(
        kp.ed25519.public_key.toBytes(),
        opened.ed25519.public_key.toBytes(),
    );
}
