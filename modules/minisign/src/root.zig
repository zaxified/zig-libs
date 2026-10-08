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
const burn = @import("burn.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "minisign file format (jedisct1/minisign) — Ed25519 sign/verify for signed files/releases, including scrypt-encrypted secret keys.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .windows },
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

    /// Serialize into `out` (secret: the plaintext key for `kdf_alg_none`).
    pub fn toBytes(self: *const RawSecretKey, out: *[wire_length]u8) void {
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
    }

    /// Parse `bytes` into `out` (every field is written).
    pub fn fromBytes(out: *RawSecretKey, bytes: *const [wire_length]u8) void {
        var i: usize = 0;
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
            encodeInto(&out, &bytes);
            return out;
        }

        /// By pointer, for the secret-key codec: no copy of the key in a frame.
        pub fn encodeInto(out: *[encoded_length]u8, bytes: *const [wire_length]u8) void {
            _ = Encoder.encode(out, bytes);
        }

        pub fn decode(text: []const u8) error{ WrongLength, InvalidBase64 }![wire_length]u8 {
            var out: [wire_length]u8 = undefined;
            try decodeInto(&out, text);
            return out;
        }

        /// `out` is zeroed on error.
        pub fn decodeInto(out: *[wire_length]u8, text: []const u8) error{ WrongLength, InvalidBase64 }!void {
            errdefer std.crypto.secureZero(u8, out);
            if (text.len != encoded_length) return error.WrongLength;
            const decoded_len = Decoder.calcSizeForSlice(text) catch return error.InvalidBase64;
            if (decoded_len != wire_length) return error.InvalidBase64;
            Decoder.decode(out, text) catch return error.InvalidBase64;
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

/// Parse a 2-line secret key file into `out`. Does not decrypt — see
/// `openSecretKey`. `out.key` is secret for an unencrypted (`-W`) file; on error
/// it is zeroed and the comment is empty. The body runs one frame down and the
/// stack it dirtied is burned.
pub fn parseSecretKeyFile(out: *ParsedSecretKey, text: []const u8) FormatError!void {
    return burn.run(burn.codec_burn, FormatError!void, parseSecretKeyFileBody, .{ out, text });
}

fn parseSecretKeyFileBody(out: *ParsedSecretKey, text: []const u8) FormatError!void {
    errdefer {
        out.untrusted_comment = "";
        std.crypto.secureZero(u8, std.mem.asBytes(&out.key));
    }
    var it = std.mem.splitScalar(u8, text, '\n');
    const comment_line = try nextLine(&it);
    if (!std.mem.startsWith(u8, comment_line, untrusted_comment_prefix))
        return error.MissingUntrustedCommentPrefix;
    const b64_line = try nextLine(&it);
    var wire: [RawSecretKey.wire_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &wire);
    try SecretKeyCodec.decodeInto(&wire, b64_line);
    RawSecretKey.fromBytes(&out.key, &wire);
    if (!std.mem.eql(u8, &out.key.sig_alg, &sig_alg_legacy)) return error.UnsupportedAlgorithm;
    if (!std.mem.eql(u8, &out.key.chk_alg, &chk_alg_blake2b)) return error.UnsupportedAlgorithm;
    if (!std.mem.eql(u8, &out.key.kdf_alg, &kdf_alg_scrypt) and !std.mem.eql(u8, &out.key.kdf_alg, &kdf_alg_none))
        return error.UnsupportedAlgorithm;
    out.untrusted_comment = comment_line[untrusted_comment_prefix.len..];
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

/// The key is read by pointer and the encoded line (the key itself for an
/// unencrypted file) is wiped from this module's frames; `w`'s own buffer is
/// the caller's.
pub fn writeSecretKeyFile(w: *std.Io.Writer, untrusted_comment: []const u8, key: *const RawSecretKey) (FormatError || std.Io.Writer.Error)!void {
    return burn.run(burn.codec_burn, (FormatError || std.Io.Writer.Error)!void, writeSecretKeyFileBody, .{ w, untrusted_comment, key });
}

fn writeSecretKeyFileBody(w: *std.Io.Writer, untrusted_comment: []const u8, key: *const RawSecretKey) (FormatError || std.Io.Writer.Error)!void {
    try checkComment(untrusted_comment);
    try w.print("{s}{s}\n", .{ untrusted_comment_prefix, untrusted_comment });
    var wire: [RawSecretKey.wire_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &wire);
    var text: [SecretKeyCodec.encoded_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &text);
    key.toBytes(&wire);
    SecretKeyCodec.encodeInto(&text, &wire);
    try w.print("{s}\n", .{&text});
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

    /// Generate a fresh random key pair (fresh random key number too) into
    /// `out`. The body runs one frame down and the stack it dirtied is burned.
    ///
    /// The two draws below are deliberately NOT the same call. `key_number`
    /// is published in the clear in every `.pub`/`.sig` file — it is an
    /// identifier, not a secret, and `io.random` is the right source for
    /// it. The Ed25519 seed is the signing key for every release this key
    /// will ever sign, so it is fail-closed (CONVENTIONS.md §2.2).
    pub fn generate(out: *KeyPair, io: std.Io) void {
        burn.run(burn.generate_burn, void, generateBody, .{ out, io });
    }

    fn generateBody(out: *KeyPair, io: std.Io) void {
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
            out.* = .{ .key_number = key_number, .ed25519 = ed25519 };
            return;
        }
    }

    pub fn publicKey(self: *const KeyPair) RawPublicKey {
        return .{
            .sig_alg = sig_alg_legacy,
            .key_number = self.key_number,
            .key = self.ed25519.public_key.toBytes(),
        };
    }

    /// The on-disk secret key struct for an unencrypted (`-W`) key: `chk`
    /// is left all-zero (see the module doc comment — the reference never
    /// computes it in this path, and never checks it either).
    pub fn toRawSecretKeyPlain(self: *const KeyPair, out: *RawSecretKey) void {
        burn.run(burn.codec_burn, void, toRawSecretKeyPlainBody, .{ self, out });
    }

    fn toRawSecretKeyPlainBody(self: *const KeyPair, out: *RawSecretKey) void {
        out.* = .{
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

/// Encrypt `key_pair` with `password` into `out`, the on-disk `RawSecretKey`
/// form (zeroed on error). `ops_limit`/`mem_limit` pick the scrypt cost
/// (`ops_limit_sensitive`/`mem_limit_sensitive` are the CLI's own defaults); the
/// wire format stores these two limits, not derived `(N, r, p)` — see the module
/// doc comment. scrypt's working memory goes through `allocator` and is zeroed
/// before it is freed; the body runs one frame down and the stack it dirtied is
/// burned.
pub fn sealSecretKey(
    allocator: std.mem.Allocator,
    out: *RawSecretKey,
    key_pair: *const KeyPair,
    password: []const u8,
    salt: [salt_length]u8,
    ops_limit: u64,
    mem_limit: usize,
) std.crypto.pwhash.KdfError!void {
    return burn.run(burn.kdf_burn, std.crypto.pwhash.KdfError!void, sealSecretKeyBody, .{ allocator, out, key_pair, password, salt, ops_limit, mem_limit });
}

fn sealSecretKeyBody(
    allocator: std.mem.Allocator,
    out: *RawSecretKey,
    key_pair: *const KeyPair,
    password: []const u8,
    salt: [salt_length]u8,
    ops_limit: u64,
    mem_limit: usize,
) std.crypto.pwhash.KdfError!void {
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
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
    var wipe: burn.WipeAllocator = .{ .child = allocator };
    try std.crypto.pwhash.scrypt.kdf(wipe.allocator(), &stream, password, &salt, params);

    out.sig_alg = sig_alg_legacy;
    out.kdf_alg = kdf_alg_scrypt;
    out.chk_alg = chk_alg_blake2b;
    out.salt = salt;
    out.ops_limit = ops_limit;
    out.mem_limit = mem_limit;
    for (&out.key_number, 0..) |*b, i| b.* = plain_key_number[i] ^ stream[i];
    for (&out.secret_key, 0..) |*b, i| b.* = plain_sk[i] ^ stream[key_number_length + i];
    for (&out.checksum, 0..) |*b, i| b.* = plain_chk[i] ^ stream[key_number_length + secret_key_length + i];
}

/// `scrypt.Params.fromLimits` hardcodes block size `r = 8` (RFC 7914); its
/// `else` branch computes `max_n = mem_limit / (r * 128)` and feeds that
/// straight into `math.log2`, which `assert`s its argument is nonzero. Any
/// `mem_limit` below this floor makes `max_n` truncate to 0 — see
/// `MemLimitTooSmall` below.
const scrypt_r = 8;
const scrypt_min_mem_limit: u64 = scrypt_r * 128; // 1024

pub const OpenSecretKeyError = error{
    UnsupportedSignatureAlgorithm,
    UnsupportedChecksumAlgorithm,
    UnsupportedKdf,
    PasswordRequired,
    WrongPassword,
    /// `raw.mem_limit` (the on-disk `mem_limit_le(8)` field, attacker/file
    /// controlled) does not fit this host's `usize`. Rejected rather than
    /// truncated: `Params.fromLimits` takes mem_limit as the scrypt memory
    /// COST parameter, so silently truncating it would silently downgrade
    /// the KDF's memory-hardness instead of failing — a security-relevant
    /// wrong answer, not just an inconvenience. Only reachable on hosts
    /// where `usize` is narrower than 64 bits; the value is a real 64-bit
    /// on-disk quantity with no reason to assume it fits 32 bits.
    MemLimitTooLarge,
    /// `raw.mem_limit < scrypt_min_mem_limit` (1024 bytes). This is the end
    /// of the range that is actually reachable on every host this module
    /// targets (`.linux64`/`.windows`, both 64-bit `usize`): a file with
    /// `mem_limit` in `[0, 1023]` used to reach `scrypt.Params.fromLimits`
    /// unchecked, whose `else` branch divides by 1024 and hands the
    /// resulting 0 to `math.log2`, which `assert`s its argument is nonzero
    /// — an unconditional panic on attacker/file-controlled bytes, before
    /// any password is checked. This is the guard `MemLimitTooLarge`'s own
    /// doc comment describes ("silently downgraded memory-hardness") but
    /// could not reach, because that comment's failure mode lives at this
    /// end of the range, not the upper one. A1 audit `minisign` F1/F2.
    MemLimitTooSmall,
};

const OpenError = OpenSecretKeyError || std.crypto.pwhash.KdfError ||
    std.crypto.errors.NonCanonicalError || std.crypto.errors.EncodingError ||
    std.crypto.errors.IdentityElementError;

/// Decrypt (if needed) and load a `RawSecretKey` into `out` (zeroed on
/// error). Pass `password = null` only for an unencrypted (`kdf_alg_none`) key
/// — its `chk` is not checked, exactly like the reference. A wrong password is
/// a typed `error.WrongPassword`, never a panic or silently-wrong key. scrypt's
/// working memory goes through `allocator` and is zeroed before it is freed;
/// the body runs one frame down and the stack it dirtied is burned.
pub fn openSecretKey(
    allocator: std.mem.Allocator,
    out: *KeyPair,
    raw: *const RawSecretKey,
    password: ?[]const u8,
) OpenError!void {
    return burn.run(burn.kdf_burn, OpenError!void, openSecretKeyBody, .{ allocator, out, raw, password });
}

fn openSecretKeyBody(
    allocator: std.mem.Allocator,
    out: *KeyPair,
    raw: *const RawSecretKey,
    password: ?[]const u8,
) OpenError!void {
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
    if (!std.mem.eql(u8, &raw.sig_alg, &sig_alg_legacy)) return error.UnsupportedSignatureAlgorithm;
    if (!std.mem.eql(u8, &raw.chk_alg, &chk_alg_blake2b)) return error.UnsupportedChecksumAlgorithm;

    var key_number = raw.key_number;
    // CONVENTIONS §2.1 Z1 — the recovered plaintext secret key. The `defer`
    // wipes this frame's copy; `out` carries the key to the caller.
    var sk_bytes = raw.secret_key;
    defer std.crypto.secureZero(u8, &sk_bytes);

    if (std.mem.eql(u8, &raw.kdf_alg, &kdf_alg_none)) {
        // Plaintext; chk intentionally unchecked (see module doc comment).
    } else if (std.mem.eql(u8, &raw.kdf_alg, &kdf_alg_scrypt)) {
        const pw = password orelse return error.PasswordRequired;
        const mem_limit: usize = std.math.cast(usize, raw.mem_limit) orelse return error.MemLimitTooLarge;
        if (mem_limit < scrypt_min_mem_limit) return error.MemLimitTooSmall;
        const params = std.crypto.pwhash.scrypt.Params.fromLimits(raw.ops_limit, mem_limit);
        var stream: [encrypted_block_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &stream);
        var wipe: burn.WipeAllocator = .{ .child = allocator };
        try std.crypto.pwhash.scrypt.kdf(wipe.allocator(), &stream, pw, &raw.salt, params);

        var plain_key_number: [key_number_length]u8 = undefined;
        var plain_sk: [secret_key_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain_sk);
        var plain_chk: [checksum_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain_chk);
        for (&plain_key_number, 0..) |*b, i| b.* = raw.key_number[i] ^ stream[i];
        for (&plain_sk, 0..) |*b, i| b.* = raw.secret_key[i] ^ stream[key_number_length + i];
        for (&plain_chk, 0..) |*b, i| b.* = raw.checksum[i] ^ stream[key_number_length + secret_key_length + i];

        var computed_chk: [checksum_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &computed_chk);
        computeChecksum(&computed_chk, raw.sig_alg, plain_key_number, plain_sk);
        if (!std.crypto.timing_safe.eql([checksum_length]u8, computed_chk, plain_chk))
            return error.WrongPassword;

        key_number = plain_key_number;
        sk_bytes = plain_sk;
    } else return error.UnsupportedKdf;

    var secret_key = try std.crypto.sign.Ed25519.SecretKey.fromBytes(sk_bytes);
    defer std.crypto.secureZero(u8, &secret_key.bytes);
    var ed25519 = try std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key);
    defer std.crypto.secureZero(u8, &ed25519.secret_key.bytes);
    out.* = .{ .key_number = key_number, .ed25519 = ed25519 };
}

// ── message signing / verification ───────────────────────────────────────────

fn prehash(message: []const u8) [prehash_length]u8 {
    var digest: [prehash_length]u8 = undefined;
    std.crypto.hash.blake2.Blake2b512.hash(message, &digest, .{});
    return digest;
}

const EdSignError = std.crypto.errors.IdentityElementError || std.crypto.errors.NonCanonicalError ||
    std.crypto.errors.KeyMismatchError || std.crypto.errors.WeakPublicKeyError;

/// Every signature of this module goes through here: std's signer runs one
/// frame down and the stack it dirtied (seed, scalar, nonce) is burned.
fn edSign(key_pair: *const KeyPair, bytes: []const u8) EdSignError!std.crypto.sign.Ed25519.Signature {
    return burn.run(burn.sign_burn, EdSignError!std.crypto.sign.Ed25519.Signature, edSignBody, .{ key_pair, bytes });
}

fn edSignBody(key_pair: *const KeyPair, bytes: []const u8) EdSignError!std.crypto.sign.Ed25519.Signature {
    return key_pair.ed25519.sign(bytes, null);
}

/// Sign `message` (deterministic Ed25519 — `noise = null`, matching the
/// reference's own deterministic `crypto_sign_detached`).
pub fn signMessage(key_pair: *const KeyPair, message: []const u8, algorithm: Algorithm) !RawSignature {
    const signed_bytes: []const u8 = switch (algorithm) {
        .legacy => message,
        .prehashed => &prehash(message),
    };
    const sig = try edSign(key_pair, signed_bytes);
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
    key_pair: *const KeyPair,
    signature: RawSignature,
    trusted_comment: []const u8,
) ![signature_length]u8 {
    const buf = try allocator.alloc(u8, signature_length + trusted_comment.len);
    defer allocator.free(buf);
    @memcpy(buf[0..signature_length], &signature.signature);
    @memcpy(buf[signature_length..], trusted_comment);
    const sig = try edSign(key_pair, buf);
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

// ── streaming (digest-based) signing / verification ──────────────────────────
//
// `signMessage`/`verifyMessage` need the whole message resident in RAM even
// for `.prehashed`, because they compute the BLAKE2b-512 digest internally.
// A caller signing/verifying a multi-gigabyte file wants to stream it through
// `std.crypto.hash.blake2.Blake2b512.update` in fixed-size chunks instead —
// this module owns that entry point because *which bytes get signed* is a
// correctness-relevant part of the wire format (the digest, tagged
// `sig_alg_prehashed`), not filesystem plumbing. Opening the file and
// looping over it is the caller's/example's job (SPEC.md "Out of scope").
//
// There is no digest-based entry point for `sig_alg_legacy`: that algorithm
// signs the raw file bytes directly, so it cannot stream by construction —
// signing it still requires the whole message in RAM via `signMessage`.

/// Sign a **precomputed** BLAKE2b-512 digest directly. Always produces a
/// `sig_alg_prehashed` ("ED") signature — identical to what `signMessage(kp,
/// message, .prehashed)` produces, given `digest ==
/// Blake2b512.hash(message)`, since both funnel into the same
/// `edSign(key_pair, &digest)` call.
pub fn signDigest(key_pair: *const KeyPair, digest: [prehash_length]u8) !RawSignature {
    const sig = try edSign(key_pair, &digest);
    return .{ .sig_alg = sig_alg_prehashed, .key_number = key_pair.key_number, .signature = sig.toBytes() };
}

/// Verify a signature against a precomputed BLAKE2b-512 digest. Rejects
/// (`error.UnsupportedAlgorithm`) a `sig_alg_legacy`-tagged signature rather
/// than checking it against the digest: a legacy signature was never made
/// over a digest, so verifying it against one would silently check the
/// wrong bytes and could accept a signature that never authenticated this
/// content.
pub fn verifyDigest(public_key: RawPublicKey, digest: [prehash_length]u8, sig: RawSignature) VerifyMessageError!void {
    if (!std.mem.eql(u8, &sig.key_number, &public_key.key_number)) return error.KeyIdMismatch;
    if (!std.mem.eql(u8, &sig.sig_alg, &sig_alg_prehashed)) return error.UnsupportedAlgorithm;
    const pk = try std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key.key);
    const signature = std.crypto.sign.Ed25519.Signature.fromBytes(sig.signature);
    try signature.verify(&digest, pk);
}

/// `signFile`'s streaming counterpart: sign a precomputed digest, then the
/// trusted comment. Pass the result + `trusted_comment` to
/// `writeSignatureFile`, exactly as with `signFile`.
pub fn signFileDigest(
    allocator: std.mem.Allocator,
    key_pair: *const KeyPair,
    digest: [prehash_length]u8,
    trusted_comment: []const u8,
) !SignedFile {
    const sig = try signDigest(key_pair, digest);
    const gsig = try signTrustedComment(allocator, key_pair, sig, trusted_comment);
    return .{ .signature = sig, .global_signature = gsig };
}

/// `verifyFile`'s streaming counterpart: verify both layers (digest/key-id,
/// then trusted comment) against a precomputed digest instead of a
/// resident message buffer.
pub fn verifyFileDigest(
    allocator: std.mem.Allocator,
    public_key: RawPublicKey,
    digest: [prehash_length]u8,
    parsed: ParsedSignature,
) !void {
    try verifyDigest(public_key, digest, parsed.signature);
    try verifyTrustedComment(
        allocator,
        public_key,
        parsed.signature,
        parsed.trusted_comment,
        parsed.global_signature,
    );
}

/// Sign both layers at once: the message (under `algorithm`) and the
/// trusted comment. Pass the result + `trusted_comment` to
/// `writeSignatureFile`.
pub fn signFile(
    allocator: std.mem.Allocator,
    key_pair: *const KeyPair,
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

/// Result slot for `openSecretKey` calls that are expected to fail (the key is
/// zeroed on error; tests run one at a time).
var test_sink: KeyPair = undefined;

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
    var wire: [RawSecretKey.wire_length]u8 = undefined;
    sk.toBytes(&wire);
    var back: RawSecretKey = undefined;
    RawSecretKey.fromBytes(&back, &wire);
    try std.testing.expectEqual(sk, back);
}

test "sign/verify round-trip, both algorithms, plus tamper + wrong-key-id" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var kp: KeyPair = undefined;
    KeyPair.generate(&kp, io);
    const pk = kp.publicKey();
    const msg = "round-trip message";

    inline for ([_]Algorithm{ .legacy, .prehashed }) |algo| {
        const signed = try signFile(gpa, &kp, msg, algo, "trusted comment");
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

test "KeyPair.generate: two calls produce different seeds (A1 F5 -- a fixed seed left the suite green)" {
    // RED, confirmed 2026-08-13 and reconfirmed by the 2026-09-04 audit: the
    // mutation `entropy.fill(io, &seed)` -> `@memset(&seed, 0x42)` in
    // `KeyPair.generate` leaves the WHOLE suite green (32/32 at the time) --
    // nothing compared two generated keys against EACH OTHER, only against
    // fixture/round-trip invariants a fixed seed satisfies just as well.
    const io = std.testing.io;
    var kp1: KeyPair = undefined;
    KeyPair.generate(&kp1, io);
    var kp2: KeyPair = undefined;
    KeyPair.generate(&kp2, io);
    try std.testing.expect(!std.mem.eql(
        u8,
        &kp1.ed25519.secret_key.toBytes(),
        &kp2.ed25519.secret_key.toBytes(),
    ));
}

test "signDigest/verifyDigest: byte-exact against signMessage/verifyMessage's own .prehashed path" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var kp: KeyPair = undefined;
    KeyPair.generate(&kp, io);
    const pk = kp.publicKey();
    const msg = "streaming digest message";
    const digest = prehash(msg);

    // Same key, same bytes, two entry points -> identical signature.
    const via_message = try signMessage(&kp, msg, .prehashed);
    const via_digest = try signDigest(&kp, digest);
    try std.testing.expectEqual(via_message, via_digest);

    try verifyDigest(pk, digest, via_digest);
    try verifyMessage(pk, msg, via_digest); // interchangeable on the verify side too

    // tampered digest
    var bad_digest = digest;
    bad_digest[0] ^= 0xff;
    try std.testing.expectError(error.SignatureVerificationFailed, verifyDigest(pk, bad_digest, via_digest));

    // wrong key id
    var wrong_sig = via_digest;
    wrong_sig.key_number[0] ^= 0xff;
    try std.testing.expectError(error.KeyIdMismatch, verifyDigest(pk, digest, wrong_sig));

    // a legacy-tagged signature is never valid input to the digest path,
    // even if the bytes happen to be unrelated garbage.
    var legacy_shaped = via_digest;
    legacy_shaped.sig_alg = sig_alg_legacy;
    try std.testing.expectError(error.UnsupportedAlgorithm, verifyDigest(pk, digest, legacy_shaped));

    // full signFileDigest/verifyFileDigest round trip, including the
    // trusted-comment layer.
    const signed = try signFileDigest(gpa, &kp, digest, "streaming trusted comment");
    const written = blk: {
        var buf: [512]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try writeSignatureFile(&w, "untrusted", signed.signature, "streaming trusted comment", signed.global_signature);
        break :blk try gpa.dupe(u8, w.buffered());
    };
    defer gpa.free(written);
    const parsed = try parseSignatureFile(written);
    try verifyFileDigest(gpa, pk, digest, parsed);

    // tampered trusted comment
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        verifyFileDigest(gpa, pk, digest, .{
            .untrusted_comment = parsed.untrusted_comment,
            .signature = parsed.signature,
            .algorithm = parsed.algorithm,
            .trusted_comment = "a different comment",
            .global_signature = parsed.global_signature,
        }),
    );
}

test "unencrypted secret key: seal is a no-op wrapper, chk stays zero, openSecretKey needs no password" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var kp: KeyPair = undefined;
    KeyPair.generate(&kp, io);
    var raw: RawSecretKey = undefined;
    kp.toRawSecretKeyPlain(&raw);
    try std.testing.expectEqualSlices(u8, &kdf_alg_none, &raw.kdf_alg);
    try std.testing.expectEqual(std.mem.zeroes([checksum_length]u8), raw.checksum);

    var opened: KeyPair = undefined;

    try openSecretKey(gpa, &opened, &raw, null);
    try std.testing.expectEqual(kp.key_number, opened.key_number);
    try std.testing.expectEqual(kp.ed25519.secret_key.toBytes(), opened.ed25519.secret_key.toBytes());
}

test "encrypted secret key: seal + open round-trip, wrong password rejected" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var kp: KeyPair = undefined;
    KeyPair.generate(&kp, io);
    var salt: [salt_length]u8 = undefined;
    io.random(&salt);

    // Cheapest legal scrypt cost so the test runs fast (`OPSLIMIT_MIN` per
    // libsodium is 32768; pair it with a small memlimit so `fromLimits`
    // lands on a tiny N).
    var raw: RawSecretKey = undefined;
    try sealSecretKey(gpa, &raw, &kp, "correct password", salt, 32768, 1 << 16);
    try std.testing.expectEqualSlices(u8, &kdf_alg_scrypt, &raw.kdf_alg);

    var opened: KeyPair = undefined;

    try openSecretKey(gpa, &opened, &raw, "correct password");
    try std.testing.expectEqual(kp.key_number, opened.key_number);
    try std.testing.expectEqual(kp.ed25519.secret_key.toBytes(), opened.ed25519.secret_key.toBytes());

    try std.testing.expectError(error.WrongPassword, openSecretKey(gpa, &test_sink, &raw, "wrong password"));
    try std.testing.expectError(error.PasswordRequired, openSecretKey(gpa, &test_sink, &raw, null));
}

test "openSecretKey: the mem_limit-fits-usize guard rejects what does not fit, for any usize width" {
    // `raw.mem_limit` is a real on-disk `u64` (`mem_limit_le(8)`); `openSecretKey`
    // now runs `std.math.cast(usize, raw.mem_limit) orelse
    // error.MemLimitTooLarge` before that value ever reaches
    // `scrypt.Params.fromLimits`/`scrypt.kdf`. This test pins the cast's
    // behaviour directly rather than driving it through a full
    // `openSecretKey` call: this dev host's `usize` is 64-bit, so no real
    // `u64` value actually overflows it here, and forcing the overflow by
    // constructing a `RawSecretKey` with an astronomical `mem_limit` would
    // ask `scrypt.kdf` to allocate memory proportional to that limit before
    // the guard could stop it in a build where the guard doesn't apply — the
    // exact DoS this guard exists to prevent, not something to reproduce in
    // a test. `u32` stands in for "a `usize` this value doesn't fit" so the
    // assertion is host-width-independent; `zig build portable-minisign`
    // (wasm32, real 32-bit `usize`) is what proves this exact guard compiles
    // and type-checks for a target where it actually fires.
    try std.testing.expectEqual(@as(?u32, null), std.math.cast(u32, @as(u64, std.math.maxInt(u32)) + 1));
    try std.testing.expectEqual(@as(?u32, std.math.maxInt(u32)), std.math.cast(u32, @as(u64, std.math.maxInt(u32))));
}

test "openSecretKey: mem_limit below the scrypt floor is rejected, not a panic (A1 F1, ladder 0/1/4/8/1023 bytes)" {
    // RED, confirmed directly against `std.crypto.pwhash.scrypt.Params.fromLimits`
    // (`.zig-cache/probe/minisign_f1_red.zig`, this session): `fromLimits(32768, 0)`
    // panics with `thread ... panic: reached unreachable code` /
    // `math.zig:1287: assert(x != 0)`, from inside `scrypt.zig:156`'s
    // `math.log2(max_n)`. Before this guard, `openSecretKey` handed a
    // file-controlled `mem_limit` straight to `fromLimits` with no floor —
    // any of the five values below reached that same panic, unauthenticated,
    // before the password was ever checked.
    const gpa = std.testing.allocator;
    var raw: RawSecretKey = .{
        .sig_alg = sig_alg_legacy,
        .kdf_alg = kdf_alg_scrypt,
        .chk_alg = chk_alg_blake2b,
        .salt = std.mem.zeroes([salt_length]u8),
        .ops_limit = 32768,
        .mem_limit = 0,
        .key_number = std.mem.zeroes([key_number_length]u8),
        .secret_key = std.mem.zeroes([secret_key_length]u8),
        .checksum = std.mem.zeroes([checksum_length]u8),
    };
    for ([_]u64{ 0, 1, 4, 8, 1023 }) |mem_limit| {
        raw.mem_limit = mem_limit;
        try std.testing.expectError(error.MemLimitTooSmall, openSecretKey(gpa, &test_sink, &raw, "any password"));
    }
    // Positive control: the floor value itself must clear THIS guard — it
    // still fails, but through the KDF's own `ln == 0` guard
    // (`error.WeakParameters`), proving the ladder above is testing the
    // right guard and not just any rejection.
    raw.mem_limit = scrypt_min_mem_limit;
    try std.testing.expectError(error.WeakParameters, openSecretKey(gpa, &test_sink, &raw, "any password"));
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
    var kp: KeyPair = undefined;
    KeyPair.generate(&kp, io);
    var raw: RawSecretKey = undefined;
    kp.toRawSecretKeyPlain(&raw);

    var bad_sig_alg = raw;
    bad_sig_alg.sig_alg = .{ 'X', 'X' };
    try std.testing.expectError(error.UnsupportedSignatureAlgorithm, openSecretKey(gpa, &test_sink, &bad_sig_alg, null));

    var bad_chk_alg = raw;
    bad_chk_alg.chk_alg = .{ 'X', 'X' };
    try std.testing.expectError(error.UnsupportedChecksumAlgorithm, openSecretKey(gpa, &test_sink, &bad_chk_alg, null));

    var bad_kdf_alg = raw;
    bad_kdf_alg.kdf_alg = .{ 'X', 'X' };
    try std.testing.expectError(error.UnsupportedKdf, openSecretKey(gpa, &test_sink, &bad_kdf_alg, "some password"));
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
/// `testkit.fuzz` — see that module for why a corpus entry is not the frame.
const tkfuzz = @import("testkit").fuzz;
const fuzzSeed = tkfuzz.seed;
const kat = @import("kat_vectors.zig");
const fuzz_test = @import("fuzz_test.zig");

const sig_file_buf_len = 1024;

/// `.minisig` files in the format `Smith.slice` reads (see `testkit.fuzz`).
///
/// ⚠ Only the SIGNATURE fixtures are used here, never the secret-key ones:
/// `kat_vectors.zig` holds real (fixture-generated) minisign secret keys, and
/// a fuzz corpus is not the place to widen their blast radius. A signature
/// file is what an attacker hands a verifier; a secret key is not.
const sig_file_seeds = [_][]const u8{
    fuzzSeed(kat.prehashed_signature_file), // the reference `minisign -S` output
    fuzzSeed(kat.legacy_signature_file), // the reference `minisign -S -l` output
    // The same file with its trailing newline removed — the parser's
    // last-line handling, which is a different path from a 4-line file.
    fuzzSeed(kat.prehashed_signature_file[0 .. kat.prehashed_signature_file.len - 1]),
    fuzzSeed("untrusted comment: ok\nAAAA\ntrusted comment: ok\nAAAA\n"), // WrongLength on both payloads
    fuzzSeed("untrusted comment: ok\n!!!!\ntrusted comment: ok\n!!!!\n"), // InvalidBase64
    fuzzSeed("wrong prefix: ok\nAAAA\ntrusted comment: ok\nAAAA\n"), // MissingUntrustedCommentPrefix
    fuzzSeed("untrusted comment: ok\nAAAA\nwrong prefix: ok\nAAAA\n"), // MissingTrustedCommentPrefix
    fuzzSeed("untrusted comment: bad\x01byte\nAAAA\ntrusted comment: ok\nAAAA\n"), // a non-printable comment
    fuzzSeed("untrusted comment: ok\n"), // one line only
    fuzzSeed(""), // the ONE input the collapsed harness ever built from
};

test "fuzz: parseSignatureFile never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzParseSignatureFile, .{ .corpus = &sig_file_seeds });
}

fn fuzzB64Line(cur: *tkfuzz.Cursor, comptime wire_length: usize, out: *[Base64Codec(wire_length).encoded_length]u8) []const u8 {
    const Codec = Base64Codec(wire_length);
    if (cur.byte() & 1 == 1) {
        // A real base64-encoded payload of correct length, script-driven content.
        var raw: [wire_length]u8 = undefined;
        for (&raw) |*b| b.* = cur.byte();
        out.* = Codec.encode(raw);
        return out;
    }
    // Garbage of arbitrary length -- exercises WrongLength/InvalidBase64.
    const len: usize = cur.ranged(0, @intCast(out.len));
    for (out[0..len]) |*b| b.* = cur.byte();
    return out[0..len];
}

fn fuzzParseSignatureFile(_: void, smith: *std.testing.Smith) !void {
    var script: [sig_file_buf_len]u8 = undefined;
    const n = smith.slice(&script);
    var src: fuzz_test.ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
    return sigFileHarness(fuzz_test.ScriptSource, &src, std.testing.allocator);
}

/// Harness body, generic over its source (testkit's fuzz driver feeds it a
/// PRNG, `testing.fuzz` a cursor over the Smith bytes).
pub fn sigFileHarness(comptime S: type, src: *S, allocator: std.mem.Allocator) anyerror!void {
    var buf: [sig_file_buf_len]u8 = undefined;
    // ⚠ ONE `smith.slice` call, and it is the FIRST draw. The harness used to
    // open with `smith.bytes(&comment_buf)` + a ranged length, and every knob
    // in `fuzzB64Line` was a `smith.value(bool)` or a ranged draw after it —
    // all of which collapse outside `--fuzz`, because a ranged `Smith` draw
    // returns the range MINIMUM when fewer than eight octets remain and `bool`
    // is a 1-bit range. The result was ONE file, byte for byte, for ever: an
    // empty untrusted comment, an empty signature line, an empty trusted
    // comment, an empty global-signature line and no final newline. It died at
    // the first length check; the algorithm-tag, base64 and printable-comment
    // checks the harness's own comment names were never reached.
    //
    // The corpus is real `.minisig` files, so pass (a) drives the parser with
    // what a verifier actually receives; pass (b) keeps the skeleton generator
    // alive by reading its choices from a `Cursor` over the same bytes.
    // Measured 2026-09-07 over the corpus above: **1 distinct file and 0
    // signature files parsed before; 10 files, 3 parsed, and the generator
    // producing 9 distinct skeletons instead of 1, after.**
    const n: usize = src.slice(&buf);
    const drawn = buf[0..n];
    if (parseSignatureFile(drawn)) |_| fuzz_test.mark(.sig_file_parsed) else |_| fuzz_test.mark(.sig_file_rejected);

    var cur: tkfuzz.Cursor = .{ .bytes = drawn };
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    try buildFuzzSignatureFile(&text, allocator, &cur);
    if (parseSignatureFile(text.items)) |_| fuzz_test.mark(.sig_file_parsed) else |_| fuzz_test.mark(.sig_file_rejected);

    // (c) A well-formed file from drawn fields (known algorithm tag, printable
    // trusted comment): random bytes essentially never get that far, so this
    // is what judges the accept path. It MUST parse and give the fields back;
    // the same file with one byte changed must merely not trap.
    var raw: RawSignature = undefined;
    raw.sig_alg = if (src.index(2) == 0) sig_alg_legacy else sig_alg_prehashed;
    src.bytes(&raw.key_number);
    src.bytes(&raw.signature);
    var gsig: [signature_length]u8 = undefined;
    src.bytes(&gsig);
    var tc: [32]u8 = undefined;
    const tc_len = src.index(tc.len + 1);
    for (tc[0..tc_len]) |*c| c.* = 0x20 + @as(u8, @intCast(src.index(95)));
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    try writeSignatureFile(&aw.writer, "fuzz", raw, tc[0..tc_len], gsig);
    const parsed = parseSignatureFile(aw.written()) catch return error.WellFormedSignatureFileRejected;
    if (!std.mem.eql(u8, &parsed.signature.toBytes(), &raw.toBytes()) or
        !std.mem.eql(u8, parsed.trusted_comment, tc[0..tc_len]) or
        !std.mem.eql(u8, &parsed.global_signature, &gsig)) return error.SignatureFileRoundTrip;
    fuzz_test.mark(.sig_file_parsed);
    const damaged = try allocator.dupe(u8, aw.written());
    defer allocator.free(damaged);
    damaged[src.index(damaged.len)] ^= @as(u8, 1) << @intCast(src.index(8));
    _ = parseSignatureFile(damaged) catch {};
}

/// The 4-line skeleton, with the comment text and both payloads driven by the
/// script. Shared with the corpus guard so the guard cannot measure a
/// different generator.
fn buildFuzzSignatureFile(text: *std.ArrayList(u8), allocator: std.mem.Allocator, cur: *tkfuzz.Cursor) !void {
    try text.appendSlice(allocator, untrusted_comment_prefix);
    const comment_len: usize = cur.ranged(0, 32);
    for (0..comment_len) |_| try text.append(allocator, cur.byte());
    try text.append(allocator, '\n');

    var sig_out: [SignatureCodec.encoded_length]u8 = undefined;
    try text.appendSlice(allocator, fuzzB64Line(cur, RawSignature.wire_length, &sig_out));
    try text.append(allocator, '\n');

    try text.appendSlice(allocator, trusted_comment_prefix);
    const trusted_len: usize = cur.ranged(0, 32);
    for (0..trusted_len) |_| try text.append(allocator, cur.byte());
    try text.append(allocator, '\n');

    var gsig_out: [GlobalSignatureCodec.encoded_length]u8 = undefined;
    try text.appendSlice(allocator, fuzzB64Line(cur, signature_length, &gsig_out));
    if (cur.byte() & 1 == 1) try text.append(allocator, '\n');
}

test "corpus: every signature file reaches the parser, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. A seed
    // longer than the harness's buffer reads back EMPTY (`Smith.slice` falls
    // back to the range minimum) and nothing else would notice.
    //
    // Two numbers past reach, both pinned at their minimum by the collapsed
    // draws: how many real `.minisig` files PARSE, and how many DISTINCT
    // skeletons the generator emits.
    const allocator = std.testing.allocator;
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var skeletons: usize = 0;
    var seen: [sig_file_seeds.len]std.ArrayList(u8) = undefined;
    defer for (seen[0..skeletons]) |*s| s.deinit(allocator);
    for (sig_file_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [sig_file_buf_len]u8 = undefined;
        const n: usize = smith.slice(&buf);
        if (n != 0) nonempty += 1;
        const drawn = buf[0..n];
        if (parseSignatureFile(drawn)) |_| parsed += 1 else |_| {}

        var cur: tkfuzz.Cursor = .{ .bytes = drawn };
        var text: std.ArrayList(u8) = .empty;
        try buildFuzzSignatureFile(&text, allocator, &cur);
        var already = false;
        for (seen[0..skeletons]) |s| {
            if (std.mem.eql(u8, s.items, text.items)) already = true;
        }
        if (already) {
            text.deinit(allocator);
        } else {
            seen[skeletons] = text;
            skeletons += 1;
        }
    }
    // One seed IS the empty file, a legal member of a refusal corpus.
    try std.testing.expectEqual(sig_file_seeds.len - 1, nonempty);
    // Measured 2026-09-07: with the collapsing draws the generator emitted
    // exactly 1 skeleton across the whole corpus, and no real signature file
    // ever reached the parser at all. After:
    try std.testing.expectEqual(@as(usize, 3), parsed);
    try std.testing.expectEqual(@as(usize, 9), skeletons);
}

// ── fuzz: parseSecretKeyFile / openSecretKey never panic on arbitrary bytes ──
//
// A1 audit `minisign` F3: neither `parseSecretKeyFile` nor `openSecretKey`
// had a fuzz harness, and F1 (the `mem_limit` panic fixed above) lives on
// exactly that path -- which is how F1 survived three prior audits and a
// clean 171k-run fuzz sweep that never once drove bytes through this parser.
// A `.key` file is the same 2-line shape as a public-key file (`untrusted
// comment: ...` + one base64 line), so this harness follows
// `fuzzParseSignatureFile`'s two-pass shape: pass (a) drives the parser with
// the drawn bytes verbatim, pass (b) reads the same bytes as a script for a
// structurally-real skeleton generator. Both passes go one step past parsing
// and also call `openSecretKey` on whatever comes out, with a fuzzed
// password -- so a regression of the F1 guard fails here, not only in the
// hand-written ladder test above. `mem_limit` gets a dedicated biased draw
// (`[0, 2047]` half the time) because a plain 8-byte random draw would all
// but never land in the 1024-wide F1 window out of 2^64.
//
// ⚠ Only the SECRET-key fixtures widen this corpus's blast radius, same
// caveat as the signature harness above about not mixing in unrelated
// fixtures for no reason -- these ARE the secret-key fixtures, used because
// this harness's whole subject is secret-key parsing.
const secret_key_file_buf_len = 512;

const secret_key_file_seeds = [_][]const u8{
    fuzzSeed(kat.unencrypted_secret_key_file),
    fuzzSeed(kat.encrypted_secret_key_file),
    fuzzSeed(kat.unencrypted_secret_key_file[0 .. kat.unencrypted_secret_key_file.len - 1]),
    fuzzSeed("untrusted comment: ok\nAAAA\n"), // WrongLength
    fuzzSeed("untrusted comment: ok\n!!!!\n"), // InvalidBase64
    fuzzSeed("wrong prefix: ok\nAAAA\n"), // MissingUntrustedCommentPrefix
    fuzzSeed("untrusted comment: ok\n"), // one line only
    fuzzSeed(""), // the collapsed-harness input
};

test "fuzz: parseSecretKeyFile/openSecretKey never panic on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzParseSecretKeyFile, .{ .corpus = &secret_key_file_seeds });
}

fn fuzzParseSecretKeyFile(_: void, smith: *std.testing.Smith) !void {
    var script: [secret_key_file_buf_len]u8 = undefined;
    const n = smith.slice(&script);
    var src: fuzz_test.ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
    return secretKeyFileHarness(fuzz_test.ScriptSource, &src, std.testing.allocator);
}

pub fn secretKeyFileHarness(comptime S: type, src: *S, allocator: std.mem.Allocator) anyerror!void {
    var buf: [secret_key_file_buf_len]u8 = undefined;
    const n: usize = src.slice(&buf);
    const drawn = buf[0..n];
    var parsed: ParsedSecretKey = undefined;
    var opened: KeyPair = undefined;
    if (parseSecretKeyFile(&parsed, drawn)) {
        fuzz_test.mark(.key_file_parsed);
        var pw_buf: [16]u8 = undefined;
        const pw_len: usize = @min(pw_buf.len, drawn.len);
        @memcpy(pw_buf[0..pw_len], drawn[0..pw_len]);
        openSecretKey(allocator, &opened, &parsed.key, pw_buf[0..pw_len]) catch {};
    } else |_| fuzz_test.mark(.key_file_rejected);

    var cur: tkfuzz.Cursor = .{ .bytes = drawn };
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    try buildFuzzSecretKeyFile(&text, allocator, &cur);
    if (parseSecretKeyFile(&parsed, text.items)) {
        fuzz_test.mark(.key_file_parsed);
        openSecretKey(allocator, &opened, &parsed.key, "fuzz password") catch {};
    } else |_| fuzz_test.mark(.key_file_rejected);
}

/// The 2-line skeleton, with the comment text and the `RawSecretKey` fields
/// driven by the script. Shared with the corpus guard so the guard cannot
/// measure a different generator.
fn buildFuzzSecretKeyFile(text: *std.ArrayList(u8), allocator: std.mem.Allocator, cur: *tkfuzz.Cursor) !void {
    try text.appendSlice(allocator, untrusted_comment_prefix);
    const comment_len: usize = cur.ranged(0, 32);
    for (0..comment_len) |_| try text.append(allocator, cur.byte());
    try text.append(allocator, '\n');

    var raw: RawSecretKey = undefined;
    raw.sig_alg = if (cur.byte() & 1 == 1) sig_alg_legacy else .{ cur.byte(), cur.byte() };
    raw.kdf_alg = if (cur.byte() & 1 == 1) kdf_alg_scrypt else kdf_alg_none;
    raw.chk_alg = if (cur.byte() & 1 == 1) chk_alg_blake2b else .{ cur.byte(), cur.byte() };
    for (&raw.salt) |*b| b.* = cur.byte();
    raw.ops_limit = readFuzzU64(cur);
    // Biased toward the A1 F1 boundary (`scrypt_min_mem_limit == 1024`).
    raw.mem_limit = if (cur.byte() & 1 == 1) @as(u64, cur.ranged(0, 2047)) else readFuzzU64(cur);
    for (&raw.key_number) |*b| b.* = cur.byte();
    for (&raw.secret_key) |*b| b.* = cur.byte();
    for (&raw.checksum) |*b| b.* = cur.byte();

    var wire: [RawSecretKey.wire_length]u8 = undefined;
    raw.toBytes(&wire);
    var b64: [SecretKeyCodec.encoded_length]u8 = undefined;
    SecretKeyCodec.encodeInto(&b64, &wire);
    try text.appendSlice(allocator, &b64);
    if (cur.byte() & 1 == 1) try text.append(allocator, '\n');
}

fn readFuzzU64(cur: *tkfuzz.Cursor) u64 {
    var b: [8]u8 = undefined;
    for (&b) |*x| x.* = cur.byte();
    return std.mem.readInt(u64, &b, .little);
}

test "corpus: every secret key file reaches the parser, and the counts are pinned" {
    // ⚠ Deliberately does NOT also pin how many skeletons `openSecretKey`
    // opens: `Ed25519.KeyPair.fromSecretKey`'s public-key recomputation
    // check is `if (std.debug.runtime_safety)`, so that count itself
    // changes between ReleaseSafe and ReleaseFast (measured: 0 vs. 3 opened
    // over this corpus) for reasons that have nothing to do with this
    // parser. `parsed`/`skeletons` below come only from `parseSecretKeyFile`
    // and `buildFuzzSecretKeyFile`, neither of which reads that flag.
    const allocator = std.testing.allocator;
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var skeletons: usize = 0;
    var parsed_key: ParsedSecretKey = undefined;
    var opened: KeyPair = undefined;
    var seen: [secret_key_file_seeds.len]std.ArrayList(u8) = undefined;
    defer for (seen[0..skeletons]) |*s| s.deinit(allocator);
    for (secret_key_file_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [secret_key_file_buf_len]u8 = undefined;
        const n: usize = smith.slice(&buf);
        if (n != 0) nonempty += 1;
        const drawn = buf[0..n];
        if (parseSecretKeyFile(&parsed_key, drawn)) |_| parsed += 1 else |_| {}

        var cur: tkfuzz.Cursor = .{ .bytes = drawn };
        var text: std.ArrayList(u8) = .empty;
        try buildFuzzSecretKeyFile(&text, allocator, &cur);
        if (parseSecretKeyFile(&parsed_key, text.items)) |_| {
            openSecretKey(allocator, &opened, &parsed_key.key, "fuzz password") catch {};
        } else |_| {}
        var already = false;
        for (seen[0..skeletons]) |s| {
            if (std.mem.eql(u8, s.items, text.items)) already = true;
        }
        if (already) {
            text.deinit(allocator);
        } else {
            seen[skeletons] = text;
            skeletons += 1;
        }
    }
    // One seed IS the empty file, a legal member of a refusal corpus.
    try std.testing.expectEqual(secret_key_file_seeds.len - 1, nonempty);
    try std.testing.expectEqual(@as(usize, 3), parsed);
    try std.testing.expectEqual(@as(usize, 7), skeletons);
}

// ── fuzz: isPrintableComment never panics/OOB-reads on arbitrary bytes ───
//
// A hand-rolled UTF-8 validator (ported from minisign.c's `is_printable`)
// with its own byte-length/continuation-byte bookkeeping (`i + need >=
// text.len`, overlong/surrogate range checks) -- exactly the shape of
// parser most prone to an off-by-one OOB read, and it runs directly over
// the trusted-comment bytes of an attacker-supplied signature file before
// `parseSignatureFile` ever echoes them anywhere.
/// Comment bytes in the format `Smith.slice` reads. Lifted from
/// `isPrintableComment: control chars and truncated UTF-8 rejected, valid
/// UTF-8 accepted`, plus the boundary shapes a hand-rolled UTF-8 validator
/// gets wrong: a multi-byte sequence that ENDS at the last octet, and one that
/// is cut one octet short of the end.
const comment_seeds = [_][]const u8{
    fuzzSeed("plain ASCII, a tab\there"),
    fuzzSeed("caf\xc3\xa9"), // valid 2-byte UTF-8
    fuzzSeed("\xe2\x82\xac"), // valid 3-byte UTF-8 (€)
    fuzzSeed("\xf0\x9f\x92\xa9"), // valid 4-byte UTF-8
    fuzzSeed("bad\x01byte"), // a control character
    fuzzSeed("del\x7f"), // DEL
    fuzzSeed("truncated\xc3"), // a 2-byte lead with no continuation: the `i + need >= len` edge
    fuzzSeed("\xe2\x82"), // a 3-byte lead one octet short at the very end
    fuzzSeed("overlong\xc0\x80"), // an overlong encoding
    fuzzSeed("\xed\xa0\x80"), // a surrogate, which UTF-8 forbids
    fuzzSeed("\xff\xfe"), // octets that are never a lead
    fuzzSeed("a" ** 64), // the full harness buffer
    fuzzSeed(""), // the empty comment, and the ONE input the collapsed harness ran
};

test "fuzz: isPrintableComment never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzIsPrintableComment, .{ .corpus = &comment_seeds });
}

fn fuzzIsPrintableComment(_: void, smith: *std.testing.Smith) !void {
    var script: [64]u8 = undefined;
    const n = smith.slice(&script);
    var src: fuzz_test.ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
    return commentHarness(fuzz_test.ScriptSource, &src, std.testing.allocator);
}

pub fn commentHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [64]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM —
    // so `len` was 0 on every input and this validator, whose whole risk is an
    // off-by-one at the END of the buffer, was only ever handed a buffer with
    // no end to walk to. Measured 2026-09-07 over the corpus above: **0 of 13
    // seeds non-empty and 0 comments accepted before, 12 of 13 non-empty (one
    // seed IS the empty comment) and 5 accepted after.**
    const len: usize = src.slice(&buf);
    if (isPrintableComment(buf[0..len])) fuzz_test.mark(.comment_printable) else fuzz_test.mark(.comment_rejected);
}

test "corpus: every comment reaches isPrintableComment, and the verdicts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment.
    //
    // ⚠ `isPrintableComment("")` is TRUE — the empty comment is printable — so
    // an "accepted > 0" guard would have read 100% while the validator walked
    // nothing at all. Both verdict counts are pinned instead, and the octet
    // total beside them.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var rejected: usize = 0;
    var octets: usize = 0;
    for (comment_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [64]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        octets += len;
        if (isPrintableComment(buf[0..len])) accepted += 1 else rejected += 1;
    }
    // One seed IS the empty comment, a legal member of the corpus.
    try std.testing.expectEqual(comment_seeds.len - 1, nonempty);
    // Measured 2026-09-07: with the collapsing draw, 13 empty comments — 13
    // accepted, 0 rejected, 0 octets walked. After:
    try std.testing.expectEqual(@as(usize, 6), accepted);
    try std.testing.expectEqual(@as(usize, 7), rejected);
    try std.testing.expectEqual(@as(usize, 138), octets);
}

test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
}

test "KeyPair.wipe destroys the long-term secret key, leaving the public half usable" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var kp: KeyPair = undefined;
    KeyPair.generate(&kp, io);
    var salt: [salt_length]u8 = undefined;
    io.random(&salt);

    var raw: RawSecretKey = undefined;

    try sealSecretKey(gpa, &raw, &kp, "pw", salt, 32768, 1 << 16);
    var opened: KeyPair = undefined;
    try openSecretKey(gpa, &opened, &raw, "pw");

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

// ── audit 2026-10-04: tests asked for by mutation survivors ──────────────────

test "isPrintableComment: overlong, out-of-range, broken and C1-control UTF-8 rejected" {
    // RFC 3629 §3/§4: the octets C0, C1 and F5..FF never appear in UTF-8; E0
    // needs A0..BF next and F0 needs 90..BF (no overlong forms); F4 needs
    // 80..8F (nothing above U+10FFFF); every trailing octet is 10xxxxxx. And
    // U+0080..U+009F are the C1 controls — U+009B is CSI, the 8-bit form of
    // the terminal escape `ESC [` this function exists to keep out of a
    // verifier's output (module doc; minisign.c `is_printable`).
    const bad = [_][]const u8{
        "\xc0\xa1", // overlong '!'
        "\xc1\xbf", // overlong DEL
        "\xe0\x80\xa1", // overlong '!' (3 octets)
        "\xf0\x80\x80\xa1", // overlong '!' (4 octets)
        "\xf4\x90\x80\x80", // U+110000
        "\xf5\x80\x80\x80", // lead octet F5
        "\xc3\x41", // a lead octet followed by ASCII
        "\xc2\x9b", // U+009B CSI
        "\xc2\x80", // U+0080
    };
    for (bad) |s| try std.testing.expect(!isPrintableComment(s));
    // The nearest valid neighbours are accepted (non-vacuity).
    const good = [_][]const u8{ "\xc2\xa0", "\xe0\xa0\x80", "\xf0\x90\x80\x80", "\xf4\x8f\xbf\xbf", "\xed\x9f\xbf" };
    for (good) |s| try std.testing.expect(isPrintableComment(s));
}

test "parseSignatureFile: trusted-comment prefix and printability, CRLF line ends, padding" {
    // A real signature file (kat_vectors.zig) with exactly one thing changed.
    const real = kat.prehashed_signature_file;
    var buf: [1024]u8 = undefined;

    // CRLF: minisign's own `trim()` strips a trailing "\r" from every line,
    // so a file saved with Windows line ends is the same file.
    var crlf: std.ArrayList(u8) = .empty;
    defer crlf.deinit(std.testing.allocator);
    for (real) |c| {
        if (c == '\n') try crlf.append(std.testing.allocator, '\r');
        try crlf.append(std.testing.allocator, c);
    }
    const pub_key = try parsePublicKeyFile(kat.unencrypted_public_key_file);
    try verifyFile(std.testing.allocator, pub_key.key, kat.message, try parseSignatureFile(crlf.items));

    // Line 3 must start with "trusted comment: " (the reference refuses the
    // file otherwise).
    const tc = std.mem.indexOf(u8, real, "\n" ++ trusted_comment_prefix).? + 1; // not the "untrusted …" one
    @memcpy(buf[0..real.len], real);
    buf[tc] = 'T';
    try std.testing.expectError(error.MissingTrustedCommentPrefix, parseSignatureFile(buf[0..real.len]));

    // A trusted comment carrying ESC is refused at parse time, before any
    // caller can print it.
    @memcpy(buf[0..real.len], real);
    buf[tc + trusted_comment_prefix.len] = 0x1b;
    try std.testing.expectError(error.UnprintableComment, parseSignatureFile(buf[0..real.len]));

    // Line 2 is the base64 of the 74-octet struct: 100 characters ending in
    // ONE '=' (RFC 4648 §4). With the final group made `xA==` it has the right length but encodes 73 octets — not the
    // struct, so not a signature line.
    const l2 = std.mem.indexOfScalar(u8, real, '\n').? + 1;
    const l2_end = std.mem.indexOfScalarPos(u8, real, l2, '\n').?;
    try std.testing.expectEqual(@as(usize, 100), l2_end - l2);
    try std.testing.expectEqual(@as(u8, '='), real[l2_end - 1]);
    @memcpy(buf[0..real.len], real);
    buf[l2_end - 3] = 'A'; // zero low bits: a canonical 1-octet final group
    buf[l2_end - 2] = '=';
    try std.testing.expectError(error.InvalidBase64, parseSignatureFile(buf[0..real.len]));
}

test "parsePublicKeyFile / parseSecretKeyFile: comment prefix and every algorithm tag checked" {
    // Both files are `untrusted comment: …` + base64 (minisign.c refuses a
    // file whose first line lacks the prefix), and a secret key names its
    // signature ("Ed"), checksum ("B2") and KDF ("Sc" or none) algorithms —
    // anything else is a key this module cannot use, refused at parse time.
    const pk = try parsePublicKeyFile(kat.unencrypted_public_key_file);
    const pk_b64 = PublicKeyCodec.encode(pk.key.toBytes());
    var buf: [512]u8 = undefined;
    const no_prefix = try std.fmt.bufPrint(&buf, "untrusted remark: x\n{s}\n", .{pk_b64});
    try std.testing.expectError(error.MissingUntrustedCommentPrefix, parsePublicKeyFile(no_prefix));

    var sk: ParsedSecretKey = undefined;
    var sk_sink: ParsedSecretKey = undefined;
    try parseSecretKeyFile(&sk, kat.unencrypted_secret_key_file); // control
    inline for (.{ "sig_alg", "chk_alg", "kdf_alg" }) |field| {
        var raw = sk.key;
        @field(raw, field) = .{ 'X', 'X' };
        var w = std.Io.Writer.fixed(&buf);
        try writeSecretKeyFile(&w, "c", &raw);
        try std.testing.expectError(error.UnsupportedAlgorithm, parseSecretKeyFile(&sk_sink, w.buffered()));
    }
    var w = std.Io.Writer.fixed(&buf);
    try writeSecretKeyFile(&w, "c", &sk.key);
    const text = w.buffered();
    text[0] = 'U';
    try std.testing.expectError(error.MissingUntrustedCommentPrefix, parseSecretKeyFile(&sk_sink, text));
}

test "writers refuse a carriage return and an unprintable trusted comment" {
    // `checkComment` refuses '\r' as well as '\n' (a reader that splits on
    // either would see an extra line), and `writeSignatureFile` refuses what
    // `parseSignatureFile` would refuse, so it never writes a file its own
    // parser rejects.
    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const pk: RawPublicKey = .{ .sig_alg = sig_alg_legacy, .key_number = @splat(0), .key = @splat(0) };
    try std.testing.expectError(error.EmbeddedNewline, writePublicKeyFile(&w, "bad\rcomment", pk));
    const sig: RawSignature = .{ .sig_alg = sig_alg_prehashed, .key_number = @splat(0), .signature = @splat(0) };
    try std.testing.expectError(error.UnprintableComment, writeSignatureFile(&w, "ok", sig, "esc\x1b[31m", @splat(0)));
}
