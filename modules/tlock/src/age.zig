// SPDX-License-Identifier: MIT

//! age — the `age-encryption.org/v1` envelope `drand/tlock`'s `tle` CLI
//! wraps `tlock.encrypt`'s 128-byte ciphertext in, so a file of ANY length
//! can be timelocked. Written from the public age specification (C2SP
//! `age.md`, "age-encryption.org/v1"); no age source was read.
//!
//! ## The file, top to bottom
//!
//! ```
//! age-encryption.org/v1
//! -> tlock <round> <chain hash, 64 lowercase hex>
//! <base64 of U||V||W, no padding, 64 columns per line, last line shorter>
//! --- <base64 of HMAC-SHA-256, no padding>
//! <16-byte nonce><STREAM payload>
//! ```
//!
//! - **File key**: 16 random bytes. The `tlock` stanza's body is the BF-IBE
//!   `Ciphertext` of the file key (`tlock.encrypt(p_pub, round, file_key,
//!   sigma)`) — the round signature recovers it.
//! - **Header MAC**: `HMAC-SHA-256(key = HKDF-SHA-256(ikm = file_key, salt =
//!   "", info = "header"), msg = every header byte up to and including
//!   "---")`. Verified in constant time before any payload byte is opened.
//! - **Payload**: `payload_key = HKDF-SHA-256(ikm = file_key, salt = nonce,
//!   info = "payload")`; the plaintext is cut into 64 KiB chunks, each sealed
//!   with ChaCha20-Poly1305 (`chachapoly`, empty AD) under the 12-byte nonce
//!   `BE88(counter) || last_flag`. The last chunk may be full; it is empty
//!   only when the whole plaintext is.
//! - **Armor** (`tle -a`): standard padded base64 of the whole binary file in
//!   64-column lines between `-----BEGIN AGE ENCRYPTED FILE-----` and
//!   `-----END AGE ENCRYPTED FILE-----`.
//!
//! ## Hostile input
//!
//! Every parser here is fail-closed with a typed error and bounded:
//! the header is capped at `max_header_bytes` and `max_stanzas`; stanza
//! bodies, MAC lines and armor lines must be canonical base64 (std's decoder
//! refuses non-zero trailing bits); nothing past the input is ever read; a
//! failing payload chunk wipes every plaintext byte already written.
//!
//! ## What this does NOT do
//!
//! - It is a decryptor for tlock-wrapped files only: a file with no `tlock`
//!   stanza is `error.NoTlockStanza`. Other stanzas (an X25519 recipient
//!   alongside) are parsed, MAC-covered and skipped; two `tlock` stanzas are
//!   refused (`tle` never writes that).
//! - Armor streams through `ArmorWriter`/`ArmorReader`. The binary file also streams over
//!   `std.Io.Reader`/`Writer` (`encryptStream`, `decryptStream`); the
//!   whole-buffer functions have exact sizes up front (`encryptedLen`,
//!   `decryptedLen`, `armoredLen`).

const std = @import("std");
const chachapoly = @import("chachapoly");
const entropy = @import("entropy");
const bls12_381 = @import("bls12_381");
const tlock_mod = @import("tlock.zig");
const burn = @import("burn.zig");

const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const Ciphertext = tlock_mod.Ciphertext;
const CiphertextSigG2 = tlock_mod.CiphertextSigG2;
const Aead = chachapoly.ChaCha20Poly1305;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const b64_raw = std.base64.standard_no_pad;
const b64_pad = std.base64.standard;

pub const version_line = "age-encryption.org/v1";
pub const stanza_type = "tlock";
pub const file_key_bytes = tlock_mod.block_bytes; // 16
pub const nonce_bytes = 16;
pub const mac_bytes = HmacSha256.mac_length; // 32
pub const chain_hash_bytes = 32;
pub const chunk_bytes = 64 * 1024;
pub const tag_bytes = Aead.tag_length;
pub const sealed_chunk_bytes = chunk_bytes + tag_bytes;
/// Columns per base64 line, in stanza bodies and in armor alike.
pub const columns = 64;

/// Cap on the header (version line through the MAC line). The age spec sets
/// none; a `tle` header is ~280 bytes, so this is generous and keeps a hostile
/// file from making the parser walk megabytes looking for `---`.
pub const max_header_bytes = 16 * 1024;
/// Cap on recipient stanzas in one header.
pub const max_stanzas = 64;
/// Cap on arguments in one stanza line (type included).
pub const max_stanza_args = 16;

pub const armor_begin = "-----BEGIN AGE ENCRYPTED FILE-----";
pub const armor_end = "-----END AGE ENCRYPTED FILE-----";

/// Which drand scheme a `tlock` stanza belongs to. The stanza names no scheme: the
/// body length tells (128 bytes: `sig_g1`; 80 bytes: `sig_g2`), and the caller knows
/// the scheme from the beacon's chain info, found by the stanza's chain hash.
pub const Scheme = enum {
    /// quicknet (`"bls-unchained-g1-rfc9380"`): public key in `G2`, round signature in `G1`;
    /// the stanza body is `U (G2, 96) || V || W` = 128 bytes. The functions without a suffix.
    sig_g1,
    /// `"pedersen-bls-unchained"`: public key in `G1`, round signature in `G2`;
    /// the stanza body is `U (G1, 48) || V || W` = 80 bytes. The functions with a `SigG2` suffix.
    sig_g2,
};

/// The types and the BF-IBE calls of one scheme.
fn Of(comptime s: Scheme) type {
    return switch (s) {
        .sig_g1 => struct {
            const Ct = Ciphertext;
            const PubKey = g2.Affine;
            const Signature = g1.Affine;
            fn encrypt(p_pub: PubKey, round: u64, m: *const [file_key_bytes]u8, sigma: *const [file_key_bytes]u8) Ct {
                return tlock_mod.encrypt(p_pub, round, m, sigma);
            }
            fn decrypt(out: *[file_key_bytes]u8, sig: Signature, ct: Ct) tlock_mod.DecryptError!void {
                return tlock_mod.decrypt(out, sig, ct);
            }
        },
        .sig_g2 => struct {
            const Ct = CiphertextSigG2;
            const PubKey = g1.Affine;
            const Signature = g2.Affine;
            fn encrypt(p_pub: PubKey, round: u64, m: *const [file_key_bytes]u8, sigma: *const [file_key_bytes]u8) Ct {
                return tlock_mod.encryptSigG2(p_pub, round, m, sigma);
            }
            fn decrypt(out: *[file_key_bytes]u8, sig: Signature, ct: Ct) tlock_mod.DecryptError!void {
                return tlock_mod.decryptSigG2(out, sig, ct);
            }
        },
    };
}

pub const HeaderError = error{
    /// The first line is not `age-encryption.org/v1`.
    NotAgeFile,
    /// Any syntax violation: a line that is neither a stanza, a body line,
    /// nor the MAC line; an over-long or non-canonical base64 line; an empty
    /// or non-VCHAR argument; a lone `scrypt` rule violation.
    MalformedHeader,
    /// No `---` MAC line within `max_header_bytes`.
    HeaderTooLarge,
    TooManyStanzas,
    NoTlockStanza,
    MultipleTlockStanzas,
    /// A `tlock` stanza with the wrong argument count, a round that is not a
    /// plain decimal `u64`, a chain hash that is not 64 lowercase hex digits,
    /// or a body that is not exactly 128 bytes.
    MalformedTlockStanza,
    /// The body's `U` is not a valid compressed `G2` point in the subgroup.
    InvalidCiphertext,
};

pub const ArmorError = error{
    /// Missing or misplaced BEGIN/END line, a line of the wrong width, a
    /// padding character before the last line, or non-canonical base64.
    MalformedArmor,
    NoSpaceLeft,
};

pub const DecryptError = HeaderError || error{
    /// `DecryptOptions.chain_hash` was given and the stanza names another chain.
    WrongChainHash,
    /// The round signature does not open the stanza (wrong round, wrong
    /// chain, or a tampered stanza) — `tlock.decrypt`'s FO rejection.
    FoCheckFailed,
    /// The file key opened, but the header MAC does not verify.
    HeaderMacMismatch,
    /// The payload is shorter than a nonce plus one tag, or its last chunk
    /// is shorter than a tag, or empty after a non-empty chunk.
    MalformedPayload,
    /// A payload chunk failed its Poly1305 check (tampered, truncated at a
    /// chunk boundary, or reordered). Every byte already written is wiped.
    PayloadAuthenticationFailed,
    NoSpaceLeft,
};

/// The `tlock` recipient a header names.
pub const Recipient = struct {
    /// The drand round whose signature opens the file.
    round: u64,
    /// The beacon's chain hash (identifies the network: quicknet, ...).
    chain_hash: [chain_hash_bytes]u8,
    /// The BF-IBE ciphertext of the file key; the tag is the scheme the body length says.
    ciphertext: StanzaCiphertext,
};

/// The stanza body, decoded by its length.
pub const StanzaCiphertext = union(Scheme) {
    sig_g1: Ciphertext,
    sig_g2: CiphertextSigG2,
};

/// A parsed age header.
pub const Header = struct {
    recipient: Recipient,
    mac: [mac_bytes]u8,
    /// Bytes the MAC covers: `file[0..mac_input_len]` ends with `---`.
    mac_input_len: usize,
    /// Header length including the MAC line's LF; the payload starts here.
    len: usize,

    /// Parse the header at the start of a BINARY (de-armored) age file.
    pub fn parse(file: []const u8) HeaderError!Header {
        var r: LineReader = .{ .bytes = file };
        const first = r.next() orelse return error.NotAgeFile;
        if (!std.mem.eql(u8, first, version_line)) return error.NotAgeFile;

        var found: ?Recipient = null;
        var stanzas: usize = 0;
        var saw_scrypt = false;
        var line = r.next() orelse return truncated(file);
        while (true) {
            if (std.mem.startsWith(u8, line, "---")) {
                if (line.len != 4 + 43 or line[3] != ' ') return error.MalformedHeader;
                const mac_input_len = r.line_start + 3;
                var mac: [mac_bytes]u8 = undefined;
                try decodeExact(&mac, line[4..]);
                if (saw_scrypt and stanzas != 1) return error.MalformedHeader;
                const recipient = found orelse return error.NoTlockStanza;
                return .{ .recipient = recipient, .mac = mac, .mac_input_len = mac_input_len, .len = r.pos };
            }
            if (!std.mem.startsWith(u8, line, "-> ")) return error.MalformedHeader;
            stanzas += 1;
            if (stanzas > max_stanzas) return error.TooManyStanzas;

            var args: [max_stanza_args][]const u8 = undefined;
            var n_args: usize = 0;
            var it = std.mem.splitScalar(u8, line[3..], ' ');
            while (it.next()) |arg| {
                if (arg.len == 0) return error.MalformedHeader;
                for (arg) |c| if (c < 0x21 or c > 0x7e) return error.MalformedHeader;
                if (n_args == max_stanza_args) return error.MalformedHeader;
                args[n_args] = arg;
                n_args += 1;
            }
            const is_tlock = std.mem.eql(u8, args[0], stanza_type);
            if (std.mem.eql(u8, args[0], "scrypt")) saw_scrypt = true;

            // Body: base64 lines of exactly `columns`, ended by a shorter one.
            var body: [Ciphertext.encoded_bytes]u8 = undefined; // the longer of the two bodies
            var body_len: usize = 0;
            var body_ok = true;
            while (true) {
                const bl = r.next() orelse return truncated(file);
                if (bl.len > columns) return error.MalformedHeader;
                const n = b64_raw.Decoder.calcSizeForSlice(bl) catch return error.MalformedHeader;
                var chunk: [48]u8 = undefined;
                b64_raw.Decoder.decode(chunk[0..n], bl) catch return error.MalformedHeader;
                if (is_tlock) {
                    if (body_len + n > body.len) body_ok = false else @memcpy(body[body_len..][0..n], chunk[0..n]);
                }
                body_len += n;
                if (bl.len < columns) break;
            }

            if (is_tlock) {
                if (found != null) return error.MultipleTlockStanzas;
                if (n_args != 3 or !body_ok) return error.MalformedTlockStanza;
                const ct: StanzaCiphertext = switch (body_len) {
                    Ciphertext.encoded_bytes => .{ .sig_g1 = Ciphertext.fromBytes(body) catch return error.InvalidCiphertext },
                    CiphertextSigG2.encoded_bytes => .{ .sig_g2 = CiphertextSigG2.fromBytes(body[0..CiphertextSigG2.encoded_bytes].*) catch return error.InvalidCiphertext },
                    else => return error.MalformedTlockStanza,
                };
                found = .{
                    .round = parseRound(args[1]) orelse return error.MalformedTlockStanza,
                    .chain_hash = parseChainHash(args[2]) orelse return error.MalformedTlockStanza,
                    .ciphertext = ct,
                };
            }
            line = r.next() orelse return truncated(file);
        }
    }
};

/// A header that ran out before its `---` line: too large if it hit the cap,
/// otherwise simply malformed.
fn truncated(file: []const u8) HeaderError {
    return if (file.len >= max_header_bytes) error.HeaderTooLarge else error.MalformedHeader;
}

/// LF-terminated lines over at most `max_header_bytes` of input. A line with
/// no LF before the end (or the cap) is not a line.
const LineReader = struct {
    bytes: []const u8,
    pos: usize = 0,
    line_start: usize = 0,

    fn next(self: *LineReader) ?[]const u8 {
        const limit = @min(self.bytes.len, max_header_bytes);
        if (self.pos >= limit) return null;
        const nl = std.mem.findScalarPos(u8, self.bytes[0..limit], self.pos, '\n') orelse return null;
        self.line_start = self.pos;
        self.pos = nl + 1;
        return self.bytes[self.line_start..nl];
    }
};

/// Decode canonical unpadded base64 that must yield exactly `out.len` bytes.
fn decodeExact(out: []u8, s: []const u8) HeaderError!void {
    const n = b64_raw.Decoder.calcSizeForSlice(s) catch return error.MalformedHeader;
    if (n != out.len) return error.MalformedHeader;
    b64_raw.Decoder.decode(out, s) catch return error.MalformedHeader;
}

/// `strconv.ParseUint(s, 10, 64)`'s accepted language minus its sign and
/// underscore forms: one or more ASCII digits, no overflow.
fn parseRound(s: []const u8) ?u64 {
    if (s.len == 0 or s.len > 20) return null;
    var v: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = std.math.mul(u64, v, 10) catch return null;
        v = std.math.add(u64, v, c - '0') catch return null;
    }
    return v;
}

/// `tle` writes the chain hash as lowercase hex and compares strings, so
/// uppercase is a different chain to it; refuse it here too.
fn parseChainHash(s: []const u8) ?[chain_hash_bytes]u8 {
    if (s.len != 2 * chain_hash_bytes) return null;
    for (s) |c| if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return null;
    var out: [chain_hash_bytes]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch return null;
    return out;
}

// ── key schedule ───────────────────────────────────────────────────────

fn headerMac(file_key: [file_key_bytes]u8, mac_input: []const u8) [mac_bytes]u8 {
    var hmac_key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &hmac_key);
    var prk = HkdfSha256.extract("", &file_key);
    defer std.crypto.secureZero(u8, &prk);
    HkdfSha256.expand(&hmac_key, "header", prk);
    var mac: [mac_bytes]u8 = undefined;
    HmacSha256.create(&mac, mac_input, &hmac_key);
    return mac;
}

/// Whether two header MACs are equal, in constant time.
fn macEql(a: [mac_bytes]u8, b: [mac_bytes]u8) bool {
    return std.crypto.timing_safe.eql([mac_bytes]u8, a, b);
}

fn payloadKey(file_key: [file_key_bytes]u8, nonce: [nonce_bytes]u8) [Aead.key_length]u8 {
    var prk = HkdfSha256.extract(&nonce, &file_key);
    defer std.crypto.secureZero(u8, &prk);
    var key: [Aead.key_length]u8 = undefined;
    HkdfSha256.expand(&key, "payload", prk);
    return key;
}

fn chunkNonce(counter: u64, last: bool) [Aead.nonce_length]u8 {
    var n = @as([Aead.nonce_length]u8, @splat(0));
    std.mem.writeInt(u64, n[3..11], counter, .big);
    n[11] = @intFromBool(last);
    return n;
}

// ── STREAM payload ─────────────────────────────────────────────────────

/// Sealed size of a `len`-byte plaintext (one tag per chunk, at least one chunk).
pub fn sealedLen(len: usize) usize {
    // `usize`, not inferred: at comptime `@max` narrows to the smallest type
    // holding both values (`u1` for one chunk) and the multiply overflowed.
    const chunks: usize = @max(1, std.math.divCeil(usize, len, chunk_bytes) catch unreachable);
    return len + chunks * tag_bytes;
}

/// Plaintext size of a `len`-byte sealed payload (nonce excluded), or
/// `MalformedPayload` if no plaintext seals to exactly that size.
pub fn openedLen(len: usize) error{MalformedPayload}!usize {
    if (len < tag_bytes) return error.MalformedPayload;
    const chunks = std.math.divCeil(usize, len, sealed_chunk_bytes) catch unreachable;
    const last = len - (chunks - 1) * sealed_chunk_bytes;
    if (last < tag_bytes or (last == tag_bytes and chunks > 1)) return error.MalformedPayload;
    return len - chunks * tag_bytes;
}

/// One direction of the age STREAM payload (C2SP `age.md`), one chunk at a
/// time: ChaCha20-Poly1305 per chunk of `chunk_bytes` under `key`, nonce
/// `BE88(counter) || last_flag`, empty AD. `sealPayload`/`openPayload`
/// below are the whole-buffer loops over it, so the Go-`tle` whole-file
/// KAT exercises exactly this code; a streaming caller drives it itself
/// (`timelock_envelope`'s stream format does).
///
/// The caller decides which chunk is the last one (it must look ahead one
/// byte); `sealChunk` asserts the shape rules, `openChunk` refuses a
/// violation with `error.MalformedPayload`:
/// - a non-last chunk carries exactly `chunk_bytes` of plaintext;
/// - the last chunk carries 1..`chunk_bytes`, or 0 only as the FIRST chunk
///   (the empty plaintext);
/// - nothing follows the last chunk.
pub const PayloadStream = struct {
    key: [Aead.key_length]u8,
    counter: u64 = 0,
    finished: bool = false,

    /// Into `out`: the stream holds the key, so returning one by value
    /// would leave a copy of the key in the caller's frame.
    pub fn init(out: *PayloadStream, key: *const [Aead.key_length]u8) void {
        out.* = .{ .key = key.* };
    }

    /// Seal one chunk: `out.len == plaintext.len + tag_bytes`.
    pub fn sealChunk(self: *PayloadStream, out: []u8, plaintext: []const u8, last: bool) void {
        std.debug.assert(!self.finished);
        std.debug.assert(out.len == plaintext.len + tag_bytes);
        std.debug.assert(chunkShapeOk(plaintext.len, last, self.counter));
        const n = plaintext.len;
        Aead.encrypt(out[0..n], out[n..][0..tag_bytes], plaintext, "", chunkNonce(self.counter, last), self.key);
        self.counter += 1;
        self.finished = last;
    }

    /// Open one sealed chunk into `out` (`out.len == sealed.len - tag_bytes`).
    /// On `PayloadAuthenticationFailed` `out` is zeroed (chachapoly's
    /// contract) and the stream must be abandoned.
    pub fn openChunk(self: *PayloadStream, out: []u8, sealed: []const u8, last: bool) error{ MalformedPayload, PayloadAuthenticationFailed }!void {
        if (self.finished) return error.MalformedPayload;
        if (sealed.len < tag_bytes) return error.MalformedPayload;
        const n = sealed.len - tag_bytes;
        if (!chunkShapeOk(n, last, self.counter)) return error.MalformedPayload;
        std.debug.assert(out.len == n);
        Aead.decrypt(out, sealed[0..n], sealed[n..][0..tag_bytes].*, "", chunkNonce(self.counter, last), self.key) catch
            return error.PayloadAuthenticationFailed;
        self.counter += 1;
        self.finished = last;
    }

    pub fn wipe(self: *PayloadStream) void {
        std.crypto.secureZero(u8, &self.key);
    }

    fn chunkShapeOk(n: usize, last: bool, counter: u64) bool {
        if (!last) return n == chunk_bytes;
        return n <= chunk_bytes and (n > 0 or counter == 0);
    }
};

/// The whole STREAM payload (nonce excluded) of `plaintext` under `key`:
/// `out.len == sealedLen(plaintext.len)`.
/// The body runs one frame down and is burned after (`burn.zig`).
pub fn sealPayload(out: []u8, key: *const [Aead.key_length]u8, plaintext: []const u8) void {
    burn.run(burn.payload_burn, void, sealPayloadBody, .{ out, key, plaintext });
}

fn sealPayloadBody(out: []u8, key: *const [Aead.key_length]u8, plaintext: []const u8) void {
    std.debug.assert(out.len == sealedLen(plaintext.len));
    var stream: PayloadStream = undefined;
    stream.init(key);
    defer stream.wipe();
    var in_off: usize = 0;
    var out_off: usize = 0;
    while (true) {
        const n = @min(chunk_bytes, plaintext.len - in_off);
        const last = in_off + n == plaintext.len;
        stream.sealChunk(out[out_off..][0 .. n + tag_bytes], plaintext[in_off..][0..n], last);
        in_off += n;
        out_off += n + tag_bytes;
        if (last) break;
    }
}

/// Open a whole STREAM payload (nonce excluded): `out.len ==
/// try openedLen(sealed.len)`. On failure every byte already written is wiped.
/// The body runs one frame down and is burned after (`burn.zig`).
pub fn openPayload(out: []u8, key: *const [Aead.key_length]u8, sealed: []const u8) error{ MalformedPayload, PayloadAuthenticationFailed }!void {
    return burn.run(burn.payload_burn, error{ MalformedPayload, PayloadAuthenticationFailed }!void, openPayloadBody, .{ out, key, sealed });
}

fn openPayloadBody(out: []u8, key: *const [Aead.key_length]u8, sealed: []const u8) error{ MalformedPayload, PayloadAuthenticationFailed }!void {
    std.debug.assert(out.len == try openedLen(sealed.len));
    var stream: PayloadStream = undefined;
    stream.init(key);
    defer stream.wipe();
    var in_off: usize = 0;
    var out_off: usize = 0;
    while (true) {
        const rest = sealed.len - in_off;
        const last = rest <= sealed_chunk_bytes;
        const c = sealed[in_off..][0..@min(rest, sealed_chunk_bytes)];
        const n = c.len - tag_bytes;
        stream.openChunk(out[out_off..][0..n], c, last) catch |err| {
            std.crypto.secureZero(u8, out[0..out_off]);
            return err;
        };
        in_off += c.len;
        out_off += n;
        if (last) return;
    }
}

// ── encrypt ────────────────────────────────────────────────────────────

/// The three random values one encryption draws. Explicit, like
/// `tlock.encrypt`'s `sigma`, so a fixed set reproduces a file byte-exactly.
pub const Randomness = struct {
    file_key: [file_key_bytes]u8,
    sigma: [tlock_mod.block_bytes]u8,
    nonce: [nonce_bytes]u8,

    /// Production: all three from `entropy.fill` (fail-closed CSPRNG),
    /// drawn straight into `out` (the file key and sigma are secrets).
    pub fn draw(out: *Randomness, io: std.Io) void {
        entropy.fill(io, &out.file_key);
        entropy.fill(io, &out.sigma);
        entropy.fill(io, &out.nonce);
    }

    /// Zero the secrets (`file_key`, `sigma`) once the file is written.
    pub fn wipe(self: *Randomness) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

fn stanzaBodyLen(comptime sch: Scheme) usize {
    const enc = b64_raw.Encoder.calcSize(Of(sch).Ct.encoded_bytes);
    return enc + enc / columns + 1; // LF per full line, plus the short (maybe empty) last line's
}

fn headerLenOf(comptime sch: Scheme, round: u64) usize {
    return version_line.len + 1 +
        "-> tlock ".len + std.fmt.count("{d}", .{round}) + 1 + 2 * chain_hash_bytes + 1 +
        stanzaBodyLen(sch) +
        "--- ".len + b64_raw.Encoder.calcSize(mac_bytes) + 1;
}

fn headerLen(round: u64) usize {
    return headerLenOf(.sig_g1, round);
}

/// Exact size of `encrypt`'s (binary, unarmored) output.
pub fn encryptedLen(round: u64, plaintext_len: usize) usize {
    return headerLen(round) + nonce_bytes + sealedLen(plaintext_len);
}

/// `encryptedLen` of the G2-signature scheme (an 80-byte stanza body).
pub fn encryptedLenSigG2(round: u64, plaintext_len: usize) usize {
    return headerLenOf(.sig_g2, round) + nonce_bytes + sealedLen(plaintext_len);
}

/// Encrypt `plaintext` to `round` of the beacon with public key `p_pub` and
/// chain hash `chain_hash`, writing the binary age file `tle` writes
/// (without `-a`). Returns `out[0..encryptedLen(round, plaintext.len)]`.
pub fn encrypt(
    out: []u8,
    plaintext: []const u8,
    p_pub: g2.Affine,
    round: u64,
    chain_hash: [chain_hash_bytes]u8,
    rnd: *const Randomness,
) error{NoSpaceLeft}![]u8 {
    return encryptOf(.sig_g1, out, plaintext, p_pub, round, chain_hash, rnd);
}

/// `encrypt` for the G2-signature scheme (`"pedersen-bls-unchained"`): `p_pub` is the
/// beacon's `G1` public key, the stanza body 80 bytes (`encryptedLenSigG2`).
pub fn encryptSigG2(
    out: []u8,
    plaintext: []const u8,
    p_pub: g1.Affine,
    round: u64,
    chain_hash: [chain_hash_bytes]u8,
    rnd: *const Randomness,
) error{NoSpaceLeft}![]u8 {
    return encryptOf(.sig_g2, out, plaintext, p_pub, round, chain_hash, rnd);
}

fn encryptOf(
    comptime sch: Scheme,
    out: []u8,
    plaintext: []const u8,
    p_pub: Of(sch).PubKey,
    round: u64,
    chain_hash: [chain_hash_bytes]u8,
    rnd: *const Randomness,
) error{NoSpaceLeft}![]u8 {
    const total = headerLenOf(sch, round) + nonce_bytes + sealedLen(plaintext.len);
    if (out.len < total) return error.NoSpaceLeft;
    // The body runs one frame down and is burned after (`burn.zig`): it holds
    // the file key, the header-MAC and payload keys.
    burn.run(burn.crypt_burn, void, encryptBody, .{ sch, out[0..total], plaintext, p_pub, round, chain_hash, rnd });
    return out[0..total];
}

fn encryptBody(comptime sch: Scheme, out: []u8, plaintext: []const u8, p_pub: Of(sch).PubKey, round: u64, chain_hash: [chain_hash_bytes]u8, rnd: *const Randomness) void {
    const head_len = headerLenOf(sch, round) + nonce_bytes;
    writeHead(sch, out[0..head_len], p_pub, round, chain_hash, rnd);
    var key = payloadKey(rnd.file_key, rnd.nonce);
    defer std.crypto.secureZero(u8, &key);
    sealPayloadBody(out[head_len..], &key, plaintext);
}

/// The header (with its MAC) and the payload nonce into `out`, which is
/// exactly `headerLenOf(sch, round) + nonce_bytes` long.
fn writeHead(comptime sch: Scheme, out: []u8, p_pub: Of(sch).PubKey, round: u64, chain_hash: [chain_hash_bytes]u8, rnd: *const Randomness) void {
    const ct = Of(sch).encrypt(p_pub, round, &rnd.file_key, &rnd.sigma).toBytes();

    var w: std.Io.Writer = .fixed(out);
    const chain_hex = std.fmt.bytesToHex(chain_hash, .lower);
    w.print("{s}\n-> {s} {d} {s}\n", .{ version_line, stanza_type, round, &chain_hex }) catch unreachable;
    var enc: [b64_raw.Encoder.calcSize(Of(sch).Ct.encoded_bytes)]u8 = undefined;
    _ = b64_raw.Encoder.encode(&enc, &ct);
    var i: usize = 0;
    while (true) : (i += columns) {
        const line = enc[i..@min(enc.len, i + columns)];
        w.print("{s}\n", .{line}) catch unreachable;
        if (line.len < columns) break;
    }
    w.writeAll("---") catch unreachable;
    const mac = headerMac(rnd.file_key, w.buffered());
    var mac_b64: [b64_raw.Encoder.calcSize(mac_bytes)]u8 = undefined;
    w.print(" {s}\n", .{b64_raw.Encoder.encode(&mac_b64, &mac)}) catch unreachable;
    w.writeAll(&rnd.nonce) catch unreachable;
    std.debug.assert(w.end == out.len);
}

pub const EncryptOptions = struct {
    /// Wrap the file in ASCII armor (`tle -a`).
    armor: bool = false,
};

/// `encrypt`, into a fresh allocation the caller frees.
pub fn encryptAlloc(
    gpa: std.mem.Allocator,
    plaintext: []const u8,
    p_pub: g2.Affine,
    round: u64,
    chain_hash: [chain_hash_bytes]u8,
    rnd: *const Randomness,
    opts: EncryptOptions,
) error{OutOfMemory}![]u8 {
    return encryptAllocOf(.sig_g1, gpa, plaintext, p_pub, round, chain_hash, rnd, opts);
}

/// `encryptAlloc` for the G2-signature scheme.
pub fn encryptAllocSigG2(
    gpa: std.mem.Allocator,
    plaintext: []const u8,
    p_pub: g1.Affine,
    round: u64,
    chain_hash: [chain_hash_bytes]u8,
    rnd: *const Randomness,
    opts: EncryptOptions,
) error{OutOfMemory}![]u8 {
    return encryptAllocOf(.sig_g2, gpa, plaintext, p_pub, round, chain_hash, rnd, opts);
}

fn encryptAllocOf(
    comptime sch: Scheme,
    gpa: std.mem.Allocator,
    plaintext: []const u8,
    p_pub: Of(sch).PubKey,
    round: u64,
    chain_hash: [chain_hash_bytes]u8,
    rnd: *const Randomness,
    opts: EncryptOptions,
) error{OutOfMemory}![]u8 {
    const bin = try gpa.alloc(u8, headerLenOf(sch, round) + nonce_bytes + sealedLen(plaintext.len));
    _ = encryptOf(sch, bin, plaintext, p_pub, round, chain_hash, rnd) catch unreachable;
    if (!opts.armor) return bin;
    defer gpa.free(bin);
    const arm = try gpa.alloc(u8, armoredLen(bin.len));
    _ = armor(arm, bin) catch unreachable;
    return arm;
}

// ── decrypt ────────────────────────────────────────────────────────────

pub const DecryptOptions = struct {
    /// If set, refuse a file whose stanza names a different chain (what
    /// `tle` does against its configured network) before any pairing runs.
    chain_hash: ?[chain_hash_bytes]u8 = null,
};

/// Exact plaintext size of a BINARY age file, from its header and length.
pub fn decryptedLen(file: []const u8) DecryptError!usize {
    const h = try Header.parse(file);
    if (file.len - h.len < nonce_bytes) return error.MalformedPayload;
    return openedLen(file.len - h.len - nonce_bytes);
}

/// Decrypt a BINARY age file with the published `round_signature` for the
/// round its `tlock` stanza names (`Header.parse(file).recipient.round`).
/// Order: header syntax, chain hash, stanza (FO check), header MAC, then the
/// payload chunk by chunk. Returns `out[0..decryptedLen(file)]`.
///
/// The key schedule runs one frame down and is burned after (`burn.zig`).
pub fn decrypt(out: []u8, file: []const u8, round_signature: g1.Affine, opts: DecryptOptions) DecryptError![]u8 {
    return decryptOf(.sig_g1, out, file, round_signature, opts);
}

/// `decrypt` for the G2-signature scheme: `round_signature` is the beacon's `G2`
/// signature; a stanza body that is not the 80 bytes of that scheme is
/// `error.InvalidCiphertext` (as `decrypt` for an 80-byte one).
pub fn decryptSigG2(out: []u8, file: []const u8, round_signature: g2.Affine, opts: DecryptOptions) DecryptError![]u8 {
    return decryptOf(.sig_g2, out, file, round_signature, opts);
}

fn decryptOf(comptime sch: Scheme, out: []u8, file: []const u8, round_signature: Of(sch).Signature, opts: DecryptOptions) DecryptError![]u8 {
    return burn.run(burn.crypt_burn, DecryptError![]u8, decryptBody, .{ sch, out, file, round_signature, opts });
}

/// The stanza's ciphertext as scheme `sch`'s type, or `InvalidCiphertext` when its body was the other scheme's.
fn stanzaCt(comptime sch: Scheme, r: Recipient) HeaderError!Of(sch).Ct {
    if (r.ciphertext != sch) return error.InvalidCiphertext;
    return @field(r.ciphertext, @tagName(sch));
}

fn decryptBody(comptime sch: Scheme, out: []u8, file: []const u8, round_signature: Of(sch).Signature, opts: DecryptOptions) DecryptError![]u8 {
    const h = try Header.parse(file);
    if (opts.chain_hash) |want| {
        if (!std.mem.eql(u8, &want, &h.recipient.chain_hash)) return error.WrongChainHash;
    }
    if (file.len - h.len < nonce_bytes) return error.MalformedPayload;
    const sealed = file[h.len + nonce_bytes ..];
    const n = try openedLen(sealed.len);
    if (out.len < n) return error.NoSpaceLeft;

    var file_key: [file_key_bytes]u8 = undefined;
    try Of(sch).decrypt(&file_key, round_signature, try stanzaCt(sch, h.recipient));
    defer std.crypto.secureZero(u8, &file_key);
    const mac = headerMac(file_key, file[0..h.mac_input_len]);
    if (!macEql(mac, h.mac)) return error.HeaderMacMismatch;

    var key = payloadKey(file_key, file[h.len..][0..nonce_bytes].*);
    defer std.crypto.secureZero(u8, &key);
    try openPayloadBody(out[0..n], &key, sealed);
    return out[0..n];
}

/// `decrypt` for a binary OR armored file (detected by `isArmored`), into a
/// fresh allocation the caller frees.
pub fn decryptAlloc(gpa: std.mem.Allocator, file: []const u8, round_signature: g1.Affine, opts: DecryptOptions) (DecryptError || ArmorError || error{OutOfMemory})![]u8 {
    return decryptAllocOf(.sig_g1, gpa, file, round_signature, opts);
}

/// `decryptAlloc` for the G2-signature scheme.
pub fn decryptAllocSigG2(gpa: std.mem.Allocator, file: []const u8, round_signature: g2.Affine, opts: DecryptOptions) (DecryptError || ArmorError || error{OutOfMemory})![]u8 {
    return decryptAllocOf(.sig_g2, gpa, file, round_signature, opts);
}

fn decryptAllocOf(comptime sch: Scheme, gpa: std.mem.Allocator, file: []const u8, round_signature: Of(sch).Signature, opts: DecryptOptions) (DecryptError || ArmorError || error{OutOfMemory})![]u8 {
    var scratch: ?[]u8 = null;
    defer if (scratch) |s| gpa.free(s);
    var bin = file;
    if (isArmored(file)) {
        scratch = try gpa.alloc(u8, dearmoredLenMax(file.len));
        bin = try dearmor(scratch.?, file);
    }
    const out = try gpa.alloc(u8, try decryptedLen(bin));
    errdefer gpa.free(out);
    _ = try decryptOf(sch, out, bin, round_signature, opts);
    return out;
}

/// The `tlock` recipient of a binary or armored file — which round's
/// signature to fetch — without decrypting anything.
pub fn inspectAlloc(gpa: std.mem.Allocator, file: []const u8) (HeaderError || ArmorError || error{OutOfMemory})!Recipient {
    if (!isArmored(file)) return (try Header.parse(file)).recipient;
    const scratch = try gpa.alloc(u8, dearmoredLenMax(file.len));
    defer gpa.free(scratch);
    return (try Header.parse(try dearmor(scratch, file))).recipient;
}

// ── streaming encrypt / decrypt ────────────────────────────────────────
//
// `tlock.New(network).Encrypt(dst io.Writer, src io.Reader, round)` and
// `.Decrypt(dst, src)` of drand/tlock (Go), over `std.Io.Reader`/`Writer`: the
// binary age file, one 64 KiB STREAM chunk at a time, so memory is bounded
// (one allocation of about 128 KiB) however large the file is. Armor is not
// streamed (`encryptAlloc`/`decryptAlloc` keep it): `tle` armors through a
// separate writer in front of this one; `ArmorWriter` / `ArmorReader` are
// that writer and its reader.

/// Streaming armor (`armor_stream.zig`): a `std.Io.Writer` that armors and a
/// `std.Io.Reader` that de-armors, to compose with `encryptStream` /
/// `decryptStream` (age's `armor.NewWriter` / `armor.NewReader`).
pub const ArmorWriter = @import("armor_stream.zig").ArmorWriter;
pub const ArmorReader = @import("armor_stream.zig").ArmorReader;

/// Errors of `encryptStream`: the reader or the writer failed, or the one
/// chunk buffer could not be allocated.
pub const EncryptStreamError = error{ ReadFailed, WriteFailed, OutOfMemory };

/// Errors of `decryptStream`: `DecryptError`'s, less `NoSpaceLeft`, plus the
/// reader's and the writer's failures and the chunk buffer's allocation.
pub const DecryptStreamError = HeaderError || tlock_mod.DecryptError || error{
    WrongChainHash,
    HeaderMacMismatch,
    MalformedPayload,
    PayloadAuthenticationFailed,
    ReadFailed,
    WriteFailed,
    OutOfMemory,
};

/// The stream form of `encrypt`: read `r` to its end and write the binary age
/// file to `w`, byte for byte what `encrypt` of the same bytes under the same
/// `rnd` produces (`encryptedLen`). The header is written first, then each
/// chunk once the next byte (or the end) proves whether it is the last.
/// `w` is not flushed; `r` is read to its end, not closed. A failed `r` or `w`
/// ends the call with `ReadFailed`/`WriteFailed` (the reader's or writer's
/// own error is where the cause is); what reached `w` before that is a
/// prefix of the file.
pub fn encryptStream(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    r: *std.Io.Reader,
    p_pub: g2.Affine,
    round: u64,
    chain_hash: [chain_hash_bytes]u8,
    rnd: *const Randomness,
) EncryptStreamError!void {
    return burn.run(burn.crypt_burn, EncryptStreamError!void, encryptStreamBody, .{ .sig_g1, gpa, w, r, p_pub, round, chain_hash, rnd });
}

/// `encryptStream` for the G2-signature scheme.
pub fn encryptStreamSigG2(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    r: *std.Io.Reader,
    p_pub: g1.Affine,
    round: u64,
    chain_hash: [chain_hash_bytes]u8,
    rnd: *const Randomness,
) EncryptStreamError!void {
    return burn.run(burn.crypt_burn, EncryptStreamError!void, encryptStreamBody, .{ .sig_g2, gpa, w, r, p_pub, round, chain_hash, rnd });
}

fn encryptStreamBody(
    comptime sch: Scheme,
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    r: *std.Io.Reader,
    p_pub: Of(sch).PubKey,
    round: u64,
    chain_hash: [chain_hash_bytes]u8,
    rnd: *const Randomness,
) EncryptStreamError!void {
    const head_max = comptime headerLenOf(sch, std.math.maxInt(u64)) + nonce_bytes;
    const head_len = headerLenOf(sch, round) + nonce_bytes;
    var head: [head_max]u8 = undefined;
    writeHead(sch, head[0..head_len], p_pub, round, chain_hash, rnd);
    try w.writeAll(head[0..head_len]);

    var key = payloadKey(rnd.file_key, rnd.nonce);
    defer std.crypto.secureZero(u8, &key);
    var stream: PayloadStream = undefined;
    stream.init(&key);
    defer stream.wipe();

    // One more plaintext byte than a chunk holds: that byte is what says the
    // chunk before it is not the last (no peek, so an unbuffered reader works).
    const buf = try gpa.alloc(u8, (chunk_bytes + 1) + sealed_chunk_bytes);
    defer {
        std.crypto.secureZero(u8, buf);
        gpa.free(buf);
    }
    const plain = buf[0 .. chunk_bytes + 1];
    const sealed = buf[chunk_bytes + 1 ..];
    var have: usize = 0;
    while (true) {
        have += try r.readSliceShort(plain[have..]);
        const last = have <= chunk_bytes;
        const n = if (last) have else chunk_bytes;
        stream.sealChunk(sealed[0 .. n + tag_bytes], plain[0..n], last);
        try w.writeAll(sealed[0 .. n + tag_bytes]);
        if (last) return;
        plain[0] = plain[chunk_bytes];
        have = 1;
    }
}

/// The stream form of `decrypt`: read a binary age file from `r` to its end
/// and write the plaintext to `w`. Order as in `decrypt` (header syntax,
/// chain hash, stanza FO check, header MAC, then the payload chunk by chunk),
/// with the differences a stream cannot avoid: the header is read up to its
/// MAC line (`max_header_bytes` at most) before anything is parsed, so a
/// malformed header can report `HeaderTooLarge` or `MalformedHeader` where
/// `decrypt` names the first bad line; and the payload length is unknown
/// until the end, so `MalformedPayload` for a payload that is too short comes
/// after the FO check and the MAC, not before. Every chunk is authenticated
/// before it is written, but a chunk written is written: a tampered or
/// truncated file fails at its bad chunk or at its end (truncation at a chunk
/// boundary is caught by the last-chunk flag of the chunk before), and the
/// plaintext before that point has already reached `w`; a caller that must not
/// act on unverified output buffers it until this returns. `w` is not flushed.
pub fn decryptStream(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    r: *std.Io.Reader,
    round_signature: g1.Affine,
    opts: DecryptOptions,
) DecryptStreamError!void {
    return burn.run(burn.crypt_burn, DecryptStreamError!void, decryptStreamBody, .{ .sig_g1, gpa, w, r, round_signature, opts });
}

/// `decryptStream` for the G2-signature scheme.
pub fn decryptStreamSigG2(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    r: *std.Io.Reader,
    round_signature: g2.Affine,
    opts: DecryptOptions,
) DecryptStreamError!void {
    return burn.run(burn.crypt_burn, DecryptStreamError!void, decryptStreamBody, .{ .sig_g2, gpa, w, r, round_signature, opts });
}

fn decryptStreamBody(
    comptime sch: Scheme,
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    r: *std.Io.Reader,
    round_signature: Of(sch).Signature,
    opts: DecryptOptions,
) DecryptStreamError!void {
    // The header, up to and including the LF of its MAC line.
    var head: [max_header_bytes]u8 = undefined;
    var n: usize = 0;
    var line_start: usize = 0;
    while (true) {
        // One byte at a time through `readSliceShort`, not `takeByte`: that one
        // needs a reader with a buffer, and this works on an unbuffered one too.
        var one: [1]u8 = undefined;
        if (try r.readSliceShort(&one) == 0) {
            // Ran out: name the fault the in-memory parser names for these bytes.
            _ = try Header.parse(head[0..n]);
            return error.MalformedHeader;
        }
        const b = one[0];
        if (n == max_header_bytes) return error.HeaderTooLarge;
        head[n] = b;
        n += 1;
        if (b != '\n') continue;
        const line = head[line_start..n];
        if (line_start == 0 and !std.mem.eql(u8, line, version_line ++ "\n")) return error.NotAgeFile;
        if (std.mem.startsWith(u8, line, "---")) break;
        line_start = n;
    }
    const h = try Header.parse(head[0..n]);
    if (h.len != n) return error.MalformedHeader;
    if (opts.chain_hash) |want| {
        if (!std.mem.eql(u8, &want, &h.recipient.chain_hash)) return error.WrongChainHash;
    }
    var nonce: [nonce_bytes]u8 = undefined;
    r.readSliceAll(&nonce) catch |err| switch (err) {
        error.ReadFailed => return error.ReadFailed,
        error.EndOfStream => return error.MalformedPayload,
    };

    var file_key: [file_key_bytes]u8 = undefined;
    try Of(sch).decrypt(&file_key, round_signature, try stanzaCt(sch, h.recipient));
    defer std.crypto.secureZero(u8, &file_key);
    const mac = headerMac(file_key, head[0..h.mac_input_len]);
    if (!macEql(mac, h.mac)) return error.HeaderMacMismatch;

    var key = payloadKey(file_key, nonce);
    defer std.crypto.secureZero(u8, &key);
    var stream: PayloadStream = undefined;
    stream.init(&key);
    defer stream.wipe();

    // As in `encryptStream`: one byte past a sealed chunk says it is not the last.
    const buf = try gpa.alloc(u8, (sealed_chunk_bytes + 1) + chunk_bytes);
    defer {
        std.crypto.secureZero(u8, buf);
        gpa.free(buf);
    }
    const sealed = buf[0 .. sealed_chunk_bytes + 1];
    const plain = buf[sealed_chunk_bytes + 1 ..];
    var have: usize = 0;
    while (true) {
        have += try r.readSliceShort(sealed[have..]);
        const last = have <= sealed_chunk_bytes;
        const c = if (last) have else sealed_chunk_bytes;
        if (c < tag_bytes) return error.MalformedPayload;
        try stream.openChunk(plain[0 .. c - tag_bytes], sealed[0..c], last);
        try w.writeAll(plain[0 .. c - tag_bytes]);
        if (last) return;
        sealed[0] = sealed[sealed_chunk_bytes];
        have = 1;
    }
}

// ── ASCII armor ────────────────────────────────────────────────────────

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

/// True if `bytes`, after leading whitespace, starts with the BEGIN line.
pub fn isArmored(bytes: []const u8) bool {
    var i: usize = 0;
    while (i < bytes.len and isSpace(bytes[i])) i += 1;
    return std.mem.startsWith(u8, bytes[i..], armor_begin);
}

/// Exact size of `armor`'s output for `len` input bytes.
pub fn armoredLen(len: usize) usize {
    const enc = b64_pad.Encoder.calcSize(len);
    const lines = std.math.divCeil(usize, enc, columns) catch unreachable;
    return armor_begin.len + 1 + enc + lines + armor_end.len + 1;
}

/// Armor a binary age file the way `tle -a` writes it. Returns `out[0..armoredLen(bin.len)]`.
pub fn armor(out: []u8, bin: []const u8) error{NoSpaceLeft}![]u8 {
    const total = armoredLen(bin.len);
    if (out.len < total) return error.NoSpaceLeft;
    var w: std.Io.Writer = .fixed(out[0..total]);
    w.writeAll(armor_begin ++ "\n") catch unreachable;
    var i: usize = 0;
    const per_line = columns / 4 * 3; // 48 input bytes -> one 64-column line
    while (i < bin.len) : (i += per_line) {
        var line: [columns]u8 = undefined;
        w.print("{s}\n", .{b64_pad.Encoder.encode(&line, bin[i..@min(bin.len, i + per_line)])}) catch unreachable;
    }
    w.writeAll(armor_end ++ "\n") catch unreachable;
    std.debug.assert(w.end == total);
    return out[0..total];
}

/// An upper bound on `dearmor`'s output for `len` armored bytes.
pub fn dearmoredLenMax(len: usize) usize {
    return len / 4 * 3 + 3;
}

/// Undo `armor`. Accepts surrounding whitespace and CRLF line endings;
/// otherwise strict: every line but the last exactly 64 columns, padding
/// only on the last line, canonical base64, nothing after the END line but
/// whitespace.
pub fn dearmor(out: []u8, armored: []const u8) ArmorError![]u8 {
    var s = std.mem.trim(u8, armored, " \t\r\n");
    if (!std.mem.startsWith(u8, s, armor_begin) or !std.mem.endsWith(u8, s, armor_end)) return error.MalformedArmor;
    if (s.len < armor_begin.len + armor_end.len + 2) return error.MalformedArmor;
    s = s[armor_begin.len .. s.len - armor_end.len];
    // `s` is now "\n<lines>\n" (or with CRs); it must start and end with a newline.
    s = if (std.mem.startsWith(u8, s, "\r\n")) s[2..] else if (std.mem.startsWith(u8, s, "\n")) s[1..] else return error.MalformedArmor;
    if (!std.mem.endsWith(u8, s, "\n")) return error.MalformedArmor;
    s = s[0 .. s.len - 1];
    if (s.len == 0) return error.MalformedArmor;

    var o: usize = 0;
    var it = std.mem.splitScalar(u8, s, '\n');
    while (it.next()) |raw| {
        const line = if (std.mem.endsWith(u8, raw, "\r")) raw[0 .. raw.len - 1] else raw;
        const is_last = it.peek() == null;
        if (line.len == 0 or line.len > columns) return error.MalformedArmor;
        if (!is_last and (line.len != columns or std.mem.findScalar(u8, line, '=') != null)) return error.MalformedArmor;
        const n = b64_pad.Decoder.calcSizeForSlice(line) catch return error.MalformedArmor;
        if (out.len - o < n) return error.NoSpaceLeft;
        b64_pad.Decoder.decode(out[o..][0..n], line) catch return error.MalformedArmor;
        o += n;
    }
    return out[0..o];
}

// ── tests ──────────────────────────────────────────────────────────────
//
// Anchors, honestly: the `tlock` stanza body, the round, the chain hash and
// the file key below are the GENUINE values of `drand/tlock`'s
// `lorem-tle-testnet-quicknet-t-2024-01-17-15-28.tle` (see `kat_test.zig`
// section 3 and NOTICE) — EXTERNAL. The header MAC, the STREAM payload and
// the armor bytes these tests produce are SELF-DERIVED from the age spec:
// that `.tle` file's full bytes are not in this tree, so no test here
// compares a whole file against Go output. The primitives underneath are
// anchored where they live: ChaCha20-Poly1305 against RFC 8439 in
// `chachapoly`, HKDF/HMAC-SHA-256 against RFC 5869/4231 in std.

const testing = std.testing;

fn hexBytes(comptime n: usize, comptime hex: []const u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// quicknet mainnet: public key and round-1000 signature (kat_test.zig section 1).
const quicknet_chain = hexBytes(32, "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971");
const quicknet_pub = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
const round_1000_sig = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";

// quicknet-t testnet: the genuine `tle` fixture's values (kat_test.zig section 3).
const qt_chain_hex = "cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5";
const qt_pub = "b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da";
const qt_round: u64 = 5423142;
const qt_sig = "96fce8e2f70e2784577c8f2d8bd36af7a4b0dfd73dd91469d8556b36d2973a4f84681a45b1af2ce0511e5a32dd72508f";
const qt_stanza_body = "87333e1baaf45ffafbaac29e472ae0974986e9d6028fb4b15cc470fdc7d412131733f6c867c7bc56ed52b6ae85196b4b0d156e65ba0038b3c6521017b3aed0c45f31011db4a326cc75f4f4a8d78ded24715853d25d7acee2ee98a8a01d8b0d20868992a49bbb8dfa7756f8a804930fe58c997398f72fe8c72da3aab6984f2c9c";
const qt_file_key = "2088b21b7778175ecb9349dd98737373";
const qt_sigma = "7f4a8bfc5ae6e845ee01773a45dd92ae";

fn pub1000() g2.Affine {
    return g2.fromBytesCompressed(hexBytes(96, quicknet_pub)) catch unreachable;
}
fn sig1000() g1.Affine {
    return g1.fromBytesCompressed(hexBytes(48, round_1000_sig)) catch unreachable;
}

const fixed_rnd: Randomness = .{
    .file_key = @as([16]u8, @splat(0x42)),
    .sigma = @as([16]u8, @splat(0x11)),
    .nonce = @as([16]u8, @splat(0x99)),
};

/// One file per length class, all opened under the real round-1000 signature.
fn roundTrip(len: usize, armored: bool) !void {
    const gpa = testing.allocator;
    const pt = try gpa.alloc(u8, len);
    defer gpa.free(pt);
    for (pt, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);

    const file = try encryptAlloc(gpa, pt, pub1000(), 1000, quicknet_chain, &fixed_rnd, .{ .armor = armored });
    defer gpa.free(file);
    try testing.expectEqual(armored, isArmored(file));

    const back = try decryptAlloc(gpa, file, sig1000(), .{ .chain_hash = quicknet_chain });
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, pt, back);
}

test "age: tlock stanza body is the genuine tle fixture's 128 bytes (EXTERNAL), and the header parses back" {
    const p_pub = try g2.fromBytesCompressed(hexBytes(96, qt_pub));
    const rnd: Randomness = .{ .file_key = hexBytes(16, qt_file_key), .sigma = hexBytes(16, qt_sigma), .nonce = @as([16]u8, @splat(0)) };
    var buf: [1024]u8 = undefined;
    const file = try encrypt(&buf, "lorem", p_pub, qt_round, hexBytes(32, qt_chain_hex), &rnd);

    // The stanza line and body exactly as the age grammar and `tle` lay them out.
    const want_body = hexBytes(128, qt_stanza_body);
    var b64: [171]u8 = undefined;
    _ = b64_raw.Encoder.encode(&b64, &want_body);
    const want_prefix = version_line ++ "\n-> tlock 5423142 " ++ qt_chain_hex ++ "\n";
    try testing.expectStringStartsWith(file, want_prefix);
    const body_text = file[want_prefix.len..][0 .. 171 + 3];
    try testing.expectEqualStrings(b64[0..64], body_text[0..64]);
    try testing.expectEqualStrings(b64[64..128], body_text[65..129]);
    try testing.expectEqualStrings(b64[128..171], body_text[130..173]);
    try testing.expectStringStartsWith(file[want_prefix.len + 174 ..], "--- ");

    const h = try Header.parse(file);
    try testing.expectEqual(qt_round, h.recipient.round);
    try testing.expectEqualSlices(u8, &want_body, &h.recipient.ciphertext.sig_g1.toBytes());
    try testing.expectEqual(headerLen(qt_round), h.len);

    // ...and it opens under the genuine published round signature.
    var out: [16]u8 = undefined;
    const pt = try decrypt(&out, file, try g1.fromBytesCompressed(hexBytes(48, qt_sig)), .{});
    try testing.expectEqualStrings("lorem", pt);
}

test "age: round trip across the chunk boundaries, binary and armored" {
    for ([_]usize{ 0, 1, chunk_bytes - 1, chunk_bytes, chunk_bytes + 1, 2 * chunk_bytes, 2 * chunk_bytes + 5 }) |len| {
        try roundTrip(len, false);
        try roundTrip(len, true);
    }
}

// ── streaming ─────────────────────────────────────────────────────────

/// A reader whose `stream` always fails: the cause of a `ReadFailed`.
fn failingReader() std.Io.Reader {
    const V = struct {
        fn stream(_: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
            return error.ReadFailed;
        }
    };
    return .{ .vtable = &.{ .stream = V.stream }, .buffer = &.{}, .seek = 0, .end = 0 };
}

fn streamPlain(pt: []u8) void {
    for (pt, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
}

/// `encryptStream` of `pt` through a reader that hands out at most 7 bytes at
/// a time, into a fresh allocation.
fn streamEncrypt(gpa: std.mem.Allocator, pt: []const u8) ![]u8 {
    var src: std.Io.Reader = .fixed(pt);
    var small: [7]u8 = undefined;
    var slow = src.limited(.unlimited, &small);
    var sink: std.Io.Writer.Allocating = .init(gpa);
    errdefer sink.deinit();
    try encryptStream(gpa, &sink.writer, &slow.interface, pub1000(), 1000, quicknet_chain, &fixed_rnd);
    return sink.toOwnedSlice();
}

fn streamDecrypt(gpa: std.mem.Allocator, file: []const u8, sig: g1.Affine, opts: DecryptOptions) ![]u8 {
    var src: std.Io.Reader = .fixed(file);
    var small: [13]u8 = undefined;
    var slow = src.limited(.unlimited, &small);
    var sink: std.Io.Writer.Allocating = .init(gpa);
    errdefer sink.deinit();
    try decryptStream(gpa, &sink.writer, &slow.interface, sig, opts);
    return sink.toOwnedSlice();
}

test "age: encryptStream through ArmorWriter is encryptAlloc's armored file; decryptStream through ArmorReader reads it back" {
    const gpa = testing.allocator;
    for ([_]usize{ 0, 1, 100, chunk_bytes + 1 }) |len| {
        const pt = try gpa.alloc(u8, len);
        defer gpa.free(pt);
        streamPlain(pt);
        const want = try encryptAlloc(gpa, pt, pub1000(), 1000, quicknet_chain, &fixed_rnd, .{ .armor = true });
        defer gpa.free(want);
        var src: std.Io.Reader = .fixed(pt);
        var sink: std.Io.Writer.Allocating = .init(gpa);
        defer sink.deinit();
        var abuf: [64]u8 = undefined;
        var aw = ArmorWriter.init(&sink.writer, &abuf);
        try encryptStream(gpa, &aw.writer, &src, pub1000(), 1000, quicknet_chain, &fixed_rnd);
        try aw.finish();
        try testing.expectEqualStrings(want, sink.written());

        var in: std.Io.Reader = .fixed(sink.written());
        var rbuf: [128]u8 = undefined;
        var ar = ArmorReader.init(&in, &rbuf);
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        try decryptStream(gpa, &out.writer, &ar.reader, sig1000(), .{});
        try testing.expectEqualSlices(u8, pt, out.written());
    }
}

test "age: encryptStream writes exactly what encrypt writes, and decryptStream reads it back, across the chunk boundaries" {
    const gpa = testing.allocator;
    const lens = [_]usize{ 0, 1, chunk_bytes - 1, chunk_bytes, chunk_bytes + 1, 2 * chunk_bytes, 2 * chunk_bytes + 1 };
    for (lens) |len| {
        const pt = try gpa.alloc(u8, len);
        defer gpa.free(pt);
        streamPlain(pt);

        const whole = try encryptAlloc(gpa, pt, pub1000(), 1000, quicknet_chain, &fixed_rnd, .{});
        defer gpa.free(whole);
        const streamed = try streamEncrypt(gpa, pt);
        defer gpa.free(streamed);
        try testing.expectEqualSlices(u8, whole, streamed);
        try testing.expectEqual(encryptedLen(1000, len), streamed.len);

        const back = try streamDecrypt(gpa, whole, sig1000(), .{ .chain_hash = quicknet_chain });
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, pt, back);
    }
}

test "age: decryptStream refuses what decrypt refuses, and writes only authenticated chunks" {
    const gpa = testing.allocator;
    const len = 2 * chunk_bytes + 5;
    const pt = try gpa.alloc(u8, len);
    defer gpa.free(pt);
    streamPlain(pt);
    const file = try encryptAlloc(gpa, pt, pub1000(), 1000, quicknet_chain, &fixed_rnd, .{});
    defer gpa.free(file);
    const head = headerLen(1000) + nonce_bytes;
    const sig = sig1000();

    // A flipped byte in the third chunk: the two before it were written whole.
    {
        const bad = try gpa.dupe(u8, file);
        defer gpa.free(bad);
        bad[head + 2 * sealed_chunk_bytes + 1] ^= 1;
        var src: std.Io.Reader = .fixed(bad);
        var sink: std.Io.Writer.Allocating = .init(gpa);
        defer sink.deinit();
        try testing.expectError(error.PayloadAuthenticationFailed, decryptStream(gpa, &sink.writer, &src, sig, .{}));
        try testing.expectEqualSlices(u8, pt[0 .. 2 * chunk_bytes], sink.written());
    }
    // Truncated at a chunk boundary, truncated inside a tag, extended by a byte.
    for ([_]usize{ head + sealed_chunk_bytes, head + 2 * sealed_chunk_bytes, file.len - 1 }) |cut| {
        const e = streamDecrypt(gpa, file[0..cut], sig, .{});
        try testing.expectError(error.PayloadAuthenticationFailed, e);
    }
    {
        const longer = try gpa.alloc(u8, file.len + 1);
        defer gpa.free(longer);
        @memcpy(longer[0..file.len], file);
        longer[file.len] = 0;
        try testing.expectError(error.PayloadAuthenticationFailed, streamDecrypt(gpa, longer, sig, .{}));
    }
    // Nothing after the nonce / not even the nonce / a lone tag after full chunks.
    try testing.expectError(error.MalformedPayload, streamDecrypt(gpa, file[0..head], sig, .{}));
    try testing.expectError(error.MalformedPayload, streamDecrypt(gpa, file[0 .. head - 1], sig, .{}));
    try testing.expectError(error.MalformedPayload, streamDecrypt(gpa, file[0 .. head + 3], sig, .{}));
    // Header: wrong chain, wrong signature, a flipped MAC byte, not an age file, empty, over the cap.
    var other = quicknet_chain;
    other[0] ^= 1;
    try testing.expectError(error.WrongChainHash, streamDecrypt(gpa, file, sig, .{ .chain_hash = other }));
    try testing.expectError(error.FoCheckFailed, streamDecrypt(gpa, file, try g1.fromBytesCompressed(hexBytes(48, qt_sig)), .{}));
    {
        const bad = try gpa.dupe(u8, file);
        defer gpa.free(bad);
        const mi = (try Header.parse(file)).mac_input_len;
        bad[mi + 1] = if (bad[mi + 1] == 'A') 'B' else 'A';
        try testing.expectError(error.HeaderMacMismatch, streamDecrypt(gpa, bad, sig, .{}));
    }
    try testing.expectError(error.NotAgeFile, streamDecrypt(gpa, "", sig, .{}));
    try testing.expectError(error.NotAgeFile, streamDecrypt(gpa, "hello\nworld\n", sig, .{}));
    try testing.expectError(error.MalformedHeader, streamDecrypt(gpa, file[0 .. head - nonce_bytes - 1], sig, .{}));
    const junk = try gpa.alloc(u8, max_header_bytes + 10);
    defer gpa.free(junk);
    @memset(junk, 'a');
    @memcpy(junk[0 .. version_line.len + 1], version_line ++ "\n");
    try testing.expectError(error.HeaderTooLarge, streamDecrypt(gpa, junk, sig, .{}));
}

test "age: decryptStream takes a header of exactly max_header_bytes and refuses one byte more; a bad first line is refused at once" {
    const gpa = testing.allocator;
    const base = try encryptAlloc(gpa, "abc", pub1000(), 1000, quicknet_chain, &fixed_rnd, .{});
    defer gpa.free(base);
    const h0 = try Header.parse(base);
    const stanza = base[0 .. h0.mac_input_len - 3]; // version line + the tlock stanza
    const mac_line_len = "--- ".len + b64_raw.Encoder.calcSize(mac_bytes) + 1;

    var key = payloadKey(fixed_rnd.file_key, fixed_rnd.nonce);
    defer std.crypto.secureZero(u8, &key);
    var sealed: [3 + tag_bytes]u8 = undefined;
    sealPayload(&sealed, &key, "abc");

    for ([_]usize{ max_header_bytes, max_header_bytes + 1 }) |total| {
        const pad_line_len = total - stanza.len - mac_line_len;
        const file = try gpa.alloc(u8, total + nonce_bytes + sealed.len);
        defer gpa.free(file);
        var w: std.Io.Writer = .fixed(file);
        try w.writeAll(stanza);
        try w.writeAll("-> pad ");
        try w.splatByteAll('A', pad_line_len - "-> pad ".len - 2);
        try w.writeAll("\n\n---");
        const mac = headerMac(fixed_rnd.file_key, w.buffered());
        var mac_b64: [b64_raw.Encoder.calcSize(mac_bytes)]u8 = undefined;
        try w.print(" {s}\n", .{b64_raw.Encoder.encode(&mac_b64, &mac)});
        try testing.expectEqual(total, w.end);
        try w.writeAll(&fixed_rnd.nonce);
        try w.writeAll(&sealed);
        if (total == max_header_bytes) {
            const pt = try streamDecrypt(gpa, file, sig1000(), .{});
            defer gpa.free(pt);
            try testing.expectEqualStrings("abc", pt);
        } else {
            try testing.expectError(error.HeaderTooLarge, streamDecrypt(gpa, file, sig1000(), .{}));
        }
    }

    // A first line that is not the version line is refused without reading on.
    const junk = try gpa.alloc(u8, max_header_bytes * 2);
    defer gpa.free(junk);
    @memset(junk, 'a');
    @memcpy(junk[0..6], "hello\n");
    try testing.expectError(error.NotAgeFile, streamDecrypt(gpa, junk, sig1000(), .{}));
}

test "age: a failing writer or reader ends the stream call with WriteFailed / ReadFailed" {
    const gpa = testing.allocator;
    const file = try encryptAlloc(gpa, "abc", pub1000(), 1000, quicknet_chain, &fixed_rnd, .{});
    defer gpa.free(file);
    const sig = sig1000();

    var tiny: [20]u8 = undefined;
    var w: std.Io.Writer = .fixed(&tiny);
    var src: std.Io.Reader = .fixed("abc");
    try testing.expectError(error.WriteFailed, encryptStream(gpa, &w, &src, pub1000(), 1000, quicknet_chain, &fixed_rnd));
    // Room for the header but not for the sealed chunk.
    var mid: [headerLen(1000) + nonce_bytes + 5]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&mid);
    var src2: std.Io.Reader = .fixed("abc");
    try testing.expectError(error.WriteFailed, encryptStream(gpa, &w2, &src2, pub1000(), 1000, quicknet_chain, &fixed_rnd));
    var w3: std.Io.Writer = .fixed(tiny[0..2]);
    var src3: std.Io.Reader = .fixed(file);
    try testing.expectError(error.WriteFailed, decryptStream(gpa, &w3, &src3, sig, .{}));

    var bad = failingReader();
    var sink: std.Io.Writer.Allocating = .init(gpa);
    defer sink.deinit();
    try testing.expectError(error.ReadFailed, encryptStream(gpa, &sink.writer, &bad, pub1000(), 1000, quicknet_chain, &fixed_rnd));
    var bad2 = failingReader();
    try testing.expectError(error.ReadFailed, decryptStream(gpa, &sink.writer, &bad2, sig, .{}));
}

test "age: an allocation failure ends the stream calls with OutOfMemory and leaks nothing" {
    const gpa = testing.allocator;
    const file = try encryptAlloc(gpa, "abc", pub1000(), 1000, quicknet_chain, &fixed_rnd, .{});
    defer gpa.free(file);
    var failing = testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    var src: std.Io.Reader = .fixed("abc");
    var sink: std.Io.Writer.Allocating = .init(gpa);
    defer sink.deinit();
    try testing.expectError(error.OutOfMemory, encryptStream(failing.allocator(), &sink.writer, &src, pub1000(), 1000, quicknet_chain, &fixed_rnd));
    var failing2 = testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    var src2: std.Io.Reader = .fixed(file);
    try testing.expectError(error.OutOfMemory, decryptStream(failing2.allocator(), &sink.writer, &src2, sig1000(), .{}));
}

test "age: sizes are exact" {
    try testing.expectEqual(@as(usize, 16), sealedLen(0));
    try testing.expectEqual(@as(usize, chunk_bytes + 16), sealedLen(chunk_bytes));
    try testing.expectEqual(@as(usize, chunk_bytes + 1 + 32), sealedLen(chunk_bytes + 1));
    for ([_]usize{ 0, 1, 100, chunk_bytes, chunk_bytes + 1, 3 * chunk_bytes }) |n| {
        try testing.expectEqual(n, try openedLen(sealedLen(n)));
    }
    // Impossible sealed sizes: shorter than a tag; a tag-only chunk after a full one.
    try testing.expectError(error.MalformedPayload, openedLen(15));
    try testing.expectError(error.MalformedPayload, openedLen(sealed_chunk_bytes + 16));
    try testing.expectError(error.MalformedPayload, openedLen(sealed_chunk_bytes + 5));
    try testing.expectEqual(@as(usize, 22 + 9 + 4 + 1 + 64 + 1 + 174 + 4 + 43 + 1), headerLen(1000));
}

test "age: STREAM nonce layout — 11-byte big-endian counter, then the last-chunk flag" {
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &chunkNonce(0, true));
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0 }, &chunkNonce(0x102, false));
}

test "age: payload tampering, truncation and extension are all refused, and nothing leaks" {
    const gpa = testing.allocator;
    const pt = @as([chunk_bytes + 100]u8, @splat(0xab));
    const file = try encryptAlloc(gpa, &pt, pub1000(), 1000, quicknet_chain, &fixed_rnd, .{});
    defer gpa.free(file);
    const out = try gpa.alloc(u8, file.len);
    defer gpa.free(out);
    const hl = headerLen(1000);

    // A flipped byte in the SECOND chunk: the first chunk opened, then is wiped.
    {
        const bad = try gpa.dupe(u8, file);
        defer gpa.free(bad);
        bad[bad.len - 3] ^= 1;
        @memset(out, 0x77);
        try testing.expectError(error.PayloadAuthenticationFailed, decrypt(out, bad, sig1000(), .{}));
        try testing.expect(std.mem.allEqual(u8, out[0..chunk_bytes], 0));
    }
    // Truncated to exactly one full chunk: that chunk is then "last" and fails.
    try testing.expectError(error.PayloadAuthenticationFailed, decrypt(out, file[0 .. hl + 16 + sealed_chunk_bytes], sig1000(), .{}));
    // Truncated mid-tag of the last chunk.
    try testing.expectError(error.PayloadAuthenticationFailed, decrypt(out, file[0 .. file.len - 1], sig1000(), .{}));
    // Truncated inside the nonce.
    try testing.expectError(error.MalformedPayload, decrypt(out, file[0 .. hl + 7], sig1000(), .{}));
    // A changed nonce derives another key.
    {
        const bad = try gpa.dupe(u8, file);
        defer gpa.free(bad);
        bad[hl] ^= 1;
        try testing.expectError(error.PayloadAuthenticationFailed, decrypt(out, bad, sig1000(), .{}));
    }
}

test "age: header MAC binds every header byte; wrong signature and wrong chain are refused" {
    const gpa = testing.allocator;
    const file = try encryptAlloc(gpa, "secret", pub1000(), 1000, quicknet_chain, &fixed_rnd, .{});
    defer gpa.free(file);
    var out: [64]u8 = undefined;

    // The MAC itself altered (still canonical base64).
    {
        const bad = try gpa.dupe(u8, file);
        defer gpa.free(bad);
        const h = try Header.parse(file);
        bad[h.mac_input_len + 1] = if (bad[h.mac_input_len + 1] == 'A') 'B' else 'A';
        try testing.expectError(error.HeaderMacMismatch, decrypt(&out, bad, sig1000(), .{}));
    }
    // The stanza line re-spelled so it still names round 1000 (`tle` parses
    // leading zeros too): the stanza still opens, and only the MAC catches it.
    {
        const edited = try std.mem.replaceOwned(u8, gpa, file, "-> tlock 1000 ", "-> tlock 01000 ");
        defer gpa.free(edited);
        try testing.expectEqual(@as(u64, 1000), (try Header.parse(edited)).recipient.round);
        try testing.expectError(error.HeaderMacMismatch, decrypt(&out, edited, sig1000(), .{}));
    }
    // The genuine quicknet-t signature for another round: FO check.
    try testing.expectError(error.FoCheckFailed, decrypt(&out, file, try g1.fromBytesCompressed(hexBytes(48, qt_sig)), .{}));
    // Chain mismatch is caught before any pairing.
    try testing.expectError(error.WrongChainHash, decrypt(&out, file, sig1000(), .{ .chain_hash = hexBytes(32, qt_chain_hex) }));
    try testing.expectError(error.NoSpaceLeft, decrypt(out[0..5], file, sig1000(), .{}));
}

/// Build a header by hand around a known body, for the parser's refusals.
fn headerText(comptime stanzas: []const u8) []const u8 {
    return version_line ++ "\n" ++ stanzas ++ "--- " ++ strRepeat("A", 42) ++ "A\n";
}

const good_body_b64 = blk: {
    @setEvalBranchQuota(100_000);
    const raw = hexBytes(128, qt_stanza_body);
    var enc: [171]u8 = undefined;
    _ = b64_raw.Encoder.encode(&enc, &raw);
    const text = enc[0..64].* ++ "\n".* ++ enc[64..128].* ++ "\n".* ++ enc[128..171].* ++ "\n".*;
    break :blk &text;
};
const good_tlock = "-> tlock 5423142 " ++ qt_chain_hex ++ "\n" ++ good_body_b64;

test "age: headerText builds the exact header bytes from a runtime call (strRepeat must be comptime-known)" {
    // Regression (Zig 0.17.0): a non-inline strRepeat made the `++` result a stack temporary.
    const h = headerText("-> x\n");
    try testing.expectEqualStrings(version_line ++ "\n-> x\n--- " ++ "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ++ "\n", h);
}

test "age: Header.parse accepts the minimal shape and other recipients beside tlock" {
    _ = try Header.parse(headerText(good_tlock));
    const h = try Header.parse(headerText("-> X25519 abc\nAAAA\n" ++ good_tlock ++ "-> some-grease !#$\n\n"));
    try testing.expectEqual(qt_round, h.recipient.round);
    // A body that is an exact multiple of 48 bytes ends with an empty line.
    _ = try Header.parse(headerText("-> other\n" ++ strRepeat("A", 64) ++ "\n\n" ++ good_tlock));
}

test "age: Header.parse refuses malformed headers with typed errors" {
    const E = HeaderError;
    const cases = .{
        .{ E.NotAgeFile, "" },
        .{ E.NotAgeFile, "age-encryption.org/v2\n" },
        .{ E.MalformedHeader, version_line ++ "\n" },
        .{ E.NoTlockStanza, headerText("-> X25519 abc\nAAAA\n") },
        .{ E.MultipleTlockStanzas, headerText(good_tlock ++ good_tlock) },
        .{ E.MalformedHeader, headerText("->  tlock\n\n") }, // empty argument
        .{ E.MalformedHeader, headerText("-> tl\x7fck\n\n") }, // non-VCHAR
        .{ E.MalformedHeader, headerText("-> x\n" ++ strRepeat("A", 65) ++ "\n") }, // over-long body line
        .{ E.MalformedHeader, headerText("-> x\nAB\n") }, // non-canonical trailing bits
        .{ E.MalformedHeader, headerText("-> x\nAA==\n") }, // padding is not allowed
        .{ E.MalformedHeader, headerText("-> x\nA\n") }, // impossible length
        .{ E.MalformedHeader, version_line ++ "\n" ++ good_tlock ++ "---\n" }, // MAC missing
        .{ E.MalformedHeader, version_line ++ "\n" ++ good_tlock ++ "--- " ++ strRepeat("A", 42) ++ "B\n" }, // non-canonical MAC
        .{ E.MalformedHeader, version_line ++ "\n" ++ good_tlock ++ "garbage\n" },
        .{ E.MalformedHeader, headerText("-> scrypt a b\nAAAA\n" ++ good_tlock) },
        .{ E.MalformedTlockStanza, headerText("-> tlock 5423142\n" ++ good_body_b64) },
        .{ E.MalformedTlockStanza, headerText("-> tlock +5423142 " ++ qt_chain_hex ++ "\n" ++ good_body_b64) },
        .{ E.MalformedTlockStanza, headerText("-> tlock 1_000 " ++ qt_chain_hex ++ "\n" ++ good_body_b64) },
        .{ E.MalformedTlockStanza, headerText("-> tlock 18446744073709551616 " ++ qt_chain_hex ++ "\n" ++ good_body_b64) },
        .{ E.MalformedTlockStanza, headerText("-> tlock 1 CC9C398442737CBD141526600919EDD69F1D6F9B4ADB67E4D912FBC64341A9A5\n" ++ good_body_b64) },
        .{ E.MalformedTlockStanza, headerText("-> tlock 1 " ++ qt_chain_hex ++ "\nAAAA\n") }, // body too short
        .{ E.MalformedTlockStanza, headerText("-> tlock 1 " ++ qt_chain_hex ++ "\n" ++ strRepeat("A", 64) ++ "\n" ++ strRepeat("A", 64) ++ "\n" ++ strRepeat("A", 64) ++ "\n\n") }, // too long
        .{ E.InvalidCiphertext, headerText("-> tlock 1 " ++ qt_chain_hex ++ "\n" ++ strRepeat("A", 64) ++ "\n" ++ strRepeat("A", 64) ++ "\n" ++ strRepeat("A", 43) ++ "\n") }, // U all-zero, no flag bits
        .{ E.InvalidCiphertext, headerText("-> tlock 1 " ++ qt_chain_hex ++ "\n" ++ strRepeat("A", 64) ++ "\n" ++ strRepeat("A", 43) ++ "\n") }, // an 80-byte body (G2-signature scheme), U all-zero
        .{ E.MalformedTlockStanza, headerText("-> tlock 1 " ++ qt_chain_hex ++ "\n" ++ strRepeat("A", 64) ++ "\n" ++ strRepeat("A", 64) ++ "\n" ++ strRepeat("A", 6) ++ "\n") }, // 100 bytes: neither scheme's length
    };
    inline for (cases) |c| {
        try testing.expectError(c[0], Header.parse(c[1]));
    }
}

test "age: Header.parse caps stanzas and header size" {
    const gpa = testing.allocator;
    var many: std.ArrayList(u8) = .empty;
    defer many.deinit(gpa);
    try many.appendSlice(gpa, version_line ++ "\n");
    for (0..max_stanzas + 1) |_| try many.appendSlice(gpa, "-> x\n\n");
    try many.appendSlice(gpa, good_tlock ++ "--- " ++ strRepeat("A", 43) ++ "\n");
    try testing.expectError(error.TooManyStanzas, Header.parse(many.items));

    var big: std.ArrayList(u8) = .empty;
    defer big.deinit(gpa);
    try big.appendSlice(gpa, version_line ++ "\n-> x\n");
    while (big.items.len < max_header_bytes + 100) try big.appendSlice(gpa, strRepeat("A", 64) ++ "\n");
    try testing.expectError(error.HeaderTooLarge, Header.parse(big.items));
}

test "age: armor layout — 64 columns, padded, no blank line at an exact multiple" {
    var out: [512]u8 = undefined;
    const a = try armor(&out, &(@as([48]u8, @splat(0))));
    try testing.expectEqualStrings(armor_begin ++ "\n" ++ strRepeat("A", 64) ++ "\n" ++ armor_end ++ "\n", a);
    const b = try armor(&out, &(@as([49]u8, @splat(0xff))));
    try testing.expectEqualStrings(armor_begin ++ "\n" ++ strRepeat("/", 64) ++ "\n/w==\n" ++ armor_end ++ "\n", b);
    try testing.expectEqual(b.len, armoredLen(49));
    var back: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &(@as([49]u8, @splat(0xff))), try dearmor(&back, b));
}

test "age: dearmor accepts surrounding whitespace and CRLF, refuses everything else" {
    var back: [128]u8 = undefined;
    const ok = " \r\n" ++ armor_begin ++ "\r\n" ++ strRepeat("/", 64) ++ "\r\n/w==\r\n" ++ armor_end ++ "\r\n\n ";
    try testing.expectEqual(@as(usize, 49), (try dearmor(&back, ok)).len);
    try testing.expect(isArmored(ok));

    const bad = [_][]const u8{
        armor_begin ++ "\n" ++ armor_end ++ "\n", // empty
        armor_begin ++ "\n/w==\n", // no END
        armor_begin ++ "\n/w==\n" ++ armor_end ++ "\nX", // trailing junk
        "x" ++ armor_begin ++ "\n/w==\n" ++ armor_end, // leading junk
        armor_begin ++ "\n" ++ strRepeat("/", 60) ++ "\n/w==\n" ++ armor_end, // short non-final line
        armor_begin ++ "\n" ++ strRepeat("/", 65) ++ "\n" ++ armor_end, // long line
        armor_begin ++ "\n" ++ strRepeat("/", 60) ++ "/w==\n/w==\n" ++ armor_end, // padding mid-stream
        armor_begin ++ "\n/x==\n" ++ armor_end, // non-canonical
        armor_begin ++ "\n/w=\n" ++ armor_end, // unpadded
        armor_begin ++ "\n" ++ strRepeat("/", 64) ++ "\n\n/w==\n" ++ armor_end, // blank line
        armor_begin ++ "/w==\n" ++ armor_end, // no newline after BEGIN
    };
    for (bad) |b| try testing.expectError(error.MalformedArmor, dearmor(&back, b));
    try testing.expectError(error.NoSpaceLeft, dearmor(back[0..10], ok));
}

test "age: encrypt is deterministic under fixed randomness, and draw() really varies" {
    const gpa = testing.allocator;
    const a = try encryptAlloc(gpa, "x", pub1000(), 1000, quicknet_chain, &fixed_rnd, .{});
    defer gpa.free(a);
    const b = try encryptAlloc(gpa, "x", pub1000(), 1000, quicknet_chain, &fixed_rnd, .{});
    defer gpa.free(b);
    try testing.expectEqualSlices(u8, a, b);

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var r1: Randomness = undefined;
    r1.draw(threaded.io());
    var r2: Randomness = undefined;
    r2.draw(threaded.io());
    try testing.expect(!std.mem.eql(u8, &r1.file_key, &r2.file_key));
    try testing.expect(!std.mem.eql(u8, &r1.nonce, &r2.nonce));
    try testing.expect(!std.mem.eql(u8, &r1.sigma, &r2.sigma));
    try testing.expect(!std.mem.eql(u8, &r1.file_key, &r1.nonce));
}

test "age: inspectAlloc reads the round from binary and armored files" {
    const gpa = testing.allocator;
    for ([_]bool{ false, true }) |arm| {
        const f = try encryptAlloc(gpa, "abc", pub1000(), 1000, quicknet_chain, &fixed_rnd, .{ .armor = arm });
        defer gpa.free(f);
        const r = try inspectAlloc(gpa, f);
        try testing.expectEqual(@as(u64, 1000), r.round);
        try testing.expectEqualSlices(u8, &quicknet_chain, &r.chain_hash);
    }
}

// ── fuzz: the three hostile-input decoders ─────────────────────────────
//
// `Header.parse`, `dearmor` and the STREAM opener are what an attacker's file
// reaches before (or instead of) the pairing. The harness feeds one input to
// all three; a valid-looking header, an armored frame and a sealed payload
// seed it. Nothing may panic or read out of bounds.

const tkfuzz = @import("testkit").fuzz;

const fuzz_seeds = [_][]const u8{
    tkfuzz.seed(""),
    tkfuzz.seed(headerText(good_tlock)),
    tkfuzz.seed(headerText("-> X25519 abc\nAAAA\n" ++ good_tlock)),
    tkfuzz.seed(armor_begin ++ "\n" ++ strRepeat("/", 64) ++ "\n/w==\n" ++ armor_end ++ "\n"),
    tkfuzz.seed(version_line ++ "\n-> x\n" ++ strRepeat("A", 64) ++ "\n"),
    tkfuzz.seed(strRepeat("\x00", 40)),
};

const fz = @import("fuzz_test.zig");
const testkit = @import("testkit");
const DecodersMark = fz.Marker(enum { header_ok, header_refused, dearmor_ok, dearmor_refused, payload_refused, payload_genuine, payload_flip_refused });
const FileMark = fz.Marker(enum { genuine_accepted, flipped_refused, truncated_refused, appended_refused });

fn fuzzDecodersSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzDecoders(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

fn fuzzDecoders(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf: [2048]u8 = undefined;
    const n: usize = fz.drawInput(S, src, &buf, &fuzz_seeds);
    const input = buf[0..n];

    if (Header.parse(input)) |_| DecodersMark.mark(.header_ok) else |_| DecodersMark.mark(.header_refused);
    var out: [2048]u8 = undefined;
    if (dearmor(&out, input)) |_| DecodersMark.mark(.dearmor_ok) else |_| DecodersMark.mark(.dearmor_refused);
    const key = @as([32]u8, @splat(7));
    if (openedLen(input.len)) |m| {
        if (openPayload(out[0..m], &key, input)) |_| {} else |_| DecodersMark.mark(.payload_refused);
    } else |_| {}

    // The oracle the decoders alone cannot give (driver only, after every draw
    // above so `Smith` replay is untouched): a payload this module sealed
    // opens to its plaintext, and one flipped octet anywhere refuses.
    if (S == fz.fuzz_driver.Rng) {
        var plain: [100]u8 = undefined;
        const plen = src.index(plain.len + 1);
        src.bytes(plain[0..plen]);
        var sealed: [100 + tag_bytes]u8 = undefined;
        const slen = sealedLen(plen);
        sealPayload(sealed[0..slen], &key, plain[0..plen]);
        var back: [100]u8 = undefined;
        openPayload(back[0..plen], &key, sealed[0..slen]) catch return error.GenuinePayloadRefused;
        if (!std.mem.eql(u8, back[0..plen], plain[0..plen])) return error.GenuinePayloadChanged;
        DecodersMark.mark(.payload_genuine);
        sealed[src.index(slen)] ^= src.valueRangeAtMost(u8, 1, 255);
        if (openPayload(back[0..plen], &key, sealed[0..slen])) |_| return error.FlippedPayloadOpened else |_| {}
        DecodersMark.mark(.payload_flip_refused);
    }
}

test "fuzz driver: TLOCK_FUZZ (age decoders)" {
    try fz.fuzz_driver.run(fuzzDecoders, .{ .prefix = "TLOCK_FUZZ", .name = "tlock-age-decoders" });
}

test "fuzz harness: age decoders, 500 seeds, reaches every outcome" {
    try DecodersMark.reach(fuzzDecoders, "tlock-age-decoders", 500);
}

test "fuzz: age header, armor and STREAM decoders never panic on hostile bytes" {
    try std.testing.fuzz({}, fuzzDecodersSmith, .{ .corpus = &fuzz_seeds });
}

/// A genuine file (real quicknet round-1000 key and signature, a random
/// plaintext) is ACCEPTED and returns its plaintext; a flipped octet anywhere,
/// a truncation and an appended octet are each REFUSED.
fn fuzzFile(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var plain: [200]u8 = undefined;
    const plen = src.index(plain.len + 1);
    src.bytes(plain[0..plen]);
    var rnd: Randomness = undefined;
    src.bytes(&rnd.file_key);
    src.bytes(&rnd.sigma);
    src.bytes(&rnd.nonce);

    const file = try encryptAlloc(gpa, plain[0..plen], pub1000(), 1000, quicknet_chain, &rnd, .{});
    defer gpa.free(file);
    var out: [200]u8 = undefined;
    const got = decrypt(out[0..plen], file, sig1000(), .{ .chain_hash = quicknet_chain }) catch return error.GenuineFileRefused;
    if (!std.mem.eql(u8, got, plain[0..plen])) return error.GenuineFileChanged;
    FileMark.mark(.genuine_accepted);

    // One flipped octet, anywhere in the file.
    const damaged = try gpa.dupe(u8, file);
    defer gpa.free(damaged);
    const at = src.index(damaged.len);
    damaged[at] ^= src.valueRangeAtMost(u8, 1, 255);
    if (decrypt(out[0..plen], damaged, sig1000(), .{ .chain_hash = quicknet_chain })) |_| {
        std.debug.print("flipped octet {d} of {d} accepted\n", .{ at, file.len });
        return error.FlippedFileAccepted;
    } else |_| FileMark.mark(.flipped_refused);

    // A truncation (decryptedLen may itself refuse; out is sized for plen).
    const cut = src.index(file.len);
    if (decrypt(&out, file[0..cut], sig1000(), .{ .chain_hash = quicknet_chain })) |_| return error.TruncatedFileAccepted else |_| FileMark.mark(.truncated_refused);

    // One octet appended.
    const longer = try gpa.alloc(u8, file.len + 1);
    defer gpa.free(longer);
    @memcpy(longer[0..file.len], file);
    longer[file.len] = src.value(u8);
    if (decrypt(&out, longer, sig1000(), .{ .chain_hash = quicknet_chain })) |_| return error.AppendedFileAccepted else |_| FileMark.mark(.appended_refused);
}

fn fuzzFileSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzFile(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: a genuine age file opens and a damaged one does not" {
    try std.testing.fuzz({}, fuzzFileSmith, .{});
}

test "fuzz driver: TLOCK_FUZZ (age file)" {
    // `.scale`: each run is an encryption and up to four decryptions (pairings).
    try fz.fuzz_driver.run(fuzzFile, .{ .prefix = "TLOCK_FUZZ", .name = "tlock-age-file", .scale = 100 });
}

test "fuzz harness: age file, 40 seeds, reaches every outcome" {
    try FileMark.reach(fuzzFile, "tlock-age-file", 40);
}

test "corpus: the age fuzz seeds reach past the first check" {
    // The seeds are only worth having if they are not all refused at the
    // first byte: one parses, one dearmors.
    var parsed: usize = 0;
    var dearmored: usize = 0;
    for (fuzz_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [2048]u8 = undefined;
        const n: usize = smith.slice(&buf);
        if (Header.parse(buf[0..n])) |_| parsed += 1 else |_| {}
        var out: [2048]u8 = undefined;
        if (dearmor(&out, buf[0..n])) |_| dearmored += 1 else |_| {}
    }
    try testing.expectEqual(@as(usize, 2), parsed);
    try testing.expectEqual(@as(usize, 1), dearmored);
}

test "PayloadStream.openChunk refuses every chunk-shape violation before touching the AEAD" {
    const key = @as([Aead.key_length]u8, @splat(0x42));
    var sealer: PayloadStream = undefined;
    sealer.init(&key);
    var full: [sealed_chunk_bytes]u8 = undefined;
    const pt = @as([chunk_bytes]u8, @splat(0x07));
    sealer.sealChunk(&full, &pt, false);
    var tail: [tag_bytes]u8 = undefined; // a genuine empty LAST chunk at counter 1
    Aead.encrypt(tail[0..0], tail[0..tag_bytes], "", "", chunkNonce(1, true), key);

    var out: [chunk_bytes]u8 = undefined;
    // A short non-last chunk.
    var o: PayloadStream = undefined;
    o.init(&key);
    try std.testing.expectError(error.MalformedPayload, o.openChunk(out[0 .. chunk_bytes - 1], full[0 .. sealed_chunk_bytes - 1], false));
    // Shorter than a tag.
    try std.testing.expectError(error.MalformedPayload, o.openChunk(out[0..0], full[0 .. tag_bytes - 1], true));
    // The genuine first chunk opens; then an EMPTY last chunk is refused
    // even though its tag is genuine — the empty final chunk is only legal
    // as the first one.
    try o.openChunk(&out, &full, false);
    try std.testing.expectEqualSlices(u8, &pt, &out);
    try std.testing.expectError(error.MalformedPayload, o.openChunk(out[0..0], &tail, true));
    // Nothing after the last chunk.
    var e: PayloadStream = undefined;
    e.init(&key);
    var empty: [tag_bytes]u8 = undefined;
    var es: PayloadStream = undefined;
    es.init(&key);
    es.sealChunk(&empty, "", true);
    try e.openChunk(out[0..0], &empty, true);
    try std.testing.expectError(error.MalformedPayload, e.openChunk(out[0..0], &empty, true));
    // The last flag is authenticated: a full chunk sealed as non-last does
    // not open as the last one (truncation at a chunk boundary).
    var t: PayloadStream = undefined;
    t.init(&key);
    try std.testing.expectError(error.PayloadAuthenticationFailed, t.openChunk(&out, &full, true));
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
