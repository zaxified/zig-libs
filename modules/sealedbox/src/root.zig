// SPDX-License-Identifier: MIT
//! sealedbox — NaCl `crypto_box_seal`: anonymous-sender public-key encryption.
//!
//! Encrypt to a recipient's X25519 public key with **no sender key**: a fresh
//! ephemeral keypair is generated per message, so the recipient cannot identify
//! the sender. This is a thin, faithful wrapper over `std.crypto.nacl.SealedBox`
//! — we do NOT roll our own crypto; the nonce derivation and AEAD are std's.
//! (X25519 keys are Curve25519, so a WireGuard pubkey doubles as a recipient key.)
//!
//! Key text serialization: base64 (`std.base64.standard`, RFC 4648 `A–Za–z0–9+/`
//! with `=` padding) and lowercase hex codecs for the 32-byte public and secret
//! keys, so keys can live in config files and wire protocols. Parsing is strict
//! (exact length, no whitespace) and returns typed errors — never panics.
//!
//! Provenance: original work of the zig-libs authors (MIT); a thin wrapper over
//! std's public NaCl `crypto_box_seal` construction. Model after libsodium
//! `crypto_box_seal` / Go `nacl/box`. No third-party source copied — the
//! construction is the public NaCl standard.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "NaCl `crypto_box_seal` — anonymous-sender X25519 public-key encryption, plus base64/hex key serialization.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .linux32 },
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "libsodium crypto_box_seal / Go nacl/box",
    .deps = .{},
};

pub const SealedBox = std.crypto.nacl.SealedBox;
pub const KeyPair = SealedBox.KeyPair;

/// Recipient public-key length (32, Curve25519).
pub const public_length = SealedBox.public_length;
/// Secret-key (X25519 scalar) length (32).
pub const secret_length = SealedBox.secret_length;
/// Bytes a sealed message adds over the plaintext (ephemeral pubkey + Poly1305 tag = 48).
pub const overhead = SealedBox.seal_length;

/// Ciphertext length for a plaintext of `plaintext_len` bytes.
pub fn sealedLen(plaintext_len: usize) usize {
    return plaintext_len + overhead;
}

// ── buffer API (no allocation) ────────────────────────────────────────────────

/// Audit finding L2: `seal`'s inferred error set silently carries whatever
/// `std.crypto.nacl.SealedBox.seal` happens to return today, so a std change
/// can widen or narrow it without this module's own API surface saying so.
/// Named explicitly instead: `InvalidBufferSize` is this module's own guard;
/// `WeakPublicKey`/`IdentityElement` are std's (an attacker-chosen or
/// degenerate `recipient_pk`).
pub const SealError = error{InvalidBufferSize} ||
    std.crypto.errors.WeakPublicKeyError ||
    std.crypto.errors.IdentityElementError;

/// Audit finding L2: `open`'s inferred error set has FOUR members
/// (`InvalidCiphertext`/`IdentityElement`/`WeakPublicKey`/`AuthenticationFailed`)
/// where the README/doc-comment only named two (tamper/short-input). Named
/// explicitly so a caller doing an exhaustive `switch` sees all four, and a
/// std change to the inferred set becomes a compile error here instead of a
/// silent widening.
pub const OpenError = error{InvalidCiphertext} ||
    std.crypto.errors.IdentityElementError ||
    std.crypto.errors.WeakPublicKeyError ||
    std.crypto.errors.AuthenticationError;

/// Seal `msg` to `recipient_pk`. `out` must be exactly `msg.len + overhead`
/// bytes; a wrong size returns `error.InvalidBufferSize` rather than trusting
/// the caller. `io` supplies entropy for the per-message ephemeral keypair.
///
/// The size check is an error and not `std.debug.assert` on purpose: an assert
/// is compiled out in ReleaseFast, so the one build where a miscomputed buffer
/// costs the most is the build where nothing would have caught it. `open`
/// below has always returned an error for the same class of mistake.
///
/// Errors: see `SealError`. `IdentityElement` is reachable from
/// attacker-controlled bytes (a degenerate `recipient_pk` some other layer
/// parsed off the wire) -- not just a pathological caller mistake.
pub fn seal(io: std.Io, out: []u8, msg: []const u8, recipient_pk: [public_length]u8) SealError!void {
    if (out.len != msg.len + overhead) return error.InvalidBufferSize;
    try SealedBox.seal(io, out, msg, recipient_pk);
}

/// Open a sealed message with the recipient keypair. `out` must be exactly
/// `sealed.len - overhead` bytes. Returns an error (never panics) on a too-short
/// or tampered ciphertext.
///
/// Errors: see `OpenError`. Note `IdentityElement`/`WeakPublicKey` are
/// reachable from the SENDER's bytes (the ephemeral public-key prefix an
/// anonymous sender supplies) via the same path a fuzzer reaches with
/// `sealed_bad_epk`-shaped input -- they are not only a caller mistake, and a
/// caller that maps "AuthenticationFailed -> quietly drop" but treats
/// everything else as an internal error gives an attacker a distinguishable
/// log signal (audit finding L2).
///
/// On ANY error, `out`'s contents are unspecified -- audit finding L6: std's
/// `@memset(m, undefined)` on the failure path is a documentation-only no-op
/// in `ReleaseFast` (the actual bytes may be leftover keystream, not zeroed
/// and not the plaintext). A caller must not read `out` unless `open`
/// returned successfully.
pub fn open(out: []u8, sealed: []const u8, kp: KeyPair) OpenError!void {
    if (sealed.len < overhead or sealed.len != out.len + overhead)
        return error.InvalidCiphertext;
    try SealedBox.open(out, sealed, kp);
}

// ── allocating convenience ────────────────────────────────────────────────────

/// Seal `msg`, returning a freshly allocated ciphertext (`msg.len + overhead`).
pub fn sealAlloc(gpa: std.mem.Allocator, io: std.Io, msg: []const u8, recipient_pk: [public_length]u8) ![]u8 {
    const out = try gpa.alloc(u8, sealedLen(msg.len));
    errdefer gpa.free(out);
    try seal(io, out, msg, recipient_pk);
    return out;
}

/// Open a sealed message, returning the freshly allocated plaintext.
/// Errors (never panics) on a too-short/tampered ciphertext.
pub fn openAlloc(gpa: std.mem.Allocator, sealed: []const u8, kp: KeyPair) ![]u8 {
    if (sealed.len < overhead) return error.InvalidCiphertext;
    const out = try gpa.alloc(u8, sealed.len - overhead);
    errdefer gpa.free(out);
    try open(out, sealed, kp);
    return out;
}

// ── key text serialization (base64 / hex) ─────────────────────────────────────
//
// Base64 is `std.base64.standard`: the RFC 4648 standard alphabet (`A–Z a–z 0–9
// + /`) WITH `=` padding — a 32-byte key is always exactly 44 chars ending in
// one `=`. Hex is lowercase on encode; parsing accepts upper- and lowercase.
// Parsers are strict: exact length required, no whitespace or other embedded
// characters tolerated. Malformed input yields `error.InvalidLength` (wrong
// text length) or `error.InvalidKeyEncoding` (bad characters / bad padding) —
// never a panic. All codecs are allocation-free (fixed-size arrays).

/// Base64 text length of an encoded 32-byte key (44, includes the `=` pad).
pub const base64_pk_len = std.base64.standard.Encoder.calcSize(public_length);
/// Hex text length of an encoded 32-byte public key (64).
pub const hex_pk_len = public_length * 2;
/// Base64 text length of an encoded secret key (same as `base64_pk_len`).
pub const base64_sk_len = std.base64.standard.Encoder.calcSize(secret_length);
/// Hex text length of an encoded secret key (same as `hex_pk_len`).
pub const hex_sk_len = secret_length * 2;

/// Errors returned by the key text parsers. Typed — malformed text never panics.
pub const KeyEncodingError = error{ InvalidLength, InvalidKeyEncoding };

/// Overwrite `bytes` with zeros in a way the optimiser may not remove.
///
/// A plain `@memset` on a buffer that is never read again is dead code, and
/// LLVM is entitled to delete it — which is precisely the case for a secret
/// you are done with. `std.crypto.secureZero` is the guaranteed version; this
/// is it, re-exported here so it sits next to the functions that hand out
/// secret material and is found by whoever is holding that material.
///
/// The buffer most often forgotten is not the 32-byte scalar but the ENCODED
/// secret: `encodeSecretKeyBase64` writes 44 bytes and `encodeSecretKeyHex`
/// returns 64, and those live in the caller's frame looking like ordinary text.
///
///     var text: [sealedbox.base64_sk_len]u8 = undefined;
///     defer sealedbox.wipe(&text);
///     sealedbox.encodeSecretKeyBase64(&text, &sk);
///
/// This is hygiene, not a defense against an attacker who can already read
/// your process memory at the moment the secret is live.
pub fn wipe(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

/// Encode a recipient public key as standard base64 (44 chars, `=`-padded).
pub fn encodePublicKeyBase64(pk: [public_length]u8) [base64_pk_len]u8 {
    return encodeKeyBase64(pk);
}

/// Parse a base64-encoded public key. Strict: exactly 44 chars, standard
/// alphabet, correct `=` padding, no whitespace.
pub fn parsePublicKeyBase64(text: []const u8) KeyEncodingError![public_length]u8 {
    return parseKeyBase64(text);
}

/// Encode a recipient public key as lowercase hex (64 chars).
pub fn encodePublicKeyHex(pk: [public_length]u8) [hex_pk_len]u8 {
    return std.fmt.bytesToHex(pk, .lower);
}

/// Parse a hex-encoded public key. Strict: exactly 64 hex digits (either case),
/// no whitespace.
pub fn parsePublicKeyHex(text: []const u8) KeyEncodingError![public_length]u8 {
    return parseKeyHex(text);
}

/// Encode a secret key as standard base64 (44 chars) into `out`. **SECRET
/// material** — the output grants full decryption capability; store/transmit
/// accordingly, and `wipe` `out` when done with it.
///
/// Pointers in, no value out (audit A1 L8). Measured at ReleaseFast, the result
/// wiped the moment it came back: the old value-in/value-out form left the raw
/// key on the dead stack twice per call and the base64 text once — one key copy
/// was the argument copy a caller makes, the rest sat in frames between the
/// encoder and its caller, where no `wipe` of the caller's buffer reaches.
/// Writing into `out` is what removed it; the `noinline` encoder and the stack
/// burn after it are guards — dropping either left the probe at zero in the
/// measured binary. `stackprobe_test.zig` asserts nothing is left.
pub fn encodeSecretKeyBase64(out: *[base64_sk_len]u8, sk: *const [secret_length]u8) void {
    encodeSecretKeyBase64Ct(out, sk);
    burnCodecStack();
}

/// Parse a base64-encoded secret key (**SECRET material**) into `out`. Same
/// strict rules as `parsePublicKeyBase64`. `out` receives the raw X25519
/// scalar — rebuild a usable keypair with `keyPairFromSecretKey` — and is
/// zeroed on any error.
///
/// Audit A1 L8: returned by value, the decoded key stayed on the dead stack
/// once per call in the module's full test binary and not in a filtered one —
/// whether the copy survived depended on inlining. Written into `out`, it does
/// not; the `noinline` decoder and the stack burn are guards (dropping either
/// left the probe at zero in the measured binary).
pub fn parseSecretKeyBase64(out: *[secret_length]u8, text: []const u8) KeyEncodingError!void {
    const result = parseSecretKeyBase64Ct(out, text);
    burnCodecStack();
    return result;
}

/// Encode a secret key as lowercase hex (64 chars). **SECRET material** —
/// `wipe` the returned buffer when done with it.
pub fn encodeSecretKeyHex(sk: [secret_length]u8) [hex_sk_len]u8 {
    return encodeSecretKeyHexCt(sk);
}

/// Parse a hex-encoded secret key (**SECRET material**) into `out`. Same strict
/// rules as `parsePublicKeyHex`; `out` is zeroed on any error.
///
/// Audit A1 L8: returned by value, the decoded key stayed on the dead stack
/// three times per call in the module's full test binary. Written into `out`,
/// it does not; the `noinline` decoder and the stack burn are guards (dropping
/// either left the probe at zero in the measured binary).
pub fn parseSecretKeyHex(out: *[secret_length]u8, text: []const u8) KeyEncodingError!void {
    const result = parseSecretKeyHexCt(out, text);
    burnCodecStack();
    return result;
}

/// Zero the stack the secret-key codecs used, at their depth (audit A1 L8). A
/// guard, not a measured necessity: with the codecs writing into caller
/// buffers, removing this call or the codecs' `noinline` left
/// `stackprobe_test.zig` at zero. It keeps whatever a codec's frames may hold
/// in a future build off the dead stack. `secureZero` writes through a volatile
/// slice, so the dead store survives optimisation.
noinline fn burnCodecStack() void {
    var buf: [1024]u8 = undefined;
    std.crypto.secureZero(u8, &buf);
}

/// Recompute the public key from a stored secret key (X25519 base-point
/// multiplication via std). The secret scalar alone fully round-trips a keypair.
/// `error.IdentityElement` only for pathological all-weak scalars.
pub fn publicFromSecret(sk: [secret_length]u8) error{IdentityElement}![public_length]u8 {
    return std.crypto.dh.X25519.recoverPublicKey(sk);
}

/// Rebuild a usable `KeyPair` from a stored secret key (public key is
/// recomputed — std's X25519 `KeyPair` treats the secret scalar as the seed).
pub fn keyPairFromSecretKey(sk: [secret_length]u8) error{IdentityElement}!KeyPair {
    return .{ .public_key = try publicFromSecret(sk), .secret_key = sk };
}

// ── constant-time codecs for SECRET key text ───────────────────────────────
//
// ⛔⛔ Why these exist at all, in one measurement. `std.base64` and
// `std.fmt.bytesToHex`/`hexToBytes` are table-driven, and a table indexed by a
// secret byte is a cache-timing oracle -- the class of T-table AES. Measured
// 2026-09-09 with `scripts/checks/ctgrind.sh sealedbox` and confirmed by disassembly
// before anything here was written:
//
//     movzbl %sil,%eax                 ; the secret character
//     movzbl 0x100fde8(%rax),%eax      ; std's 256-byte char_to_index[secret]
//     shr $0x34,%r8 ; and $0x3f,%r8d   ; a secret 6-bit group
//     movzbl 0x100ff2e(%r8),%esi       ; std's 64-byte alphabet[secret]
//
// 43 / 47 / 8 / 7 in-file contexts across the four secret-key codecs, 95 of
// them reported on a LOAD rather than a conditional jump. The values were
// always correct; what leaked was the ADDRESS PATTERN, which no value test can
// see.
//
// ⚠ The PUBLIC-key codecs deliberately still use `std`. Their input is public,
// so a table lookup discloses nothing, and re-implementing them would trade a
// well-tested decoder for a hand-written one to buy nothing. That asymmetry is
// the point: this is not "std is bad", it is "this input is a secret".
//
// ⚠ These are also NOT a general base64/hex library. They accept exactly the
// one length each key encoding has, and they are slower than std's. Do not
// reach for them for anything but key material.

/// Optimization barrier (montint `b199192` leak class): launder a value
/// through an empty inline-asm so LLVM loses all range and equality knowledge
/// about it. No-op at runtime. Same idiom as `p256/src/group.zig`,
/// `k256/src/field.zig`, `fss/src/dpf.zig` and `montint`.
///
/// ⛔ LOAD-BEARING, not defensive. Every mask below is derived from a
/// comparison against a secret, and LLVM is entitled to notice that a masked
/// select over a small known range can be rewritten as a jump table or a
/// branch -- which is exactly how `bfv`'s correctly-written branch-free `csub`
/// became a real `cmp`/`jb` at one call site out of ninety-nine. The barrier is
/// what makes the source claim survive into the binary.
inline fn blackBox(x: u16) u16 {
    return asm volatile (""
        : [ret] "=r" (-> u16),
        : [x] "0" (x),
    );
}

/// `0xFFFF` when `a == b`, else 0. Constant time in both operands.
///
/// ⚠ `nz` must be ONE bit before it is negated into a mask. An earlier draft
/// truncated a shifted `u32` and kept sixteen, so the "not equal" mask came out
/// as garbage instead of zero and every OR-term bled into the result. The KAT
/// caught it (`d` decoded as `f` — the index off by two), which is the argument
/// for keeping a fixed published vector next to hand-rolled constant-time code.
inline fn ctEq(a: u16, b: u16) u16 {
    const d = a ^ b;
    const nz: u16 = (d | (0 -% d)) >> 15; // 1 when d != 0, else 0
    // ⛔⛔ The barrier goes on the RESULT, not on the input, and that is the
    // whole lesson. Laundering `d` hides the VALUE but not the STRUCTURE:
    // LLVM still saw that `ctEq(c,'+') & 62` is "62 when c=='+', else 0" and
    // emitted a `test`/`je` for it -- measured at `root.zig:292`, one live
    // branch in an otherwise clean run. Laundering the mask denies it the
    // rewrite. Same placement as `fss`'s `xorMasked`.
    return blackBox((nz ^ 1) *% 0xFFFF);
}

/// `0xFFFF` when `a >= b`, else 0. Operands must be < 2^15 (all are: they are
/// bytes and 6-bit groups), so the subtraction cannot wrap into the sign bit
/// for the wrong reason.
inline fn ctGe(a: u16, b: u16) u16 {
    const d = a -% b;
    return blackBox((~(d >> 15) & 1) *% 0xFFFF);
}

/// `0xFFFF` when `lo <= x <= hi`, else 0.
inline fn ctInRange(x: u16, lo: u16, hi: u16) u16 {
    return ctGe(x, lo) & ctGe(hi, x);
}

/// Base64 index (0..63) -> standard-alphabet character, without a table.
/// Shape follows libsodium's `b64_byte_to_char`.
inline fn ctB64Char(x: u16) u8 {
    const c =
        (ctInRange(x, 0, 25) & (x +% 'A')) |
        (ctInRange(x, 26, 51) & (x +% ('a' - 26))) |
        (ctInRange(x, 52, 61) & (x -% (52 - '0'))) | // 52-'0' == 4
        (ctEq(x, 62) & '+') |
        (ctEq(x, 63) & '/');
    return @truncate(c);
}

/// Standard-alphabet character -> base64 index, without a table.
/// Returns `0x100` for any character outside the alphabet, so the caller
/// accumulates one invalid flag instead of returning early.
inline fn ctB64Index(c: u16) u16 {
    const x =
        (ctInRange(c, 'A', 'Z') & (c -% 'A')) |
        (ctInRange(c, 'a', 'z') & (c -% ('a' - 26))) |
        (ctInRange(c, '0', '9') & (c +% (52 -% '0'))) |
        (ctEq(c, '+') & 62) |
        (ctEq(c, '/') & 63);
    // ⛔ `x == 0` is ambiguous: it is both the value of 'A' and the value of
    // "nothing matched". Disambiguate on the CHARACTER, not on the result.
    return x | (ctEq(x, 0) & ~ctEq(c, 'A') & 0x100);
}

/// Nibble -> lowercase hex digit, without a table.
inline fn ctHexChar(n: u16) u8 {
    // n < 10 -> '0'+n ; n >= 10 -> 'a'+n-10, and ('a'-10) - '0' == 39.
    return @truncate(n +% '0' +% (ctGe(n, 10) & 39));
}

/// Lowercase or uppercase hex digit -> nibble, without a table. Returns
/// `0x100` for any non-hex character.
inline fn ctHexNibble(c: u16) u16 {
    const v =
        (ctInRange(c, '0', '9') & (c -% '0')) |
        (ctInRange(c, 'a', 'f') & (c -% ('a' - 10))) |
        (ctInRange(c, 'A', 'F') & (c -% ('A' - 10)));
    // Same ambiguity as base64: 0 is the value of '0' and of "no match".
    return v | (ctEq(v, 0) & ~ctEq(c, '0') & 0x100);
}

/// Constant-time base64 encode of SECRET key material. 32 bytes -> 44 chars
/// (standard alphabet, one `=` of padding, since 32 = 3*10 + 2).
noinline fn encodeSecretKeyBase64Ct(out: *[base64_sk_len]u8, key: *const [secret_length]u8) void {
    var i: usize = 0;
    var o: usize = 0;
    // 10 full 3-byte groups -> 40 chars.
    while (i + 3 <= secret_length) : (i += 3) {
        const b0: u16 = key[i];
        const b1: u16 = key[i + 1];
        const b2: u16 = key[i + 2];
        out[o] = ctB64Char(b0 >> 2);
        out[o + 1] = ctB64Char(((b0 & 0x03) << 4) | (b1 >> 4));
        out[o + 2] = ctB64Char(((b1 & 0x0f) << 2) | (b2 >> 6));
        out[o + 3] = ctB64Char(b2 & 0x3f);
        o += 4;
    }
    // The trailing 2 bytes -> 3 chars + '='. The loop bound and this tail are
    // fixed by `secret_length`, not by data, so they carry no secret.
    const b0: u16 = key[secret_length - 2];
    const b1: u16 = key[secret_length - 1];
    out[o] = ctB64Char(b0 >> 2);
    out[o + 1] = ctB64Char(((b0 & 0x03) << 4) | (b1 >> 4));
    out[o + 2] = ctB64Char((b1 & 0x0f) << 2);
    out[o + 3] = '=';
}

/// Constant-time base64 decode of SECRET key material. Strict: exactly 44
/// chars, standard alphabet, one trailing `=`.
///
/// ⛔ Every character is decoded before anything is rejected: an early return
/// on the first bad character would leak WHERE the text went wrong, which is
/// the padding-oracle shape one layer up.
noinline fn parseSecretKeyBase64Ct(out: *[secret_length]u8, text: []const u8) KeyEncodingError!void {
    if (text.len != base64_sk_len) {
        std.crypto.secureZero(u8, out);
        return error.InvalidLength;
    }

    var invalid: u16 = 0;
    var vals: [base64_sk_len]u16 = undefined;
    for (text[0 .. base64_sk_len - 1], vals[0 .. base64_sk_len - 1]) |c, *v| {
        const idx = ctB64Index(c);
        invalid |= idx & 0x100;
        v.* = idx & 0x3f;
    }
    // Padding is structural, not secret: the last character must be '='.
    invalid |= ctEq(text[base64_sk_len - 1], '=') & 0x100 ^ 0x100;

    var i: usize = 0;
    var o: usize = 0;
    while (o + 3 <= secret_length) : (o += 3) {
        const acc = (@as(u32, vals[i]) << 18) | (@as(u32, vals[i + 1]) << 12) |
            (@as(u32, vals[i + 2]) << 6) | @as(u32, vals[i + 3]);
        out[o] = @truncate(acc >> 16);
        out[o + 1] = @truncate(acc >> 8);
        out[o + 2] = @truncate(acc);
        i += 4;
    }
    const acc = (@as(u32, vals[i]) << 18) | (@as(u32, vals[i + 1]) << 12) | (@as(u32, vals[i + 2]) << 6);
    out[secret_length - 2] = @truncate(acc >> 16);
    out[secret_length - 1] = @truncate(acc >> 8);
    // The final group's low 6 bits must be zero, or two distinct texts would
    // decode to the same key (RFC 4648 §3.5 canonical form).
    invalid |= ctEq(@as(u16, @truncate(acc)) & 0xff, 0) & 0x100 ^ 0x100;

    if (invalid != 0) {
        std.crypto.secureZero(u8, out);
        return error.InvalidKeyEncoding;
    }
}

/// Constant-time lowercase-hex encode of SECRET key material.
fn encodeSecretKeyHexCt(key: [secret_length]u8) [hex_sk_len]u8 {
    var out: [hex_sk_len]u8 = undefined;
    for (key, 0..) |b, i| {
        out[2 * i] = ctHexChar(@as(u16, b) >> 4);
        out[2 * i + 1] = ctHexChar(@as(u16, b) & 0x0f);
    }
    return out;
}

/// Constant-time hex decode of SECRET key material. Either case, exactly 64
/// digits, and — like the base64 parser — every digit is decoded before any
/// rejection.
noinline fn parseSecretKeyHexCt(out: *[secret_length]u8, text: []const u8) KeyEncodingError!void {
    if (text.len != hex_sk_len) {
        std.crypto.secureZero(u8, out);
        return error.InvalidLength;
    }

    var invalid: u16 = 0;
    for (out, 0..) |*b, i| {
        const hi = ctHexNibble(text[2 * i]);
        const lo = ctHexNibble(text[2 * i + 1]);
        invalid |= (hi | lo) & 0x100;
        b.* = @truncate(((hi & 0x0f) << 4) | (lo & 0x0f));
    }
    if (invalid != 0) {
        std.crypto.secureZero(u8, out);
        return error.InvalidKeyEncoding;
    }
}

fn encodeKeyBase64(key: [32]u8) [base64_pk_len]u8 {
    var out: [base64_pk_len]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &key);
    return out;
}

fn parseKeyBase64(text: []const u8) KeyEncodingError![32]u8 {
    if (text.len != base64_pk_len) return error.InvalidLength;
    // Right length but wrong padding shape (e.g. trailing "==") would decode to
    // fewer than 32 bytes — reject before decoding into the fixed-size output.
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(text) catch
        return error.InvalidKeyEncoding;
    if (decoded_len != 32) return error.InvalidKeyEncoding;
    var out: [32]u8 = undefined;
    std.base64.standard.Decoder.decode(&out, text) catch return error.InvalidKeyEncoding;
    return out;
}

fn parseKeyHex(text: []const u8) KeyEncodingError![32]u8 {
    if (text.len != hex_pk_len) return error.InvalidLength;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch return error.InvalidKeyEncoding;
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────────

// Dark-tests aggregator (CONVENTIONS.md §6.3): a bare re-export does not pull
// a submodule's tests into the test binary — this reference does.
test {
    _ = @import("kat_test.zig");
}

// Value-returning shims for the tests below, which compare keys and texts
// inline. The public secret-key codecs write into caller buffers (audit A1 L8).
fn testEncodeSecretKeyBase64(sk: [secret_length]u8) [base64_sk_len]u8 {
    var text: [base64_sk_len]u8 = undefined;
    encodeSecretKeyBase64(&text, &sk);
    return text;
}

fn testParseSecretKeyBase64(text: []const u8) KeyEncodingError![secret_length]u8 {
    var key: [secret_length]u8 = undefined;
    try parseSecretKeyBase64(&key, text);
    return key;
}

fn testParseSecretKeyHex(text: []const u8) KeyEncodingError![secret_length]u8 {
    var key: [secret_length]u8 = undefined;
    try parseSecretKeyHex(&key, text);
    return key;
}

// A wrong `out` size used to be `std.debug.assert`, which ReleaseFast removes
// -- so the mistake was caught in exactly the build where it costs least.
// Written in terms of `overhead` rather than a literal, so the test measures
// the mechanism and not one arithmetic result.
test "seal: a wrong-sized out buffer is an error, not an assert" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);
    const msg = "sealed-box buffer size check";

    var too_small: [msg.len + overhead - 1]u8 = undefined;
    try std.testing.expectError(error.InvalidBufferSize, seal(io, &too_small, msg, kp.public_key));

    var too_large: [msg.len + overhead + 1]u8 = undefined;
    try std.testing.expectError(error.InvalidBufferSize, seal(io, &too_large, msg, kp.public_key));

    var exact: [msg.len + overhead]u8 = undefined;
    try seal(io, &exact, msg, kp.public_key);
}

test "round-trip: buffer API, various sizes including empty" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);

    const msgs = [_][]const u8{ "", "x", "hello sealed box", "a" ** 100 };
    inline for (msgs) |msg| {
        var boxed: [msg.len + overhead]u8 = undefined;
        try seal(io, &boxed, msg, kp.public_key);
        try std.testing.expectEqual(sealedLen(msg.len), boxed.len);

        var opened: [msg.len]u8 = undefined;
        try open(&opened, &boxed, kp);
        try std.testing.expectEqualSlices(u8, msg, &opened);
    }
}

test "round-trip: sealAlloc/openAlloc" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const kp = KeyPair.generate(io);

    const msgs = [_][]const u8{ "", "allocating convenience round-trip" };
    for (msgs) |msg| {
        const boxed = try sealAlloc(gpa, io, msg, kp.public_key);
        defer gpa.free(boxed);
        try std.testing.expectEqual(sealedLen(msg.len), boxed.len);
        try std.testing.expectEqual(msg.len + overhead, boxed.len);

        const opened = try openAlloc(gpa, boxed, kp);
        defer gpa.free(opened);
        try std.testing.expectEqualSlices(u8, msg, opened);
    }
}

test "tamper: flipped byte in box or ephemeral pk fails authentication" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);
    const msg = "tamper me";

    var boxed: [msg.len + overhead]u8 = undefined;
    try seal(io, &boxed, msg, kp.public_key);
    var opened: [msg.len]u8 = undefined;

    // flip a byte in the box portion (past the ephemeral pk prefix)
    var t1 = boxed;
    t1[t1.len - 1] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &t1, kp));

    // flip a byte in the ephemeral pk prefix
    var t2 = boxed;
    t2[0] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &t2, kp));
}

test "wrong recipient keypair fails authentication" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);
    const wrong_kp = KeyPair.generate(io);
    const msg = "for someone else";

    var boxed: [msg.len + overhead]u8 = undefined;
    try seal(io, &boxed, msg, kp.public_key);
    var opened: [msg.len]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &boxed, wrong_kp));
}

test "too-short/garbage ciphertext: clean error, no panic" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const kp = KeyPair.generate(io);

    var opened: [4]u8 = undefined;

    // shorter than the overhead
    const short = [_]u8{0xaa} ** (overhead - 1);
    try std.testing.expectError(error.InvalidCiphertext, open(&opened, &short, kp));
    try std.testing.expectError(error.InvalidCiphertext, openAlloc(gpa, &short, kp));

    // empty ciphertext
    try std.testing.expectError(error.InvalidCiphertext, open(&opened, "", kp));
    try std.testing.expectError(error.InvalidCiphertext, openAlloc(gpa, "", kp));

    // long enough but out-length mismatch
    const mismatched = [_]u8{0xbb} ** (overhead + 10);
    try std.testing.expectError(error.InvalidCiphertext, open(&opened, &mismatched, kp));

    // well-sized garbage: must fail authentication, never panic
    var garbage: [4 + overhead]u8 = undefined;
    io.random(&garbage);
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &garbage, kp));
}

test "KAT: a key whose base64 uses BOTH `+` and `/` — the two alphabet slots nothing else covers" {
    // ⛔ Audit finding L1. Mutation M13 (decoder switched to the URL-SAFE
    // alphabet, `-` `_` instead of `+` `/`) was caught only BY LUCK: both
    // fixed KAT strings in this module ("AAECAwQ…" and "dwdtCnMYpX08…")
    // contain neither character, so the only test that could see the swap
    // encoded a FRESHLY GENERATED key and its verdict rode on entropy.
    // P(a random 32-byte key encodes without `+` or `/`) ≈ 0.255, two keys per
    // run, so the gate went green roughly once every twelve runs — measured
    // RED 11 / GREEN 1 of 12. A gate whose teeth are on a coin flip.
    //
    // This vector is chosen so that indices 62 (`+`) and 63 (`/`) both appear:
    // three occurrences, at three different 6-bit positions.
    const key: [public_length]u8 = .{
        0x48, 0x47, 0x08, 0xfc, 0xe1, 0x0f, 0x53, 0x01,
        0xf0, 0xd0, 0x02, 0x7e, 0x87, 0xdf, 0x9e, 0xc3,
        0xa9, 0xfc, 0x9b, 0x6a, 0xb9, 0x9a, 0xd6, 0x80,
        0x8e, 0x14, 0xef, 0xa3, 0xa0, 0x2e, 0xe8, 0xef,
    };
    const expected = "SEcI/OEPUwHw0AJ+h9+ew6n8m2q5mtaAjhTvo6Au6O8=";
    try std.testing.expect(std.mem.indexOfScalar(u8, expected, '+') != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, expected, '/') != null);

    // Public path — still `std.base64`, and the path M13 mutated.
    const pub_b64 = encodePublicKeyBase64(key);
    try std.testing.expectEqualStrings(expected, &pub_b64);
    try std.testing.expectEqual(key, try parsePublicKeyBase64(expected));

    // Secret path — this module's own constant-time codec, which must agree
    // character for character on exactly these two slots.
    const sec_b64 = testEncodeSecretKeyBase64(key);
    try std.testing.expectEqualStrings(expected, &sec_b64);
    try std.testing.expectEqualSlices(u8, &key, &(try testParseSecretKeyBase64(expected)));

    // ⛔ And the url-safe spelling of the SAME key must be rejected by both,
    // which is what makes this a test of the alphabet rather than of a string:
    // an implementation that quietly accepted `-`/`_` would round-trip happily.
    var urlsafe: [base64_pk_len]u8 = undefined;
    @memcpy(&urlsafe, expected);
    for (&urlsafe) |*c| c.* = switch (c.*) {
        '+' => '-',
        '/' => '_',
        else => c.*,
    };
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64(&urlsafe));
    try std.testing.expectError(error.InvalidKeyEncoding, testParseSecretKeyBase64(&urlsafe));
}

test "KAT: public key base64 + hex, exact strings and decode-back" {
    const pk: [public_length]u8 = blk: {
        var k: [public_length]u8 = undefined;
        for (&k, 0..) |*b, i| b.* = @intCast(i);
        break :blk k; // 00 01 02 … 1f
    };

    const b64 = encodePublicKeyBase64(pk);
    try std.testing.expectEqual(base64_pk_len, b64.len);
    try std.testing.expectEqualStrings("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", &b64);
    try std.testing.expectEqual(pk, try parsePublicKeyBase64(&b64));

    const hex = encodePublicKeyHex(pk);
    try std.testing.expectEqual(hex_pk_len, hex.len);
    try std.testing.expectEqualStrings(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        &hex,
    );
    try std.testing.expectEqual(pk, try parsePublicKeyHex(&hex));
    // hex parsing accepts uppercase too
    try std.testing.expectEqual(pk, try parsePublicKeyHex(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    ));
}

test "KAT: secret key (RFC 7748 Alice) base64 + hex + public recompute" {
    // RFC 7748 §6.1 Alice's secret and public key.
    const sk_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const pk_hex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const sk = try testParseSecretKeyHex(sk_hex);

    const b64 = testEncodeSecretKeyBase64(sk);
    try std.testing.expectEqualStrings("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", &b64);
    try std.testing.expectEqual(sk, try testParseSecretKeyBase64(&b64));

    const hex = encodeSecretKeyHex(sk);
    try std.testing.expectEqualStrings(sk_hex, &hex);
    try std.testing.expectEqual(sk, try testParseSecretKeyHex(&hex));

    // secret → public rebuild matches the RFC vector
    const pk = try publicFromSecret(sk);
    try std.testing.expectEqualStrings(pk_hex, &encodePublicKeyHex(pk));
    const kp = try keyPairFromSecretKey(sk);
    try std.testing.expectEqual(pk, kp.public_key);
    try std.testing.expectEqual(sk, kp.secret_key);
}

test "round-trip: generated keys survive text serialization; rebuilt keypair opens" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);

    // public key: base64 + hex round-trip
    try std.testing.expectEqual(kp.public_key, try parsePublicKeyBase64(&encodePublicKeyBase64(kp.public_key)));
    try std.testing.expectEqual(kp.public_key, try parsePublicKeyHex(&encodePublicKeyHex(kp.public_key)));

    // secret key: base64 + hex round-trip
    try std.testing.expectEqual(kp.secret_key, try testParseSecretKeyBase64(&testEncodeSecretKeyBase64(kp.secret_key)));
    try std.testing.expectEqual(kp.secret_key, try testParseSecretKeyHex(&encodeSecretKeyHex(kp.secret_key)));

    // end-to-end: serialize both keys → parse back → seal to parsed public key
    // → open with a keypair rebuilt from the stored secret
    const pk_stored = encodePublicKeyBase64(kp.public_key);
    const sk_stored = encodeSecretKeyHex(kp.secret_key);
    const pk_back = try parsePublicKeyBase64(&pk_stored);
    const kp_back = try keyPairFromSecretKey(try testParseSecretKeyHex(&sk_stored));
    try std.testing.expectEqual(kp.public_key, kp_back.public_key);

    const msg = "keys came from a config file";
    var boxed: [msg.len + overhead]u8 = undefined;
    try seal(io, &boxed, msg, pk_back);
    var opened: [msg.len]u8 = undefined;
    try open(&opened, &boxed, kp_back);
    try std.testing.expectEqualSlices(u8, msg, &opened);
}

test "malformed key text: typed errors, no panic" {
    const good_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const good_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    // base64: wrong length (short, long, empty)
    try std.testing.expectError(error.InvalidLength, parsePublicKeyBase64(good_b64[0 .. good_b64.len - 1]));
    try std.testing.expectError(error.InvalidLength, parsePublicKeyBase64(good_b64 ++ "A"));
    try std.testing.expectError(error.InvalidLength, parsePublicKeyBase64(""));
    // base64: non-alphabet chars at right length
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64("!" ++ good_b64[1..]));
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh?="));
    // base64: embedded whitespace is rejected (strict policy)
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64(" " ++ good_b64[1..]));
    // base64: wrong padding shape (44 chars but decodes to 31 or 33 bytes)
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64(good_b64[0..42] ++ "=="));
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64(good_b64[0..43] ++ "A"));

    // hex: odd length, wrong length, empty
    try std.testing.expectError(error.InvalidLength, parsePublicKeyHex(good_hex[0..63]));
    try std.testing.expectError(error.InvalidLength, parsePublicKeyHex(good_hex[0..62]));
    try std.testing.expectError(error.InvalidLength, parsePublicKeyHex(good_hex ++ "00"));
    try std.testing.expectError(error.InvalidLength, parsePublicKeyHex(""));
    // hex: non-hex chars / whitespace at right length
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyHex("zz" ++ good_hex[2..]));
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyHex(" " ++ good_hex[1..]));

    // secret parsers share the code path — spot-check both error kinds
    try std.testing.expectError(error.InvalidLength, testParseSecretKeyBase64("short"));
    try std.testing.expectError(error.InvalidKeyEncoding, testParseSecretKeyBase64("*" ++ good_b64[1..]));
    try std.testing.expectError(error.InvalidLength, testParseSecretKeyHex("abc"));
    try std.testing.expectError(error.InvalidKeyEncoding, testParseSecretKeyHex("g" ++ good_hex[1..]));
}

test "constant-time codecs: EXHAUSTIVE agreement with std over every input byte" {
    // ⭐ Exhaustive rather than sampled, and it is cheap: 64 + 256 + 16 + 256
    // cases. The `hqc` precedent is the reason -- there, a table lookup and its
    // constant-time replacement agreed on all 65 536 pairs and STILL differed
    // in the only way that mattered (the memory access pattern). Value equality
    // is what this test can prove; it proves it completely.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (0..64) |i| {
        try std.testing.expectEqual(alphabet[i], ctB64Char(@intCast(i)));
    }
    for (0..256) |c| {
        const got = ctB64Index(@intCast(c));
        if (std.mem.indexOfScalar(u8, alphabet, @intCast(c))) |idx| {
            try std.testing.expectEqual(@as(u16, @intCast(idx)), got);
        } else {
            // ⛔ The invalid marker must be OUTSIDE the 0..63 range a valid
            // index occupies, or "not in the alphabet" would decode as data.
            try std.testing.expectEqual(@as(u16, 0x100), got & 0x100);
        }
    }

    const hex_digits = "0123456789abcdef";
    for (0..16) |n| {
        try std.testing.expectEqual(hex_digits[n], ctHexChar(@intCast(n)));
    }
    for (0..256) |c| {
        const got = ctHexNibble(@intCast(c));
        const ch: u8 = @intCast(c);
        const expected: ?u16 = switch (ch) {
            '0'...'9' => ch - '0',
            'a'...'f' => ch - 'a' + 10,
            'A'...'F' => ch - 'A' + 10,
            else => null,
        };
        if (expected) |e| {
            try std.testing.expectEqual(e, got);
        } else {
            try std.testing.expectEqual(@as(u16, 0x100), got & 0x100);
        }
    }
}

test "constant-time codecs: agree with the std-backed public path on 512 keys" {
    // ⭐ The public-key codecs still go through std, so they are a live oracle
    // for the secret-key ones sitting right next to them -- the same bytes,
    // encoded two independent ways, in the same test binary.
    var seed: u64 = 0x5ea1edb0;
    for (0..512) |_| {
        var key: [secret_length]u8 = undefined;
        for (&key) |*b| {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            b.* = @truncate(seed >> 33);
        }

        const ct_b64 = testEncodeSecretKeyBase64(key);
        const std_b64 = encodePublicKeyBase64(key);
        try std.testing.expectEqualStrings(&std_b64, &ct_b64);

        const ct_hex = encodeSecretKeyHex(key);
        const std_hex = encodePublicKeyHex(key);
        try std.testing.expectEqualStrings(&std_hex, &ct_hex);

        try std.testing.expectEqualSlices(u8, &key, &(try testParseSecretKeyBase64(&ct_b64)));
        try std.testing.expectEqualSlices(u8, &key, &(try testParseSecretKeyHex(&ct_hex)));
        // Uppercase hex is accepted by both parsers.
        var upper = ct_hex;
        for (&upper) |*c| c.* = std.ascii.toUpper(c.*);
        try std.testing.expectEqualSlices(u8, &key, &(try testParseSecretKeyHex(&upper)));
    }
}

test "constant-time parsers reject exactly what the std-backed ones reject" {
    var key: [secret_length]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    const b64 = testEncodeSecretKeyBase64(key);
    const hex = encodeSecretKeyHex(key);

    // A bad character in EVERY position, checked against the public parser.
    for (0..b64.len) |i| {
        var bad = b64;
        bad[i] = if (bad[i] == '*') '#' else '*';
        try std.testing.expectError(error.InvalidKeyEncoding, testParseSecretKeyBase64(&bad));
        try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64(&bad));
    }
    for (0..hex.len) |i| {
        var bad = hex;
        bad[i] = 'z';
        try std.testing.expectError(error.InvalidKeyEncoding, testParseSecretKeyHex(&bad));
        try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyHex(&bad));
    }

    // Length is structural, not secret, so it stays a distinct error.
    try std.testing.expectError(error.InvalidLength, testParseSecretKeyBase64(b64[0 .. b64.len - 1]));
    try std.testing.expectError(error.InvalidLength, testParseSecretKeyHex(hex[0 .. hex.len - 1]));

    // Padding must be present and last.
    var nopad = b64;
    nopad[b64.len - 1] = 'A';
    try std.testing.expectError(error.InvalidKeyEncoding, testParseSecretKeyBase64(&nopad));

    // ⛔ Non-canonical final group: the last 6-bit value carries 2 bits that
    // MUST be zero. Without this check two distinct texts decode to one key,
    // which is a malleable key encoding (RFC 4648 §3.5).
    var noncanon = b64;
    noncanon[b64.len - 2] = ctB64Char(ctB64Index(noncanon[b64.len - 2]) | 1);
    try std.testing.expectError(error.InvalidKeyEncoding, testParseSecretKeyBase64(&noncanon));
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64(&noncanon));
}

test "wipe: the encoded secret really is gone from the buffer" {
    // Round-trips first, so the test cannot pass by wiping something that was
    // never a secret in the first place.
    const sk = [_]u8{0xA5} ** secret_length;
    var text = testEncodeSecretKeyBase64(sk);
    try std.testing.expectEqual(sk, try testParseSecretKeyBase64(&text));

    wipe(&text);
    for (text) |c| try std.testing.expectEqual(@as(u8, 0), c);

    var hex_text = encodeSecretKeyHex(sk);
    try std.testing.expectEqual(sk, try testParseSecretKeyHex(&hex_text));
    wipe(&hex_text);
    for (hex_text) |c| try std.testing.expectEqual(@as(u8, 0), c);

    // And the raw scalar itself.
    var raw = sk;
    wipe(&raw);
    try std.testing.expectEqual([_]u8{0} ** secret_length, raw);
}
