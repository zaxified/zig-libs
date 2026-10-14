// SPDX-License-Identifier: MIT

//! Key serialisation: the DER and PEM writers mirroring `root.zig`'s parsers
//! (`PublicKey.fromDer`/`fromPem`, `SecretKey.fromDer`/`fromPem`, `fromPkcs8`).
//!
//! Allocation-free and copy-free for secrets: DER is written back to front
//! straight into the caller's `out` (every TLV's length is known once its
//! content is down), then moved to the front of `out`; each secret INTEGER is
//! written by position from its limbs into its final place, so no secret
//! value is staged in a stack buffer. On error `out` is zeroed.
//!
//! The encoding is canonical DER (minimal INTEGERs with a sign octet where the
//! top bit is set, minimal definite lengths), so for the same key the output
//! equals OpenSSL's `i2d_*` and Go's `x509.Marshal*` byte for byte. Stripping
//! an INTEGER's leading zero octets branches on the top bytes of the value:
//! DER makes a value's byte length part of the encoding, and every parser
//! (ours included) reads it from the length octets anyway.

const std = @import("std");
const root = @import("root.zig");
const montint = @import("montint");

const MontParams = montint.DynModint(root.max_modulus_bits);
const MontElem = MontParams.Elem;
const PublicKey = root.PublicKey;
const SecretKey = root.SecretKey;

pub const MarshalError = error{BufferTooSmall};

const k = root.max_modulus_len;

/// INTEGER header (≤ 4) + sign octet + `len` content bytes.
fn intMax(len: usize) usize {
    return 4 + 1 + len;
}

/// AlgorithmIdentifier { rsaEncryption, NULL } — the only one this module
/// reads or writes for a key (RFC 8017 Appendix A.1).
const alg_id_rsa = [_]u8{ 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };

/// Largest `RSAPublicKey` DER: SEQUENCE { n, e }.
pub const max_pkcs1_public_der_len = 4 + intMax(k) + intMax(4);
/// Largest `SubjectPublicKeyInfo` DER: SEQUENCE { algId, BIT STRING { 0, RSAPublicKey } }.
pub const max_spki_der_len = 4 + alg_id_rsa.len + 4 + 1 + max_pkcs1_public_der_len;
/// Largest two-prime `RSAPrivateKey` DER. `p`, `dP`, `qInv` are below `p` and
/// `q`, `dQ` below `q`, with `|p| + |q| ≤ k + 1` bytes for any split of the
/// modulus (`fromPrimes` does not require balanced primes).
pub const max_pkcs1_private_der_len = 4 + intMax(1) + 2 * intMax(k) + intMax(4) + 5 * 5 + 3 * (k + 1);
/// Largest PKCS#8 `PrivateKeyInfo` DER wrapping `max_pkcs1_private_der_len`.
pub const max_pkcs8_der_len = 4 + intMax(1) + alg_id_rsa.len + 4 + max_pkcs1_private_der_len;

/// Length of a PEM block for `der_len` DER bytes under `label`: RFC 7468
/// strict form, 64-column base64 lines, `\n` line ends (what OpenSSL writes).
pub fn pemLen(label_len: usize, der_len: usize) usize {
    const lines = (der_len + 47) / 48;
    return ("-----BEGIN -----\n".len + label_len) + std.base64.standard.Encoder.calcSize(der_len) + lines +
        ("-----END -----\n".len + label_len);
}

/// Largest PEM `toPem` writes for a public key (either label).
pub const max_public_pem_len = pemLen("RSA PUBLIC KEY".len, max_spki_der_len);
/// Largest PEM `toPem` writes for a secret key (either label).
pub const max_private_pem_len = pemLen("RSA PRIVATE KEY".len, max_pkcs8_der_len);

/// Back-to-front DER writer: content lives in `buf[pos..]`.
const RevWriter = struct {
    buf: []u8,
    pos: usize,

    fn init(buf: []u8) RevWriter {
        return .{ .buf = buf, .pos = buf.len };
    }

    fn len(w: *const RevWriter) usize {
        return w.buf.len - w.pos;
    }

    fn byte(w: *RevWriter, b: u8) MarshalError!void {
        if (w.pos == 0) return error.BufferTooSmall;
        w.pos -= 1;
        w.buf[w.pos] = b;
    }

    fn bytes(w: *RevWriter, b: []const u8) MarshalError!void {
        if (b.len > w.pos) return error.BufferTooSmall;
        w.pos -= b.len;
        @memcpy(w.buf[w.pos..][0..b.len], b);
    }

    /// Tag and minimal definite length for `content_len` bytes already down.
    fn header(w: *RevWriter, tag: u8, content_len: usize) MarshalError!void {
        if (content_len < 0x80) {
            try w.byte(@intCast(content_len));
        } else if (content_len < 0x100) {
            try w.byte(@intCast(content_len));
            try w.byte(0x81);
        } else {
            std.debug.assert(content_len < 0x10000); // every structure here is < 8 KiB
            try w.byte(@truncate(content_len));
            try w.byte(@intCast(content_len >> 8));
            try w.byte(0x82);
        }
        try w.byte(tag);
    }

    /// Close a constructed element whose content began when `len()` was `mark`.
    fn close(w: *RevWriter, tag: u8, mark: usize) MarshalError!void {
        try w.header(tag, w.len() - mark);
    }

    /// INTEGER of the non-negative limb value `v`, written by position into
    /// a `width`-byte field (`width` ≥ the value's byte length), then
    /// trimmed to its minimal form.
    fn integer(w: *RevWriter, v: *const MontElem, width: usize) MarshalError!void {
        if (width == 0 or width > w.pos) return error.BufferTooSmall;
        const end = w.pos;
        const field = w.buf[end - width .. end];
        for (field, 0..) |*o, i| {
            const at = width - 1 - i;
            o.* = if (at / 8 < v.len) @truncate(v[at / 8] >> @intCast(8 * (at % 8))) else 0;
        }
        var z: usize = 0;
        while (z + 1 < width and field[z] == 0) z += 1;
        w.pos = end - width + z;
        if (field[z] & 0x80 != 0) try w.byte(0);
        try w.header(0x02, end - w.pos);
    }

    fn integerU32(w: *RevWriter, v: u32) MarshalError!void {
        var e = MontParams.zero;
        e[0] = v;
        try w.integer(&e, 4);
    }

    /// Move the finished DER to the front of `buf`, zero what it vacated.
    fn finish(w: *RevWriter) []u8 {
        const n = w.len();
        std.mem.copyForwards(u8, w.buf[0..n], w.buf[w.pos..]);
        std.crypto.secureZero(u8, w.buf[@max(n, w.pos)..]);
        return w.buf[0..n];
    }
};

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
fn writePkcs1Public(w: *RevWriter, m: *const MontParams, e: u32) MarshalError!void {
    const mark = w.len();
    try w.integerU32(e);
    try w.integer(&m.m, m.byteLen());
    try w.close(0x30, mark);
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }`.
fn writeSpki(w: *RevWriter, m: *const MontParams, e: u32) MarshalError!void {
    const mark = w.len();
    const bits_mark = w.len();
    try writePkcs1Public(w, m, e);
    try w.byte(0); // no unused bits
    try w.close(0x03, bits_mark);
    try w.bytes(&alg_id_rsa);
    try w.close(0x30, mark);
}

/// `RSAPrivateKey` (RFC 8017 A.1.2), version 0, two-prime.
fn writePkcs1Private(w: *RevWriter, sk: *const SecretKey) MarshalError!void {
    const plen = sk.p_mont.byteLen();
    const qlen = sk.q_mont.byteLen();
    const nlen = sk.n_mont.byteLen();
    var t: MontElem = undefined;
    defer std.crypto.secureZero(u64, &t);

    const mark = w.len();
    t = MontParams.elemFromFf(&sk.qinv.v);
    try w.integer(&t, plen);
    t = MontParams.elemFromFf(&sk.dq.v);
    try w.integer(&t, qlen);
    t = MontParams.elemFromFf(&sk.dp.v);
    try w.integer(&t, plen);
    try w.integer(&sk.q_mont.m, qlen);
    try w.integer(&sk.p_mont.m, plen);
    t = MontParams.elemFromFf(&sk.d.v);
    try w.integer(&t, nlen);
    try w.integerU32(sk.e.toPrimitive(u32) catch unreachable); // < 2^32 since fromPrimes
    try w.integer(&sk.n_mont.m, nlen);
    try w.integerU32(0); // version: two-prime
    try w.close(0x30, mark);
}

/// `PrivateKeyInfo ::= SEQUENCE { version 0, algorithm, privateKey OCTET STRING }`.
fn writePkcs8(w: *RevWriter, sk: *const SecretKey) MarshalError!void {
    const mark = w.len();
    const oct_mark = w.len();
    try writePkcs1Private(w, sk);
    try w.close(0x04, oct_mark);
    try w.bytes(&alg_id_rsa);
    try w.integerU32(0);
    try w.close(0x30, mark);
}

pub const PublicDer = enum { pkcs1, spki };
pub const PrivateDer = enum { pkcs1, pkcs8 };

pub fn publicDer(m: *const MontParams, e: u32, form: PublicDer, out: []u8) MarshalError![]u8 {
    var w = RevWriter.init(out);
    (switch (form) {
        .pkcs1 => writePkcs1Public(&w, m, e),
        .spki => writeSpki(&w, m, e),
    }) catch |err| {
        @memset(out, 0);
        return err;
    };
    return w.finish();
}

pub fn privateDer(sk: *const SecretKey, form: PrivateDer, out: []u8) MarshalError![]u8 {
    var w = RevWriter.init(out);
    (switch (form) {
        .pkcs1 => writePkcs1Private(&w, sk),
        .pkcs8 => writePkcs8(&w, sk),
    }) catch |err| {
        std.crypto.secureZero(u8, out);
        return err;
    };
    return w.finish();
}

pub fn publicPem(m: *const MontParams, e: u32, form: PublicDer, out: []u8) MarshalError![]u8 {
    var w = RevWriter.init(out);
    (switch (form) {
        .pkcs1 => writePkcs1Public(&w, m, e),
        .spki => writeSpki(&w, m, e),
    }) catch |err| {
        @memset(out, 0);
        return err;
    };
    return pemFromTail(out, w.len(), switch (form) {
        .pkcs1 => "RSA PUBLIC KEY",
        .spki => "PUBLIC KEY",
    });
}

pub fn privatePem(sk: *const SecretKey, form: PrivateDer, out: []u8) MarshalError![]u8 {
    var w = RevWriter.init(out);
    (switch (form) {
        .pkcs1 => writePkcs1Private(&w, sk),
        .pkcs8 => writePkcs8(&w, sk),
    }) catch |err| {
        std.crypto.secureZero(u8, out);
        return err;
    };
    return pemFromTail(out, w.len(), switch (form) {
        .pkcs1 => "RSA PRIVATE KEY",
        .pkcs8 => "PRIVATE KEY",
    });
}

/// PEM-encode the `der_len` DER bytes at the end of `out` in place. The DER
/// is first moved to end exactly where the PEM text will end; base64 output
/// (4 bytes per 3, plus newlines) then never overtakes the DER still to be
/// read, since each 48-byte chunk is copied out before its 65 bytes go down.
fn pemFromTail(out: []u8, der_len: usize, label: []const u8) MarshalError![]u8 {
    const total = pemLen(label.len, der_len);
    if (total > out.len) {
        std.crypto.secureZero(u8, out);
        return error.BufferTooSmall;
    }
    const der_at = total - der_len;
    std.mem.copyForwards(u8, out[der_at..total], out[out.len - der_len ..]);
    std.crypto.secureZero(u8, out[total..]);

    var o: usize = 0;
    for ([_][]const u8{ "-----BEGIN ", label, "-----\n" }) |s| {
        @memcpy(out[o..][0..s.len], s);
        o += s.len;
    }
    var chunk: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &chunk);
    var i: usize = 0;
    while (i < der_len) : (i += 48) {
        const n = @min(48, der_len - i);
        @memcpy(chunk[0..n], out[der_at + i ..][0..n]);
        std.debug.assert(o + 65 <= der_at + i + n or i + n == der_len); // never overwrites unread DER
        o += std.base64.standard.Encoder.encode(out[o..], chunk[0..n]).len;
        out[o] = '\n';
        o += 1;
    }
    for ([_][]const u8{ "-----END ", label, "-----\n" }) |s| {
        @memcpy(out[o..][0..s.len], s);
        o += s.len;
    }
    std.debug.assert(o == total);
    return out[0..total];
}

// ── encrypted PKCS#8: PBES2 with PBKDF2 (RFC 8018 §6.2, A.2, A.4) ───────────

const aescbc = @import("aescbc");
const Aes192 = @import("aes192").Aes192;

/// 1.2.840.113549.1.5.13 / .12 (RFC 8018 Appendix A.4 / A.2).
pub const oid_pbes2 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d };
pub const oid_pbkdf2 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c };
/// 1.2.840.113549.2.x — hmacWithSHA1 (7) … hmacWithSHA512 (11).
pub const oid_hmac_arc = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02 };
/// 2.16.840.1.101.3.4.1.x — aes128-CBC (2), aes192-CBC (22), aes256-CBC (42).
pub const oid_aes_arc = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01 };

/// The PBKDF2 pseudo-random function (PBKDF2-params `prf`).
pub const Pbes2Prf = enum {
    hmac_sha1,
    hmac_sha224,
    hmac_sha256,
    hmac_sha384,
    hmac_sha512,

    pub fn Type(comptime prf: Pbes2Prf) type {
        const h = std.crypto.auth.hmac;
        return switch (prf) {
            .hmac_sha1 => h.HmacSha1,
            .hmac_sha224 => h.sha2.HmacSha224,
            .hmac_sha256 => h.sha2.HmacSha256,
            .hmac_sha384 => h.sha2.HmacSha384,
            .hmac_sha512 => h.sha2.HmacSha512,
        };
    }

    pub fn oidLast(prf: Pbes2Prf) u8 {
        return 7 + @as(u8, @intFromEnum(prf));
    }

    pub fn fromOidLast(b: u8) ?Pbes2Prf {
        if (b < 7 or b > 11) return null;
        return @enumFromInt(b - 7);
    }
};

/// The PBES2 encryption scheme: AES-CBC with PKCS#7 padding (what OpenSSL,
/// Go's x/crypto users and every other common PBES2 writer use).
pub const Pbes2Cipher = enum {
    aes128_cbc,
    aes192_cbc,
    aes256_cbc,

    pub fn Aes(comptime c: Pbes2Cipher) type {
        const aes = std.crypto.core.aes;
        return switch (c) {
            .aes128_cbc => aes.Aes128,
            .aes192_cbc => Aes192,
            .aes256_cbc => aes.Aes256,
        };
    }

    pub fn keyLen(c: Pbes2Cipher) usize {
        return switch (c) {
            .aes128_cbc => 16,
            .aes192_cbc => 24,
            .aes256_cbc => 32,
        };
    }

    pub fn oidLast(c: Pbes2Cipher) u8 {
        return switch (c) {
            .aes128_cbc => 0x02,
            .aes192_cbc => 0x16,
            .aes256_cbc => 0x2a,
        };
    }

    pub fn fromOidLast(b: u8) ?Pbes2Cipher {
        return switch (b) {
            0x02 => .aes128_cbc,
            0x16 => .aes192_cbc,
            0x2a => .aes256_cbc,
            else => null,
        };
    }
};

/// The largest PBKDF2 iteration count read or written: 2^20, ~0.3 s of
/// HMAC-SHA-256 on a desktop core (512× OpenSSL's default of 2048, above
/// OWASP's 600 000 for SHA-256). A file may name any count up to 2^32 − 1;
/// without a cap an untrusted key file is a CPU-burning input (the OpenSSH
/// bcrypt-rounds HANG of 2026-10-09 is the same class).
pub const max_pbkdf2_iterations: u32 = 1 << 20;
/// The longest PBKDF2 salt read or written (OpenSSL writes 16).
pub const max_pbes2_salt_len = 64;

/// Parameters for `SecretKey.toPkcs8Encrypted`; the defaults are OpenSSL 3's
/// `openssl pkcs8 -topk8` / `genpkey -aes256` output shape.
pub const Pbes2Options = struct {
    cipher: Pbes2Cipher = .aes256_cbc,
    prf: Pbes2Prf = .hmac_sha256,
    /// 1 ≤ iterations ≤ `max_pbkdf2_iterations`. OpenSSL's default is 2048;
    /// raise it for keys at rest where the password is the only protection.
    iterations: u32 = 2048,
    /// 1 ≤ salt_len ≤ `max_pbes2_salt_len`.
    salt_len: u8 = 16,
};

/// Largest `EncryptedPrivateKeyInfo` DER `toPkcs8Encrypted` writes: the
/// padded PKCS#8 plus at most ~140 bytes of algorithm parameters.
pub const max_encrypted_pkcs8_der_len = 4 + 4 + 160 + max_pkcs8_der_len + aescbc.block_len;
pub const max_encrypted_pem_len = pemLen("ENCRYPTED PRIVATE KEY".len, max_encrypted_pkcs8_der_len);

pub const EncryptError = MarshalError || error{InvalidOptions};

fn writeEncrypted(w: *RevWriter, sk: *const SecretKey, password: []const u8, random: std.Random, opts: Pbes2Options) EncryptError!void {
    if (opts.iterations == 0 or opts.iterations > max_pbkdf2_iterations or
        opts.salt_len == 0 or opts.salt_len > max_pbes2_salt_len) return error.InvalidOptions;

    // The plaintext PKCS#8, PKCS#7-padded (RFC 8018 §6.1.1 step 4).
    var plain: [max_pkcs8_der_len + aescbc.block_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain);
    const n = (try privateDer(sk, .pkcs8, plain[0..max_pkcs8_der_len])).len;
    const pad = aescbc.block_len - n % aescbc.block_len;
    @memset(plain[n..][0..pad], @intCast(pad));
    const padded = plain[0 .. n + pad];

    var salt_buf: [max_pbes2_salt_len]u8 = undefined;
    const salt = salt_buf[0..opts.salt_len];
    random.bytes(salt);
    var iv: [aescbc.block_len]u8 = undefined;
    random.bytes(&iv);
    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    switch (opts.prf) {
        inline else => |p| std.crypto.pwhash.pbkdf2(key[0..opts.cipher.keyLen()], password, salt, opts.iterations, p.Type()) catch unreachable, // rounds ≥ 1, dk ≤ 32
    }

    const mark = w.len();
    // encryptedData OCTET STRING, encrypted straight into place.
    if (padded.len > w.pos) return error.BufferTooSmall;
    w.pos -= padded.len;
    switch (opts.cipher) {
        inline else => |c| {
            const A = c.Aes();
            _ = aescbc.encrypt(A, key[0 .. A.key_bits / 8], iv, padded, w.buf[w.pos..][0..padded.len]) catch unreachable; // aligned, sized
        },
    }
    try w.header(0x04, padded.len);

    // encryptionAlgorithm { pbes2, PBES2-params { keyDerivationFunc, encryptionScheme } }
    const alg_mark = w.len();
    const es_mark = w.len();
    try w.bytes(&iv);
    try w.header(0x04, iv.len);
    try w.byte(opts.cipher.oidLast());
    try w.bytes(&oid_aes_arc);
    try w.header(0x06, oid_aes_arc.len + 1);
    try w.close(0x30, es_mark);

    const kdf_mark = w.len();
    const kp_mark = w.len();
    if (opts.prf != .hmac_sha1) { // DER omits a DEFAULT value (hmacWithSHA1)
        const prf_mark = w.len();
        try w.bytes(&.{ 0x05, 0x00 });
        try w.byte(opts.prf.oidLast());
        try w.bytes(&oid_hmac_arc);
        try w.header(0x06, oid_hmac_arc.len + 1);
        try w.close(0x30, prf_mark);
    }
    try w.integerU32(opts.iterations);
    try w.bytes(salt);
    try w.header(0x04, salt.len);
    try w.close(0x30, kp_mark);
    try w.bytes(&oid_pbkdf2);
    try w.header(0x06, oid_pbkdf2.len);
    try w.close(0x30, kdf_mark);
    try w.close(0x30, alg_mark); // PBES2-params
    try w.bytes(&oid_pbes2);
    try w.header(0x06, oid_pbes2.len);
    try w.close(0x30, alg_mark); // AlgorithmIdentifier
    try w.close(0x30, mark);
}

pub fn encryptedDer(sk: *const SecretKey, password: []const u8, random: std.Random, opts: Pbes2Options, out: []u8) EncryptError![]u8 {
    var w = RevWriter.init(out);
    writeEncrypted(&w, sk, password, random, opts) catch |err| {
        std.crypto.secureZero(u8, out);
        return err;
    };
    return w.finish();
}

pub fn encryptedPem(sk: *const SecretKey, password: []const u8, random: std.Random, opts: Pbes2Options, out: []u8) EncryptError![]u8 {
    var w = RevWriter.init(out);
    writeEncrypted(&w, sk, password, random, opts) catch |err| {
        std.crypto.secureZero(u8, out);
        return err;
    };
    return pemFromTail(out, w.len(), "ENCRYPTED PRIVATE KEY");
}
