// SPDX-License-Identifier: MIT

//! PKCS#8 `EncryptedPrivateKeyInfo` (RFC 5958 §3) under PBES2 (RFC 8018):
//! the structure behind PEM `ENCRYPTED PRIVATE KEY`.
//!
//! Key derivation: PBKDF2 (RFC 8018 A.2) with HMAC-SHA-1/224/256/384/512, or
//! scrypt (RFC 7914 §7). Cipher: AES-128/192/256-CBC with PKCS#7 padding (RFC
//! 8018 B.2.5). That is everything `openssl pkcs8 -topk8` writes that
//! RustCrypto's `pkcs8` also reads; SPEC § Encrypted keys lists what is
//! refused and why.
//!
//! This file knows bytes only: the structure, the key derivation and the
//! cipher. The step to a `PrivateKey` (`parseEncryptedPkcs8`,
//! `encryptPkcs8`, the PEM entry points) is in `root.zig`.
//!
//! No allocation. scrypt needs memory proportional to N * r: the caller
//! supplies it (`DecryptOptions.scrypt_work`); a file asking for more than
//! that buffer holds is `KdfParamsTooLarge`, so the buffer is also the memory
//! cap. A wrong password and a damaged ciphertext are one error
//! (`IncorrectPasswordOrCorrupt`): CBC has no MAC, and telling "bad padding"
//! from "padding fine, DER nonsense" would be a padding oracle.

const std = @import("std");
const der = @import("der.zig");
const burn = @import("burn.zig");
const aescbc = @import("aescbc");
const Aes192 = @import("aes192").Aes192;

const pwhash = std.crypto.pwhash;

// ── OIDs ────────────────────────────────────────────────────────────────────

/// 1.2.840.113549.1.5.13 PBES2, .12 PBKDF2 (RFC 8018 A.4, A.2).
pub const oid_pbes2 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d };
pub const oid_pbkdf2 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c };
/// 1.3.6.1.4.1.11591.4.11 id-scrypt (RFC 7914 §7).
pub const oid_scrypt = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x04, 0x0b };
/// 1.2.840.113549.2.x -- hmacWithSHA1 (7) ... hmacWithSHA512 (11).
const oid_hmac_arc = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02 };
/// 2.16.840.1.101.3.4.1.x -- aes128-CBC (2), aes192-CBC (22), aes256-CBC (42).
const oid_aes_arc = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01 };

// ── algorithms ──────────────────────────────────────────────────────────────

/// The PBKDF2 pseudo-random function (`PBKDF2-params.prf`).
pub const Prf = enum {
    hmac_sha1,
    hmac_sha224,
    hmac_sha256,
    hmac_sha384,
    hmac_sha512,

    pub fn Type(comptime prf: Prf) type {
        const h = std.crypto.auth.hmac;
        return switch (prf) {
            .hmac_sha1 => h.HmacSha1,
            .hmac_sha224 => h.sha2.HmacSha224,
            .hmac_sha256 => h.sha2.HmacSha256,
            .hmac_sha384 => h.sha2.HmacSha384,
            .hmac_sha512 => h.sha2.HmacSha512,
        };
    }

    fn oidLast(prf: Prf) u8 {
        return 7 + @as(u8, @backingInt(prf));
    }

    fn fromOidLast(b: u8) ?Prf {
        if (b < 7 or b > 11) return null;
        return @fromBackingInt(@intCast(b - 7));
    }
};

/// The PBES2 encryption scheme: AES-CBC, PKCS#7 padding.
pub const Cipher = enum {
    aes128_cbc,
    aes192_cbc,
    aes256_cbc,

    pub fn Aes(comptime c: Cipher) type {
        const aes = std.crypto.core.aes;
        return switch (c) {
            .aes128_cbc => aes.Aes128,
            .aes192_cbc => Aes192,
            .aes256_cbc => aes.Aes256,
        };
    }

    pub fn keyLen(c: Cipher) usize {
        return switch (c) {
            .aes128_cbc => 16,
            .aes192_cbc => 24,
            .aes256_cbc => 32,
        };
    }

    fn oidLast(c: Cipher) u8 {
        return switch (c) {
            .aes128_cbc => 0x02,
            .aes192_cbc => 0x16,
            .aes256_cbc => 0x2a,
        };
    }

    fn fromOidLast(b: u8) ?Cipher {
        return switch (b) {
            0x02 => .aes128_cbc,
            0x16 => .aes192_cbc,
            0x2a => .aes256_cbc,
            else => null,
        };
    }
};

pub const Pbkdf2Params = struct {
    prf: Prf = .hmac_sha256,
    /// Written: 1 ..= `max_written_pbkdf2_iterations`. Read: saturated at
    /// `maxInt(u64)` when the file names more.
    iterations: u64 = 2048,
};

pub const ScryptParams = struct {
    /// N = 2^log2_n (RFC 7914: N is a power of two above one).
    log2_n: u6 = 14,
    r: u32 = 8,
    p: u32 = 1,

    pub fn cost(s: ScryptParams) u128 {
        return (@as(u128, 1) << s.log2_n) * s.r * s.p;
    }

    /// Bytes of `scrypt_work` this parameter set needs.
    pub fn workLen(s: ScryptParams) u128 {
        const r: u128 = s.r;
        return 256 * r + (@as(u128, 128) << s.log2_n) * r + 128 * @as(u128, s.p) * r + work_slack;
    }
};

/// std's scrypt takes 16-aligned blocks from the allocator; the slack pays for
/// the alignment of a caller buffer that is not.
const work_slack = 32;

/// `scrypt_work` size for the parameters: what the caller must supply.
/// `maxInt(usize)` when no buffer could hold it.
pub fn scryptWorkLen(p: ScryptParams) usize {
    const n = p.workLen();
    return if (n > std.math.maxInt(usize)) std.math.maxInt(usize) else @intCast(n);
}

pub const Kdf = union(enum) {
    pbkdf2: Pbkdf2Params,
    scrypt: ScryptParams,
};

// ── limits ──────────────────────────────────────────────────────────────────

/// Default cap on PBKDF2 iterations read: 2^20, ~0.3 s of HMAC-SHA-256 on a
/// desktop core -- 512 times OpenSSL's default of 2048 and above OWASP's
/// 600 000 for SHA-256. OpenSSL itself accepts up to 2^31 - 1 and RustCrypto
/// has no cap, so an untrusted key file can burn minutes of CPU there;
/// `DecryptOptions.max_pbkdf2_iterations` raises it.
pub const default_max_pbkdf2_iterations: u32 = 1 << 20;

/// Default cap on scrypt's N * r * p (the work, as RFC 7914 counts it): 2^23,
/// which is N = 2^20, r = 8, p = 1 (Colin Percival's "sensitive" setting, 1 GiB
/// of memory, a few seconds). OpenSSL's default `maxmem` (32 MiB) is a memory
/// cap only; here the memory cap is the caller's `scrypt_work` buffer and the
/// time cap is this.
pub const default_max_scrypt_cost: u64 = 1 << 23;

/// The longest salt read (a salt only feeds a hash once; this bounds the DER
/// walk, not the CPU) and the longest written (OpenSSL writes 16).
pub const max_read_salt_len = 1024;
pub const max_write_salt_len = 64;

/// Upper bounds on what `encrypt` writes, mirroring the defaults above.
pub const max_written_pbkdf2_iterations: u64 = default_max_pbkdf2_iterations;

/// Octets the encryption algorithm and framing add to the padded ciphertext,
/// worst case (scrypt, 64-byte salt, 8-byte N): generous.
pub const max_overhead = 256;

// ── errors ──────────────────────────────────────────────────────────────────

pub const InfoError = error{
    /// Not a well-formed EncryptedPrivateKeyInfo / PBES2 structure.
    MalformedKey,
    /// Well-formed, but not PBES2 with PBKDF2 or scrypt and AES-CBC: PBES1,
    /// DES / 3DES / RC2, AES-GCM, Camellia, ARIA, a PRF outside HMAC-SHA-1/224/
    /// 256/384/512, or scrypt with no `scrypt_work`.
    UnsupportedEncryption,
};

pub const DecryptError = InfoError || error{
    /// The key derivation asks for more than the limits in `DecryptOptions`
    /// allow (iterations, scrypt cost, scrypt memory).
    KdfParamsTooLarge,
    /// A wrong password, a damaged ciphertext, or plaintext that is not a
    /// PKCS#8 `PrivateKeyInfo`: indistinguishable by design.
    IncorrectPasswordOrCorrupt,
    /// `out` is shorter than the ciphertext.
    NoSpaceLeft,
};

pub const EncryptError = error{
    /// An option outside its documented range.
    InvalidOptions,
    /// The key does not fit its algorithm or encoding (`writePkcs8`'s verdict).
    MalformedKey,
    NoSpaceLeft,
};

// ── the structure ───────────────────────────────────────────────────────────

/// A parsed EncryptedPrivateKeyInfo: every field a slice of the input.
pub const Info = struct {
    kdf: Kdf,
    salt: []const u8,
    cipher: Cipher,
    iv: *const [aescbc.block_len]u8,
    /// The encrypted PrivateKeyInfo: a non-empty multiple of 16 octets.
    ciphertext: []const u8,
};

/// The EncryptedPrivateKeyInfo structure, all of it public data:
///   SEQUENCE { SEQUENCE { pbes2, SEQUENCE {
///       SEQUENCE { pbkdf2, SEQUENCE { salt OCTET STRING, iterationCount,
///                                     keyLength OPTIONAL, prf DEFAULT sha1 } }
///              | { scrypt, SEQUENCE { salt, N, r, p, keyLength OPTIONAL } },
///       SEQUENCE { aes-CBC OID, iv OCTET STRING(16) } } },
///     encryptedData OCTET STRING }
/// Checked as the RFCs require; no limit on iteration counts or scrypt cost
/// here (`decrypt` applies those), values wider than 64 bits saturate.
pub fn parse(bytes: []const u8) InfoError!Info {
    var top = der.Reader.init(bytes);
    var epki = try top.sub(0x30);
    try top.end();
    var alg = try epki.sub(0x30);
    const data = try epki.expect(0x04);
    try epki.end();

    const alg_oid = try alg.expect(0x06);
    if (!std.mem.eql(u8, alg_oid, &oid_pbes2)) return error.UnsupportedEncryption; // PBES1, PKCS#12 PBEs, ...
    var params = try alg.sub(0x30);
    try alg.end();
    var kdf_seq = try params.sub(0x30);
    var enc_seq = try params.sub(0x30);
    try params.end();

    var key_len: ?u64 = null;
    const kdf_oid = try kdf_seq.expect(0x06);
    var kp = try kdf_seq.sub(0x30);
    try kdf_seq.end();
    const salt_tag = kp.peekTag() orelse return error.MalformedKey;
    // `otherSource` (a salt from an AlgorithmIdentifier) is not defined by any
    // RFC 8018 profile in use.
    if (salt_tag == 0x30) return error.UnsupportedEncryption;
    const salt = try kp.expect(0x04);
    var kdf: Kdf = undefined;
    if (std.mem.eql(u8, kdf_oid, &oid_pbkdf2)) {
        const iterations = try uint(try kp.expect(0x02));
        if (kp.peekTag() == 0x02) key_len = try uint(try kp.expect(0x02));
        var prf: Prf = .hmac_sha1; // DEFAULT algid-hmacWithSHA1
        if (!kp.atEnd()) {
            var p = try kp.sub(0x30);
            const p_oid = try p.expect(0x06);
            prf = if (p_oid.len == oid_hmac_arc.len + 1 and std.mem.eql(u8, p_oid[0..oid_hmac_arc.len], &oid_hmac_arc))
                Prf.fromOidLast(p_oid[oid_hmac_arc.len]) orelse return error.UnsupportedEncryption
            else
                return error.UnsupportedEncryption;
            if (!p.atEnd()) { // parameters: NULL (RFC 8018 B.1.1), or absent
                if ((try p.expect(0x05)).len != 0) return error.MalformedKey;
                try p.end();
            }
        }
        try kp.end();
        if (iterations == 0) return error.MalformedKey;
        kdf = .{ .pbkdf2 = .{ .prf = prf, .iterations = iterations } };
    } else if (std.mem.eql(u8, kdf_oid, &oid_scrypt)) {
        const n = try uint(try kp.expect(0x02));
        const r = try uint(try kp.expect(0x02));
        const p = try uint(try kp.expect(0x02));
        if (kp.peekTag() == 0x02) key_len = try uint(try kp.expect(0x02));
        try kp.end();
        // RFC 7914 §6: N > 1, a power of two; r and p positive. A value
        // beyond 32 bits is far past any limit: reported as such by `decrypt`.
        if (n < 2 or !std.math.isPowerOfTwo(n) or r == 0 or p == 0) return error.MalformedKey;
        kdf = .{ .scrypt = .{
            .log2_n = @intCast(@ctz(n)),
            .r = @intCast(@min(r, std.math.maxInt(u32))),
            .p = @intCast(@min(p, std.math.maxInt(u32))),
        } };
    } else return error.UnsupportedEncryption;

    const enc_oid = try enc_seq.expect(0x06);
    if (enc_oid.len != oid_aes_arc.len + 1 or !std.mem.eql(u8, enc_oid[0..oid_aes_arc.len], &oid_aes_arc)) return error.UnsupportedEncryption;
    const cipher = Cipher.fromOidLast(enc_oid[oid_aes_arc.len]) orelse return error.UnsupportedEncryption;
    const iv = try enc_seq.expect(0x04);
    try enc_seq.end();
    if (iv.len != aescbc.block_len) return error.MalformedKey;
    if (key_len) |kl| if (kl != cipher.keyLen()) return error.MalformedKey;
    if (salt.len == 0 or salt.len > max_read_salt_len) return error.MalformedKey;
    if (data.len == 0 or data.len % aescbc.block_len != 0) return error.MalformedKey;
    return .{ .kdf = kdf, .salt = salt, .cipher = cipher, .iv = iv[0..aescbc.block_len], .ciphertext = data };
}

/// A non-negative, minimal DER INTEGER as a u64, saturating when wider.
fn uint(b: []const u8) InfoError!u64 {
    if (b.len == 0 or b[0] & 0x80 != 0) return error.MalformedKey; // empty or negative
    if (b.len > 1 and b[0] == 0 and b[1] & 0x80 == 0) return error.MalformedKey; // not minimal
    const s = if (b[0] == 0) b[1..] else b;
    if (s.len > 8) return std.math.maxInt(u64);
    var v: u64 = 0;
    for (s) |x| v = v << 8 | x;
    return v;
}

// ── key derivation ──────────────────────────────────────────────────────────

pub const DecryptOptions = struct {
    /// Refuse (`KdfParamsTooLarge`) a PBKDF2 file naming more iterations.
    max_pbkdf2_iterations: u32 = default_max_pbkdf2_iterations,
    /// Refuse a scrypt file whose N * r * p is larger.
    max_scrypt_cost: u64 = default_max_scrypt_cost,
    /// Memory for scrypt (`scryptWorkLen` of the file's parameters), wiped
    /// before `decrypt` returns. Empty: scrypt files are
    /// `UnsupportedEncryption`; too small for a file's parameters:
    /// `KdfParamsTooLarge`.
    scrypt_work: []u8 = &.{},
};

/// Derive the cipher key into `key[0..cipher.keyLen()]`.
fn derive(key: *[32]u8, info: Info, password: []const u8, opts: DecryptOptions) DecryptError!void {
    const dk = key[0..info.cipher.keyLen()];
    switch (info.kdf) {
        .pbkdf2 => |k| {
            if (k.iterations > opts.max_pbkdf2_iterations) return error.KdfParamsTooLarge;
            switch (k.prf) {
                inline else => |p| pwhash.pbkdf2(dk, password, info.salt, @intCast(k.iterations), p.Type()) catch return error.MalformedKey, // rounds >= 1, dk <= 32
            }
        },
        .scrypt => |s| {
            if (opts.scrypt_work.len == 0) return error.UnsupportedEncryption;
            if (s.cost() > opts.max_scrypt_cost) return error.KdfParamsTooLarge;
            const need = s.workLen();
            if (need > opts.scrypt_work.len or s.r > std.math.maxInt(u30) or s.p > std.math.maxInt(u30)) return error.KdfParamsTooLarge;
            const used = opts.scrypt_work[0..@intCast(need)];
            defer std.crypto.secureZero(u8, used);
            var fba = std.heap.FixedBufferAllocator.init(used);
            pwhash.scrypt.kdf(fba.allocator(), dk, password, info.salt, .{
                .ln = s.log2_n,
                .r = @intCast(s.r),
                .p = @intCast(s.p),
            }) catch |err| return switch (err) {
                error.OutOfMemory => error.KdfParamsTooLarge,
                else => error.MalformedKey,
            };
        },
    }
}

fn overlapsOtherThanAtStart(a: []const u8, b: []const u8) bool {
    const a0 = @intFromPtr(a.ptr);
    const b0 = @intFromPtr(b.ptr);
    if (a0 == b0) return false;
    return a0 < b0 + b.len and b0 < a0 + a.len;
}

/// Decrypt `info.ciphertext` into `out` and return the plaintext (a PKCS#8
/// `PrivateKeyInfo` for a key file) as `out[0..n]`. `out` is at least
/// `info.ciphertext.len` long and either separate from the ciphertext or
/// starts exactly at it (in-place); a partial overlap is `NoSpaceLeft`.
/// Everything past the plaintext that `out` was written with is wiped, on
/// success and on every error; so are the derived key and `scrypt_work`.
/// Padding: PKCS#7, checked in constant time; a wrong password and a bad
/// padding are the same error.
/// The call runs one frame down and the stack it dirtied (PBKDF2/scrypt and HMAC
/// state, AES round keys) is zeroed after it (`burn.pbes2_burn`): `pbes2` is public, so
/// this is an entry point of its own.
pub fn decrypt(info: Info, password: []const u8, out: []u8, opts: DecryptOptions) DecryptError![]u8 {
    return burn.run(burn.pbes2_burn, DecryptError![]u8, decryptBody, .{ info, password, out, opts });
}

fn decryptBody(info: Info, password: []const u8, out: []u8, opts: DecryptOptions) DecryptError![]u8 {
    if (out.len < info.ciphertext.len or overlapsOtherThanAtStart(out[0..info.ciphertext.len], info.ciphertext)) return error.NoSpaceLeft;
    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    try derive(&key, info, password, opts);

    const pt = out[0..info.ciphertext.len];
    switch (info.cipher) {
        inline else => |c| {
            const A = c.Aes();
            _ = aescbc.decrypt(A, key[0 .. A.key_bits / 8], info.iv.*, info.ciphertext, pt) catch {
                std.crypto.secureZero(u8, pt);
                return error.MalformedKey; // aligned and sized above
            };
        },
    }
    const n = aescbc.unpadPkcs7(pt) catch {
        std.crypto.secureZero(u8, pt);
        return error.IncorrectPasswordOrCorrupt;
    };
    std.crypto.secureZero(u8, pt[n..]);
    return pt[0..n];
}

// ── encryption ──────────────────────────────────────────────────────────────

/// What `openssl pkcs8 -topk8` writes by default (OpenSSL 3.5.5): PBKDF2 with
/// HMAC-SHA-256 and 2048 iterations, a 16-byte salt, AES-256-CBC.
pub const EncryptOptions = struct {
    cipher: Cipher = .aes256_cbc,
    kdf: Kdf = .{ .pbkdf2 = .{} },
    /// 1 ..= `max_write_salt_len`.
    salt_len: u8 = 16,
    /// scrypt only: `scryptWorkLen` of the parameters.
    scrypt_work: []u8 = &.{},
};

fn uintLen(v: u64) usize {
    var n: usize = 1;
    var x = v >> 8;
    while (x != 0) : (x >>= 8) n += 1;
    if ((v >> @intCast(8 * (n - 1))) & 0x80 != 0) n += 1; // leading zero keeps it positive
    return n;
}

fn writeUint(w: *der.Writer, v: u64) void {
    const n = uintLen(v);
    w.header(0x02, n);
    var i = n;
    while (i > 0) {
        i -= 1;
        w.byte(if (i >= 8) 0 else @truncate(v >> @intCast(8 * i)));
    }
}

fn uintTlvLen(v: u64) usize {
    return der.tlvLen(uintLen(v));
}

/// Length of the PBKDF2 / scrypt `SEQUENCE` parameter's content.
fn kdfParamsLen(kdf: Kdf, salt_len: usize) usize {
    const salt = der.tlvLen(salt_len);
    return switch (kdf) {
        .pbkdf2 => |k| salt + uintTlvLen(k.iterations) + if (k.prf == .hmac_sha1)
            0 // DER omits a DEFAULT value
        else
            der.tlvLen(der.tlvLen(oid_hmac_arc.len + 1) + der.tlvLen(0)),
        .scrypt => |s| salt + uintTlvLen(@as(u64, 1) << s.log2_n) + uintTlvLen(s.r) + uintTlvLen(s.p),
    };
}

fn validate(opts: EncryptOptions) EncryptError!void {
    if (opts.salt_len == 0 or opts.salt_len > max_write_salt_len) return error.InvalidOptions;
    switch (opts.kdf) {
        .pbkdf2 => |k| if (k.iterations == 0 or k.iterations > max_written_pbkdf2_iterations) return error.InvalidOptions,
        .scrypt => |s| {
            if (s.log2_n == 0 or s.r == 0 or s.p == 0) return error.InvalidOptions;
            if (s.r > std.math.maxInt(u30) or s.p > std.math.maxInt(u30)) return error.InvalidOptions;
            if (s.cost() > default_max_scrypt_cost) return error.InvalidOptions;
            if (s.workLen() > opts.scrypt_work.len) return error.InvalidOptions;
        },
    }
}

/// The lengths of the nested SEQUENCEs `encrypt` writes.
const Layout = struct {
    kdf_oid: []const u8,
    kp: usize,
    kdf: usize,
    enc: usize,
    params: usize,
    alg: usize,
    padded: usize,
    total: usize,

    fn of(plain_len: usize, opts: EncryptOptions) Layout {
        var l: Layout = undefined;
        l.kdf_oid = switch (opts.kdf) {
            .pbkdf2 => &oid_pbkdf2,
            .scrypt => &oid_scrypt,
        };
        l.kp = kdfParamsLen(opts.kdf, opts.salt_len);
        l.kdf = der.tlvLen(l.kdf_oid.len) + der.tlvLen(l.kp);
        l.enc = der.tlvLen(oid_aes_arc.len + 1) + der.tlvLen(aescbc.block_len);
        l.params = der.tlvLen(l.kdf) + der.tlvLen(l.enc);
        l.alg = der.tlvLen(oid_pbes2.len) + der.tlvLen(l.params);
        l.padded = aescbc.paddedLenPkcs7(plain_len);
        l.total = der.tlvLen(der.tlvLen(l.alg) + der.tlvLen(l.padded));
        return l;
    }
};

/// Bytes `encrypt` writes for a PKCS#8 of `plain_len` octets.
pub fn encryptedLen(plain_len: usize, opts: EncryptOptions) usize {
    return Layout.of(plain_len, opts).total;
}

/// Encrypt the PKCS#8 `PrivateKeyInfo` at `stage[0..plain_len]` and write the
/// EncryptedPrivateKeyInfo DER to `out`. `stage` is the caller's secret
/// buffer, at least `plain_len + 16` long: it is padded in place and holds
/// the padded plaintext on return -- the caller wipes it. Salt and IV come
/// from `random`. `out` is wiped on every error.
/// Burned like `decrypt` (`burn.pbes2_burn`).
pub fn encrypt(out: []u8, stage: []u8, plain_len: usize, password: []const u8, random: std.Random, opts: EncryptOptions) EncryptError![]u8 {
    return burn.run(burn.pbes2_burn, EncryptError![]u8, encryptBody, .{ out, stage, plain_len, password, random, opts });
}

fn encryptBody(out: []u8, stage: []u8, plain_len: usize, password: []const u8, random: std.Random, opts: EncryptOptions) EncryptError![]u8 {
    errdefer std.crypto.secureZero(u8, out);
    try validate(opts);
    const padded_len = aescbc.paddedLenPkcs7(plain_len);
    if (stage.len < padded_len) return error.NoSpaceLeft;
    _ = aescbc.padPkcs7(stage[0..plain_len], stage) catch return error.NoSpaceLeft;
    const padded = stage[0..padded_len];

    var salt_buf: [max_write_salt_len]u8 = undefined;
    const salt = salt_buf[0..opts.salt_len];
    random.bytes(salt);
    var iv: [aescbc.block_len]u8 = undefined;
    random.bytes(&iv);

    const info: Info = .{ .kdf = opts.kdf, .salt = salt, .cipher = opts.cipher, .iv = &iv, .ciphertext = padded };
    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    derive(&key, info, password, .{
        .max_pbkdf2_iterations = default_max_pbkdf2_iterations,
        .max_scrypt_cost = default_max_scrypt_cost,
        .scrypt_work = opts.scrypt_work,
    }) catch return error.InvalidOptions; // `validate` passed: not reachable for a sound `opts`

    // Framing, then the ciphertext straight into place.
    const l = Layout.of(plain_len, opts);
    const total = l.total;
    if (out.len < total) return error.NoSpaceLeft;

    var w = der.Writer.init(out[0..total]);
    w.header(0x30, der.tlvLen(l.alg) + der.tlvLen(l.padded));
    w.header(0x30, l.alg);
    w.tlv(0x06, &oid_pbes2);
    w.header(0x30, l.params);
    w.header(0x30, l.kdf);
    w.tlv(0x06, l.kdf_oid);
    w.header(0x30, l.kp);
    w.tlv(0x04, salt);
    switch (opts.kdf) {
        .pbkdf2 => |k| {
            writeUint(&w, k.iterations);
            if (k.prf != .hmac_sha1) {
                w.header(0x30, der.tlvLen(oid_hmac_arc.len + 1) + der.tlvLen(0));
                w.header(0x06, oid_hmac_arc.len + 1);
                w.bytes(&oid_hmac_arc);
                w.byte(k.prf.oidLast());
                w.tlv(0x05, &.{});
            }
        },
        .scrypt => |s| {
            writeUint(&w, @as(u64, 1) << s.log2_n);
            writeUint(&w, s.r);
            writeUint(&w, s.p);
        },
    }
    w.header(0x30, l.enc);
    w.header(0x06, oid_aes_arc.len + 1);
    w.bytes(&oid_aes_arc);
    w.byte(opts.cipher.oidLast());
    w.tlv(0x04, &iv);
    w.header(0x04, l.padded);
    const head = w.finish() catch return error.NoSpaceLeft;
    std.debug.assert(head.len + l.padded == total);

    const ct = out[head.len..total];
    switch (opts.cipher) {
        inline else => |c| {
            const A = c.Aes();
            _ = aescbc.encrypt(A, key[0 .. A.key_bits / 8], iv, padded, ct) catch return error.NoSpaceLeft; // aligned, sized
        },
    }
    return out[0..total];
}
