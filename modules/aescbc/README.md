# aescbc

AES-CBC mode (NIST SP800-38A) over `std.crypto.core.aes`'s
`Aes128`/`Aes256` (and the `aes192` module's `Aes192`): one-shot, incremental
(Go's `BlockMode` shape), streaming with padding (OpenSSL's Update/Final
shape) and ciphertext stealing (CS1/CS2/CS3), plus PKCS#7, ANSI X9.23,
ISO 10126, ISO/IEC 7816-4, zero and XML-Encryption padding. `std`
ships the AES block cipher but no CBC mode; this is the one place CBC gets
implemented in this repo; `xmlenc`, `jwe` and `megolm` build on it (the first
two used to hand-roll their own CBC loop). See `SPEC.md` for the full design,
the padding-oracle caveat, and how AES-192 is passed in.

- **Status:** `extract`. Zero dependencies.
- **Model after:** NIST SP800-38A §6.2 (CBC mode); RFC 5652 §6.3 (PKCS#7
  padding); W3C XML-Encryption Syntax and Processing 1.1 §5.2 (xmlenc
  padding).

Provenance: clean-room from NIST SP800-38A §6.2 and its 2010 Addendum (CTS),
RFC 5652 §6.3 (PKCS#7), W3C XML-Encryption 1.1 §5.2, ANSI X9.23, ISO/IEC
7816-4 and RFC 3962 (CTS test vectors) — all public specs; the AES block cipher itself is
`std.crypto.core.aes`. No third-party source ported or studied, so no `NOTICE`
entry is required (root [`NOTICE`](../../NOTICE) §0).

## Usage

```zig
const aescbc = @import("aescbc");
const Aes256 = std.crypto.core.aes.Aes256;

// Raw CBC (block-aligned input only) — the primitive.
var ct: [32]u8 = undefined;
_ = try aescbc.encrypt(Aes256, &key, iv, plaintext_32_bytes, &ct);
var pt: [32]u8 = undefined;
_ = try aescbc.decrypt(Aes256, &key, iv, &ct, &pt);

// PKCS#7 (RFC 5652 §6.3) — what jwe's AxxxCBC-HSxxx uses.
var padded: [64]u8 = undefined;
const padded_len = try aescbc.padPkcs7(msg, &padded);
// ... encrypt padded[0..padded_len] ...
// ... decrypt into `out` ...
const n = try aescbc.unpadPkcs7(out[0..padded_len]);

// XML-Encryption padding (W3C xmlenc-core-1 §5.2) — what xmlenc's CBC
// content decryption uses. Only the final byte is meaningful; unlike
// PKCS#7, the preceding pad bytes are not validated (the scheme doesn't
// define them).
const n2 = try aescbc.unpadXmlEnc(decrypted[0..len]);
```

Many messages under one key, or a body that arrives in pieces:

```zig
// Block-aligned pieces, chain carried across calls (Go CryptBlocks / SetIV).
var e = aescbc.Encryptor(Aes256).init(&key, iv);
_ = try e.update(first_blocks, out1);
_ = try e.update(more_blocks, out2);
e.setIv(next_iv); // next message, same key schedule

// Any piece length, PKCS#7 applied at the end (OpenSSL Update/Final).
var s = aescbc.StreamEncryptor(Aes256, .pkcs7).init(&key, iv);
var w = try s.update(chunk, out[0..s.maxUpdateLen(chunk.len)]);
w += try s.finish(out[w..]); // needs block_len octets of room

// Ciphertext stealing: no padding, ciphertext as long as the plaintext (>= 16).
_ = try aescbc.encryptCts(Aes256, .cs3, &key, iv, msg, ct);
```

None of it allocates — caller supplies `out`. The cipher is a
`comptime` type parameter: `std.crypto.core.aes.Aes128`/`Aes256`, or for
AES-192 (which std 0.16 lacks) the `aes192` module's `Aes192`.

**Padding-oracle warning:** never call `decrypt` + an unpad helper directly
against attacker-controlled ciphertext without an authentication step (a MAC
verified *before* decrypting, or a signature check on the plaintext
afterward) — see `SPEC.md` for why and how `jwe`/`xmlenc` each compose this
safely.

## Tests

```
zig build test-aescbc
zig build test-aescbc -Doptimize=ReleaseFast
```

NIST SP800-38A F.2.1/F.2.3/F.2.5 (AES-128/192/256-CBC) byte-exact, both
directions, one-shot and block by block; RFC 3962 (CS3) and OpenSSL (CS1) CTS
vectors; deterministic fuzz harnesses (`AESCBC_FUZZ`) for CBC against a
scalar reference, every padding, CTS against a model and streaming in random
pieces; PKCS#7 and XML-Enc pad/unpad round-trips and malformed-padding
rejection with positive controls; edge cases (empty message, undersized
buffer, non-block-aligned input).

Benchmark against Go's `crypto/cipher` and OpenSSL (needs `go` and
`libcrypto.so.3`): `zig build bench-aescbc`.
