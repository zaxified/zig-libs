# aescbc

Raw AES-CBC mode (NIST SP800-38A) over `std.crypto.core.aes`'s
`Aes128`/`Aes256`, plus PKCS#7 and XML-Encryption padding helpers. `std`
ships the AES block cipher but no CBC mode; this is the one place CBC gets
implemented in this repo, so `xmlenc` and `jwe` (which each hand-rolled their
own CBC loop) can build on it instead. See `SPEC.md` for the full design,
the padding-oracle caveat, and the AES-192 exclusion.

- **Status:** `extract`. Zero dependencies.
- **Model after:** NIST SP800-38A §6.2 (CBC mode); RFC 5652 §6.3 (PKCS#7
  padding); W3C XML-Encryption Syntax and Processing 1.1 §5.2 (xmlenc
  padding).

## Usage

```zig
const aescbc = @import("aescbc");
const Aes256 = std.crypto.core.aes.Aes256;

// Raw CBC (block-aligned input only) — the primitive.
var ct: [32]u8 = undefined;
_ = try aescbc.encrypt(Aes256, key, iv, plaintext_32_bytes, &ct);
var pt: [32]u8 = undefined;
_ = try aescbc.decrypt(Aes256, key, iv, &ct, &pt);

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

`encrypt`/`decrypt` never allocate — caller supplies `out`. AES-192 is not
offered (`std.crypto.core.aes` has no AES-192 core in 0.16); passing it is a
compile error, not a runtime error, since the cipher is a `comptime` type
parameter.

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

NIST SP800-38A F.2.1 (AES-128-CBC) and F.2.5 (AES-256-CBC) byte-exact, both
directions; PKCS#7 and XML-Enc pad/unpad round-trips and malformed-padding
rejection with positive controls; edge cases (empty message, undersized
buffer, non-block-aligned input).
