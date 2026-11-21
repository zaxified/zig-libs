# aesccm

AES-CCM authenticated encryption (NIST SP 800-38C, RFC 3610), generic over the
nonce length (7..13 bytes) and the tag length (4..16, even) at comptime.

Zig's std exports only 13-byte-nonce CCM presets; the TLS 1.3 / DTLS 1.3 CCM
and CCM_8 suites (RFC 8446 §B.4) need a 12-byte nonce. This module covers both.

```zig
const aesccm = @import("aesccm");

// TLS_AES_128_CCM_8_SHA256's AEAD: 16-byte key, 12-byte nonce, 8-byte tag.
var ctx = aesccm.Aes128Ccm8.init(key);
defer ctx.deinit();
var tag: [8]u8 = undefined;
try ctx.seal(ciphertext, &tag, plaintext, additional_data, nonce);
try ctx.open(plaintext_out, ciphertext, tag, additional_data, nonce); // error.AuthenticationFailed

// Any other profile:
const C = aesccm.Ccm(std.crypto.core.aes.Aes256, 16, 13);
try C.encrypt(ct, &tag16, msg, ad, nonce13, key32);
```

Presets: `Aes128Ccm`, `Aes128Ccm8`, `Aes256Ccm`, `Aes256Ccm8` (12-byte nonce),
`Aes128Ccm8Nonce13` (COSE AES-CCM-16-64-128 / OSCORE). Errors instead of
asserts: `BufferSizeMismatch`, `MessageTooLong`, `AuthenticationFailed` (the
plaintext buffer is zeroed on it).

Verified against NIST SP 800-38C Appendix C, RFC 3610's packet vectors and an
OpenSSL KAT table (`tools/ccm_kats.py`). See `SPEC.md`.

Provenance: original work of the zig-libs authors (MIT), implemented directly from RFC 3610 and NIST SP 800-38C.
