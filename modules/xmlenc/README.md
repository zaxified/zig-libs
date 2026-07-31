# xmlenc

W3C XML-Encryption (xmlenc-core-1) **decryption** — recover the plaintext
`<saml:Assertion>` from a `<saml:EncryptedAssertion>` / `<xenc:EncryptedData>`
so the SAML SP can run signature verification and XSW defense on it. eIDAS
requires encrypted assertions; this closes the SAML cluster's last gap.

Decryption only (we are the relying party with the private key). Encryption,
`CipherReference` (external ciphertext URI), and ciphertext `Transforms` are out
of scope and rejected. See `SPEC.md` for the full algorithm allow-list and
security posture.

Provenance: clean-room from W3C *XML Encryption* 1.1 (xmlenc-core-1) plus
RFC 8017 (RSA-OAEP), RFC 3394 (AES key wrap) and NIST SP800-38A/D — all public
specifications. No third-party XML-Enc implementation was consulted, so no
`NOTICE` entry is required (root [`NOTICE`](../../NOTICE) §0).

## Supported algorithms

- **Key transport:** `rsa-oaep-mgf1p` (SHA-1), xenc11 `rsa-oaep` (SHA-1/SHA-256,
  MGF matching the digest), and — gated behind `allow_weak_rsa15` —
  `rsa-1_5`. Optional `kw-aes128`/`kw-aes256` symmetric key wrap (RFC 3394) when
  a KEK is supplied.
- **Content:** `aes128-cbc`, `aes256-cbc`, `aes128-gcm`, `aes256-gcm`. AES-192
  is `UnsupportedAlgorithm` (std 0.16 has no AES-192 block cipher). GCM and OAEP
  are the safe, preferred paths.

Anything off the list → `error.UnsupportedAlgorithm`.

## Usage

```zig
const xmlenc = @import("xmlenc");

// `enc_assertion` is the parsed <saml:EncryptedAssertion> element;
// `sk` is your rsa.SecretKey.
const plaintext = try xmlenc.decryptAssertion(alloc, enc_assertion, sk, .{});
defer alloc.free(plaintext);
// `plaintext` is the serialized <saml:Assertion> — re-parse + verify it.

// Or, given a bare <xenc:EncryptedData>:
const pt = try xmlenc.decryptData(alloc, encrypted_data, sk, .{});

// Options:
//   .allow_weak_rsa15 = true   // opt in to Bleichenbacher-vulnerable rsa-1_5
//   .kek = some_kek            // symmetric KEK for kw-aes128/256
//   .max_ciphertext_len = N    // DoS bound on decoded content (default 4 MiB)
```

`decryptDataToDocument` is a convenience that parses the recovered octets and
returns an owned `xml.Document`.

## Security

Decrypts attacker-influenced ciphertext. All cryptographic failures collapse to
a single generic `error.DecryptionError` (no padding/oracle signal); `rsa-1_5`
and AES-CBC carry the documented Bleichenbacher / padding-oracle caveats; the
safe composition is **decrypt → signature-verify**. The recovered CEK is
zeroized after use. Never panics. Full detail in `SPEC.md`.

## Testing

```
zig build test-xmlenc
zig build test-xmlenc -Doptimize=ReleaseFast
```

CBC core is byte-exact against NIST SP800-38A; AES key unwrap against RFC 3394;
round-trips are locally constructed (no external SAML EncryptedAssertion fixture
was available — see SPEC.md).

## License

MIT (`SPDX-License-Identifier: MIT`).
