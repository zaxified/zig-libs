# keycodec

The key file formats every crypto stack reads: PKCS#8 `PRIVATE KEY`, SEC1
`EC PRIVATE KEY`, PKCS#1 `RSA PRIVATE KEY` / `RSA PUBLIC KEY`, and
SubjectPublicKeyInfo `PUBLIC KEY`, with their PEM armour. One shared reader and
writer, so that `jwt`, `acme`, `tlsserver` and `mlkem` stop each carrying their
own copy.

Algorithms: EC on P-256, P-384, P-521 and secp256k1; Ed25519, Ed448, X25519,
X448 (RFC 8410); RSA and RSASSA-PSS; ML-DSA-44/65/87 (RFC 9881) and
ML-KEM-512/768/1024 (RFC 9935) in all three private-key forms (`seed`,
`expandedKey`, `both`).

**Type-agnostic.** A parsed key is its algorithm plus slices of your buffer:
the EC scalar, the Ed/X key, the PKCS#1 DER, the ML seed and expanded key, and
the public key where the format carries one. Building a key object (std's
ECDSA, `p256`, `rsa`, std's ML-DSA, ...) is the next line of your code. This
keeps the module's only dependency `b64ct`.

- **Model after:** Go `crypto/x509` (`ParsePKCS8PrivateKey`,
  `ParseECPrivateKey`, `ParsePKCS1PrivateKey`, `ParsePKIXPublicKey`,
  `Marshal*`) and `encoding/pem` (the reference); RustCrypto `pkcs8`, `sec1`,
  `spki`, `pem-rfc7468` (Rust).
- **Platform:** any (pure computation). **Role:** codec. **Concurrency:**
  reentrant. **Allocation:** none: every function works in caller buffers.

## API

```zig
const keycodec = @import("keycodec");

// Read the first private key of a PEM file (other blocks are skipped).
var der_buf: [keycodec.max_private_der_len]u8 = undefined;
defer std.crypto.secureZero(u8, &der_buf); // the key's parts point in here
const key = try keycodec.parsePrivateKeyPem(pem_text, &der_buf);
switch (key.algorithm) {
    .ec_p256 => {
        var scalar: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &scalar);
        try key.scalarInto(&scalar); // left-padded, already checked in [1, n)
        const sk = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(scalar);
        _ = sk;
    },
    .ed25519 => { const seed = key.secret[0..32]; _ = seed; },
    .rsa => try rsa.SecretKey.fromDer(&rsa_key, key.secret), // the PKCS#1 DER
    .ml_dsa_65 => { const seed = key.secret; _ = seed; }, // key.pq_form: .seed / .expanded / .both
    else => return error.UnsupportedKey,
}

// The same from DER: PKCS#8, SEC1 and PKCS#1 are told apart by structure.
const k2 = try keycodec.parsePrivateKeyDer(der);
// Or one structure explicitly.
const k3 = try keycodec.parsePkcs8(der);
const k4 = try keycodec.parseSec1(der, null); // or the curve the context names

// Public keys: SPKI or PKCS#1.
var pub_buf: [keycodec.max_public_der_len]u8 = undefined;
const pk = try keycodec.parsePublicKeyPem(pub_pem, &pub_buf);
// pk.algorithm, pk.key: EC point / raw key / RSAPublicKey DER

// Writing: fill the parts, pick the encoding. Byte-identical to openssl.
var out: [keycodec.max_private_pem_len]u8 = undefined;
const text = try keycodec.writePrivateKeyPem(&out, .{
    .algorithm = .ec_p384,
    .encoding = .pkcs8, // or .sec1
    .secret = &scalar,
    .public = &uncompressed_point, // optional
});
const spki = try keycodec.writeSpki(&spki_buf, .{ .algorithm = .ed25519, .key = &public_key });
```

`keycodec.pem` is the armour alone: `pem.Iterator` over every block,
`pem.find`, `Block.decode` (constant time), `pem.encode`.

Errors: `MalformedKey` (bad DER, a length that does not fit the algorithm, a
scalar out of range), `UnsupportedAlgorithm` (well-formed, but DSA,
brainpool, explicit EC parameters, ...), and on the PEM paths `InvalidPem`,
`MissingKey`, `EncryptedKey` (PKCS#8 PBES2 and legacy `Proc-Type`
encryption), `UnsupportedFormat` (an OpenSSH key: the `ssh` module reads
those), `NoSpaceLeft`.

## What is checked, and what is yours

Checked here: strict DER (minimal lengths, no trailing data), every version
field, the algorithm identifier and its parameters as the RFCs require them,
every length against the algorithm, an EC scalar in [1, n) (in constant time),
an EC point's SEC1 shape.

Not checked, because it needs the key's arithmetic: that an EC point is on its
curve, that a stored public key belongs to the secret, that an ML `both`
key's seed expands to its expanded half, the RSA numbers. Your key type does
that (`KeyPair.fromSecretKey` and a comparison, `rsa.SecretKey.fromDer`).

## Secrets

Parsing copies nothing: the result points into your DER buffer, and you wipe
it. `parsePrivateKeyPem` and `writePrivateKeyPem` decode and encode the base64
with `b64ct` (constant time), walk PEM blocks without a Boyer-Moore-Horspool
search over key bodies, keep the DER only in a wiped stack buffer, and burn
their stack. See `SPEC.md` § Constant-time contract.

Provenance: original work of the zig-libs authors (MIT), new module (gap)
2026-11-05, extracted from the key readers in `tlsserver/src/keys.zig` and
`acme/src/x509.zig`; no third-party code. Data: `src/vectors.zig` is generated
by our own tooling (`tools/vectors.py`) from a third-party binary run as a
black-box oracle (OpenSSL 3.5.5, fresh test keys); the two RFC 8410 §10.3
examples in `src/tests.zig` are reproduced from that RFC (IETF Trust, code
components under the Revised BSD licence).
