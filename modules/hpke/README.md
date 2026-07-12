# hpke

**Hybrid Public Key Encryption (RFC 9180)**: a KEM (`Encap`/`Decap`) + KDF
(HKDF) + AEAD composed into a single-shot "seal to a public key, open with
the matching private key" API, plus a multi-message `Context` (§5.2) for
streaming use and a secret-export function (§5.3) higher-level protocols
(MLS and friends) can pull their own derived keys from.

**Status: crypto-implementation pass done — everything is real and
KAT-validated** against RFC 9180 Appendix A.1 (the full vector: DHKEM
`Encap`/`Decap`/`DeriveKeyPair`, key schedule, all 6 encryption tuples,
all 3 exported values, single-shot `sealBase`/`openBase` end-to-end), A.2
(ChaCha20Poly1305), and A.3 (P-256), byte-exact. `AuthEncap`/`AuthDecap`
(auth/auth_psk modes' KEM fold) are implemented and self-consistency-
tested (no official Appendix A auth-mode vector is embedded). See
`SPEC.md` for the threat model and the done-record of the fill-in pass.

| File | Provides |
|---|---|
| `suite.zig` | `KemId`/`KdfId`/`AeadId`/`Mode`, `i2osp`/`os2ip`, `suiteId`/`kemSuiteId`, `labeledExtract`/`labeledExpand` (§4) |
| `dhkem.zig` | `X25519Kem`/`P256Kem`: `encap`/`encapDeterministic`/`decap`/`authEncapDeterministic`/`authDecap`/`deriveKeyPair`/`generateKeyPair` (§4.1/§7.1.1–§7.1.3) |
| `schedule.zig` | `keySchedule` (§5.1), `Context(Aead, Nh).seal`/`.open`/`.exportSecret` (§5.2/§5.3), `computeNonce`/`incrementSeq`, `sealBase`/`sealBaseDeterministic`/`openBase` (§6.1) |
| `kat_rfc9180.zig` | RFC 9180 Appendix A.1 (full vector) + A.2/A.3 (header fields), driven end-to-end through the real implementation |

- **Model after:** RFC 9180 (Hybrid Public Key Encryption).
- **Platform:** any. **Role:** util (no owned transport/socket — an
  application decides how `enc` and ciphertext travel). **Concurrency:**
  reentrant — `Context` is a plain caller-owned value, every free function
  touches only its parameters.
- **Deps:** none (`std` only — `std.crypto.dh.X25519`,
  `std.crypto.ecc.P256`, `std.crypto.kdf.hkdf.HkdfSha256`,
  `std.crypto.aead.aes_gcm`, `std.crypto.aead.chacha_poly`).

## Import

```zig
const hpke = @import("hpke");
```

## API surface (today)

**Real — suite/label plumbing** (`suite.zig`, re-exported at
`hpke.suite`):

```zig
const suite_id = hpke.suite.suiteId(0x0020, 0x0001, 0x0001); // X25519 + HKDF-SHA256 + AES-128-GCM
const kem_suite_id = hpke.suite.kemSuiteId(0x0020);

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const prk = hpke.suite.labeledExtract(HkdfSha256, &kem_suite_id, "", "eae_prk", dh_output);
var shared_secret: [32]u8 = undefined;
try hpke.suite.labeledExpand(HkdfSha256, &kem_suite_id, prk, "shared_secret", kem_context, &shared_secret);
```

**KEM** (`dhkem.zig`, re-exported as `hpke.X25519Kem`/`hpke.P256Kem`):

```zig
const kp = hpke.X25519Kem.generateKeyPair(io); // fresh random keypair
const kp2 = hpke.X25519Kem.deriveKeyPair(ikm); // RFC 9180 §7.1.3, ikm-seeded
const encapped = try hpke.X25519Kem.encap(kp.public_key, io); // {shared_secret, enc}
const ss = try hpke.X25519Kem.decap(encapped.enc, kp); // == encapped.shared_secret
```

The single-shot flow (§6.1):

```zig
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
var ct_buf: [pt.len + Aes128Gcm.tag_length]u8 = undefined;
const sealed = try hpke.sealBase(hpke.X25519Kem, Aes128Gcm, 32, pkR, io, info, aad, pt, &ct_buf);
// send sealed.enc || ct_buf to the receiver holding skR

var pt_buf: [pt.len]u8 = undefined;
try hpke.openBase(hpke.X25519Kem, Aes128Gcm, 32, sealed.enc, skR, info, aad, ct_buf[0..], &pt_buf);
```

## Verify

```sh
zig build test-hpke
```

41 tests, all real, no skip guards: the full RFC 9180 A.1 vector driven
end-to-end through the actual implementation (DHKEM Encap/Decap/
DeriveKeyPair, key schedule, all 6 published encryption tuples including
the seq-skipping ones, all 3 exported values, `sealBaseDeterministic` →
`openBase` reproducing `enc` + the first ciphertext in one call), A.2
(ChaCha20Poly1305) and A.3 (P-256) headers byte-exact, low-order/
malformed-key rejection (`error.DhFailed`/`error.DeserializeError`),
`VerifyPSKInputs` consistency, seq fail-closed at the ceiling, auth-mode
self-consistency round trips, and fresh-random-key `sealBase`→`openBase`
round trips (X25519+AES-128-GCM and P-256+ChaCha20Poly1305). Green in
Debug and ReleaseFast.

## Provenance

Clean-room from RFC 9180 (public IETF specification). See `NOTICE` for
the full statement (no third-party implementation was consulted as a
design reference).
