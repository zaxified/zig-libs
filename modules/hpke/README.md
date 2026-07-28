# hpke

**Hybrid Public Key Encryption (RFC 9180)**: a KEM (`Encap`/`Decap`) + KDF
(HKDF) + AEAD composed into a single-shot "seal to a public key, open with
the matching private key" API, plus a multi-message `Context` (§5.2) for
streaming use and a secret-export function (§5.3) higher-level protocols
(MLS and friends) can pull their own derived keys from.

**Status: crypto-implementation pass done — everything is real and
KAT-validated** against RFC 9180 Appendix A, byte-exact, in **all four
modes**: A.1.1 base (the full vector: DHKEM `Encap`/`Decap`/
`DeriveKeyPair`, key schedule, all 6 encryption tuples, all 3 exported
values, single-shot `sealBase`/`openBase` end-to-end), A.1.2 `psk`, A.1.3
`auth` and A.1.4 `auth_psk` driven through the same full chain, plus A.2
(ChaCha20Poly1305), A.3 (P-256) and A.3.2/A.3.3/A.3.4 (the three non-base
modes over P-256). `AuthEncap`/`AuthDecap` are anchored to the RFC's own
published `enc`/`shared_secret` for both KEMs, not merely round-trip-tested.
See `SPEC.md` for the threat model, the done-records, and the one place
this module is deliberately stricter than the RFC (§5.1.2's PSK-length
floor, `error.PskTooShort`).

| File | Provides |
|---|---|
| `suite.zig` | `KemId`/`KdfId`/`AeadId`/`Mode`, `i2osp`/`os2ip`, `suiteId`/`kemSuiteId`, `labeledExtract`/`labeledExpand` (§4) |
| `dhkem.zig` | `X25519Kem`/`P256Kem`: `encap`/`encapDeterministic`/`decap`/`authEncapDeterministic`/`authDecap`/`deriveKeyPair`/`generateKeyPair` (§4.1/§7.1.1–§7.1.3) |
| `schedule.zig` | `keySchedule` (§5.1), `Context(Aead, Nh).seal`/`.open`/`.exportSecret` (§5.2/§5.3), `computeNonce`/`incrementSeq`, and §6.1's single-shot `sealBase`/`sealPsk`/`sealAuth`/`sealAuthPsk` (+ `*Deterministic` KAT seams) with their `open*` mirrors |
| `kat_rfc9180.zig` | RFC 9180 Appendix A vectors: A.1 in all four modes (full), A.2/A.3 headers, A.3's three non-base modes — driven end-to-end through the real implementation |

- **Model after:** RFC 9180 (Hybrid Public Key Encryption).
- **Platform:** any. **Role:** util (no owned transport/socket — an
  application decides how `enc` and ciphertext travel). **Concurrency:**
  reentrant — `Context` is a plain caller-owned value, every free function
  touches only its parameters.
- **Deps:** `p256` (DHKEM(P-256)'s group — byte-exact to
  `std.crypto.ecc.P256`; the X25519 KEM path stays on `std`). Also `std`
  directly: `std.crypto.dh.X25519`, `std.crypto.kdf.hkdf.HkdfSha256`,
  `std.crypto.aead.aes_gcm`, `std.crypto.aead.chacha_poly`.

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

The other three modes are the same call with their extra inputs — the
sender's static keypair (`skS`, next to the other KEM key) and/or
`psk`/`psk_id` (next to the other key-schedule input, `info`):

```zig
// mode_psk: recipient is assured the sender held `psk` (>= 32 bytes, §5.1.2)
const s = try hpke.sealPsk(hpke.X25519Kem, Aes128Gcm, 32, pkR, io, info, psk, psk_id, aad, pt, &ct_buf);
try hpke.openPsk(hpke.X25519Kem, Aes128Gcm, 32, s.enc, skR, info, psk, psk_id, aad, ct_buf[0..], &pt_buf);

// mode_auth: recipient is assured the sender held the private key for pkS
const s2 = try hpke.sealAuth(hpke.X25519Kem, Aes128Gcm, 32, pkR, skS, io, info, aad, pt, &ct_buf);
try hpke.openAuth(hpke.X25519Kem, Aes128Gcm, 32, s2.enc, skR, skS.public_key, info, aad, ct_buf[0..], &pt_buf);

// mode_auth_psk: both at once
const s3 = try hpke.sealAuthPsk(hpke.X25519Kem, Aes128Gcm, 32, pkR, skS, io, info, psk, psk_id, aad, pt, &ct_buf);
try hpke.openAuthPsk(hpke.X25519Kem, Aes128Gcm, 32, s3.enc, skR, skS.public_key, info, psk, psk_id, aad, ct_buf[0..], &pt_buf);
```

`mode_auth` authenticates the sender **to this recipient only** — the
recipient can compute the same shared secret, so it is not a signature and
not transferable to a third party (SPEC.md, threat model).

## Verify

```sh
zig build test-hpke
```

All tests are real, no skip guards: the full RFC 9180 A.1 vector driven
end-to-end through the actual implementation (DHKEM Encap/Decap/
DeriveKeyPair, key schedule, all 6 published encryption tuples including
the seq-skipping ones, all 3 exported values, `sealBaseDeterministic` →
`openBase` reproducing `enc` + the first ciphertext in one call); the same
full chain for `mode_psk`/`mode_auth`/`mode_auth_psk` against A.1.2/A.1.3/
A.1.4 and A.3.2/A.3.3/A.3.4 (including `AuthEncap`/`AuthDecap` and
`P256Kem.deriveKeyPair` byte-exact); A.2 (ChaCha20Poly1305) and A.3
(P-256) headers byte-exact; low-order/malformed-key rejection
(`error.DhFailed`/`error.DeserializeError`), `VerifyPSKInputs` consistency
and the §5.1.2 PSK floor (`error.PskTooShort`), seq fail-closed at the
ceiling, wrong-`pkS`/wrong-`psk`/wrong-mode open rejection, and
fresh-random-key round trips through every `seal*`→`open*` pair
(X25519+AES-128-GCM and P-256+ChaCha20Poly1305). Green in Debug and
ReleaseFast.

## Provenance

Clean-room from RFC 9180 (public IETF specification). See `NOTICE` for
the full statement (no third-party implementation was consulted as a
design reference).
