# hpke

**Hybrid Public Key Encryption (RFC 9180)**: a KEM (`Encap`/`Decap`) + KDF
(HKDF) + AEAD composed into a single-shot "seal to a public key, open with
the matching private key" API, plus a multi-message `Context` (§5.2) for
streaming use and a secret-export function (§5.3) higher-level protocols
(MLS and friends) can pull their own derived keys from.

**Coverage.** All four RFC 9180 modes (base, psk, auth, auth_psk) are anchored
byte-exact to Appendix A (A.1 to A.4 and A.6), to Go 1.26 `crypto/hpke`'s test
vectors and to a live differential run against Go (see *Verify* and *Interop*);
`AuthEncap`/`AuthDecap` are anchored to the RFC's own published
`enc`/`shared_secret`, not merely round-trip-tested. `SPEC.md` carries the
threat model, the design, and the one place this module is deliberately
stricter than the RFC (§5.1.2's PSK-length floor, `error.PskTooShort`).

**Suites.**

- **KEMs:** `X25519Kem`, `P256Kem`, `P384Kem`, `P521Kem` (DHKEMs, all four modes) and
  `MlKem512Kem`, `MlKem768Kem`, `MlKem1024Kem`, `MlKem768P256Kem`,
  `MlKem1024P384Kem`, `MlKem768X25519Kem` (X-Wing) (draft-ietf-hpke-pq; base and psk
  modes only, no `AuthEncap` for a KEM that is not a DH).
- **Key-schedule KDF:** the comptime `Nh` argument of every entry point is the integer
  32/48/64 (HKDF-SHA256/384/512; `schedule.KdfOf(Nh)`) or one of `hpke.kdf.{HkdfSha256,
  HkdfSha384, HkdfSha512, Shake128, Shake256, TurboShake128, TurboShake256}`. It is a
  SEPARATE choice from a DHKEM's own internal KDF (fixed per `kem_id`, RFC 9180 §7.1
  Table 2: X25519/P-256 HKDF-SHA256, P-384 HKDF-SHA384, P-521 HKDF-SHA512).
- **AEAD:** AES-128-GCM and AES-256-GCM (`aesgcm` module; std's types are accepted
  identically), `hpke.ChaCha20Poly1305` and `hpke.ExportOnly` (aead_id 0xFFFF:
  `exportSecret` only).

| File | Provides |
|---|---|
| `suite.zig` | `KemId`/`KdfId`/`AeadId`/`Mode`, `i2osp`/`os2ip`, `suiteId`/`kemSuiteId`, `labeledExtract`/`labeledExpand` (§4) |
| `dhkem.zig` | `X25519Kem`/`P256Kem`/`P384Kem`/`P521Kem`: `encap`/`encapDeterministic`/`decap`/`authEncapDeterministic`/`authDecap`/`deriveKeyPair`/`generateKeyPair`/`keyPairFromSecret` and, on the NIST KEMs, `validatePublicKey` (§4.1/§7.1.1–§7.1.3) |
| `pq.zig`, `kdf.zig` | the draft-ietf-hpke-pq KEMs; the `hpke.kdf` types, including the one-stage SHAKE/TurboSHAKE KDFs |
| `schedule.zig` | `keySchedule` (§5.1), `Context(Aead, Nh).seal`/`.open`/`.exportSecret` (§5.2/§5.3), `computeNonce`/`incrementSeq`, `KdfOf(Nh)`, §5.1's `setupBaseS`/`setupPskS`/`setupAuthS`/`setupAuthPskS` (+ `*Deterministic` KAT seams) with their `setup*R` mirrors — return the `Context` itself, for multi-message/export-only use — and §6.1's single-shot `sealBase`/`sealPsk`/`sealAuth`/`sealAuthPsk` with their `open*` mirrors, thin compositions over `setup*` |
| `burn.zig` | the stack-zeroing every secret-touching entry point runs under |
| `kat_*.zig`, `go_oracle_*.zig`, `fuzz_test.zig`, … | the test classes listed under *Verify* |

- **Model after:** RFC 9180 (Hybrid Public Key Encryption).
- **Platform:** any. **Role:** util (no owned transport/socket — an
  application decides how `enc` and ciphertext travel). **Concurrency:**
  reentrant — `Context` is a plain caller-owned value, every free function
  touches only its parameters.
- **Deps:** `p256`, `p384` and `p521` (the DHKEM(P-256/384/521) and hybrid-KEM
  groups), `ct25519` (X25519 for DHKEM(X25519) and X-Wing; `X25519Kem.KeyPair`
  stays `std.crypto.dh.X25519.KeyPair`), `mlkem` (the ML-KEM half of the pq KEMs),
  `chachapoly` (the ChaCha20-Poly1305 AEAD), `aesgcm` (the AES-GCM AEADs) and `entropy`
  (key generation). Also `std` directly: HKDF (`Hkdf` over `HmacSha384` for
  HKDF-SHA384, which `std` names no alias for) and SHA-3/SHAKE/TurboSHAKE.

## Import

```zig
const hpke = @import("hpke");
```

## API surface

**Suite/label plumbing** (`suite.zig`, re-exported at
`hpke.suite`):

```zig
const suite_id = hpke.suite.suiteId(0x0020, 0x0001, 0x0001); // X25519 + HKDF-SHA256 + AES-128-GCM
const kem_suite_id = hpke.suite.kemSuiteId(0x0020);

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
var prk: [HkdfSha256.prk_length]u8 = undefined;
hpke.suite.labeledExtract(HkdfSha256, &prk, &kem_suite_id, "", "eae_prk", dh_output);
var shared_secret: [32]u8 = undefined;
try hpke.suite.labeledExpand(HkdfSha256, &kem_suite_id, &prk, "shared_secret", kem_context, &shared_secret);
```

**KEM** (`dhkem.zig`, re-exported as `hpke.X25519Kem`/`hpke.P256Kem`/
`hpke.P384Kem`/`hpke.P521Kem`):

```zig
var kp: hpke.X25519Kem.KeyPair = undefined;
hpke.X25519Kem.generateKeyPair(&kp, io); // fresh random keypair
var kp2: hpke.X25519Kem.KeyPair = undefined;
hpke.X25519Kem.deriveKeyPair(&kp2, ikm); // RFC 9180 §7.1.3, ikm-seeded
var encapped: hpke.X25519Kem.Encapped = undefined;
try hpke.X25519Kem.encap(&encapped, kp.public_key, io); // {shared_secret, enc}
var ss: [hpke.X25519Kem.Nsecret]u8 = undefined;
try hpke.X25519Kem.decap(&ss, encapped.enc, &kp); // == encapped.shared_secret
```

**Secrets never travel by value.** Every private key is taken as
`*const KeyPair`, and every secret result — a key pair, a shared secret, a
`Context`, a `Setup` — is written into an `out` pointer (zeroed on error),
never returned: a by-value argument or a returned value is a copy in the
caller's frame that nothing wipes. Every entry point that touches a secret
also zeroes the stack its body used before it returns (`src/burn.zig`); a
ReleaseFast probe (`src/stackprobe_test.zig`) checks all of it, the caller's
frame included.

`hpke.P384Kem` is the same shape (`hpke.P384Kem.generateKeyPair(&kp, io)`,
`Npk`=97/`Nsk`=48/`Nsecret`=48 instead of P-256's 65/32/32) — pass it to
`sealBase`/`setupBaseS`/etc. in place of `X25519Kem`/`P256Kem` below; the
outer `Nh` (key-schedule KDF width) is unrelated and picked the same way
regardless of KEM.

The single-shot flow (§6.1):

```zig
const Aes128Gcm = @import("aesgcm").Aes128Gcm;
var ct_buf: [pt.len + Aes128Gcm.tag_length]u8 = undefined;
const sealed = try hpke.sealBase(hpke.X25519Kem, Aes128Gcm, 32, pkR, io, info, aad, pt, &ct_buf);
// send sealed.enc || ct_buf to the receiver holding skR

var pt_buf: [pt.len]u8 = undefined;
try hpke.openBase(hpke.X25519Kem, Aes128Gcm, 32, sealed.enc, &skR, info, aad, ct_buf[0..], &pt_buf);
```

The other three modes are the same call with their extra inputs — the
sender's static keypair (`skS`, next to the other KEM key) and/or
`psk`/`psk_id` (next to the other key-schedule input, `info`):

```zig
// mode_psk: recipient is assured the sender held `psk` (>= 32 bytes, §5.1.2)
const s = try hpke.sealPsk(hpke.X25519Kem, Aes128Gcm, 32, pkR, io, info, psk, psk_id, aad, pt, &ct_buf);
try hpke.openPsk(hpke.X25519Kem, Aes128Gcm, 32, s.enc, &skR, info, psk, psk_id, aad, ct_buf[0..], &pt_buf);

// mode_auth: recipient is assured the sender held the private key for pkS
const s2 = try hpke.sealAuth(hpke.X25519Kem, Aes128Gcm, 32, pkR, &skS, io, info, aad, pt, &ct_buf);
try hpke.openAuth(hpke.X25519Kem, Aes128Gcm, 32, s2.enc, &skR, skS.public_key, info, aad, ct_buf[0..], &pt_buf);

// mode_auth_psk: both at once
const s3 = try hpke.sealAuthPsk(hpke.X25519Kem, Aes128Gcm, 32, pkR, &skS, io, info, psk, psk_id, aad, pt, &ct_buf);
try hpke.openAuthPsk(hpke.X25519Kem, Aes128Gcm, 32, s3.enc, &skR, skS.public_key, info, psk, psk_id, aad, ct_buf[0..], &pt_buf);
```

`mode_auth` authenticates the sender **to this recipient only** — the
recipient can compute the same shared secret, so it is not a signature and
not transferable to a third party (SPEC.md, threat model).

**The multi-message flow (§5.1): `setup*S`/`setup*R`.** For a caller that
wants the `Context` itself — to seal/open more than one message, or (like
MLS's external-init/external-commit, RFC 9420 §8.3/§12.4) to call ONLY
`Context.exportSecret` and never seal anything — `setupBaseS`/`setupBaseR`
(and the `psk`/`auth`/`auth_psk` siblings, same parameter shape as the
single-shot wrappers minus `aad`/`pt`/`out`) hand back the encapsulation and
the `Context`, not a consumed one-shot ciphertext:

```zig
var setup: hpke.Setup(hpke.X25519Kem, Aes128Gcm, 32) = undefined;
try hpke.setupBaseS(hpke.X25519Kem, Aes128Gcm, 32, &setup, pkR, io, info);
// send setup.enc to the receiver holding skR

var context: hpke.Context(Aes128Gcm, 32) = undefined;
try hpke.setupBaseR(hpke.X25519Kem, Aes128Gcm, 32, &context, setup.enc, &skR, info);

// repeated seal/open over the SAME context:
try setup.context.seal(aad, pt, &ct_buf);
try context.open(aad, ct_buf[0..], &pt_buf);

// or, export-only (no seal/open at all — the MLS external-init/-commit use):
var secret: [32]u8 = undefined;
try context.exportSecret(&suite_id, "my exporter label", &secret);
```

**Runtime-agile suites** (`hpke.agile`, the suite chosen by id at run time, as Go's
`crypto/hpke`):

```zig
const s = try hpke.agile.Suite.init(kem_id, kdf_id, aead_id); // error.UnsupportedSuite
var kp: hpke.agile.KeyPair = undefined;
try hpke.agile.generateKeyPair(&kp, s.kem, io);
const pk = kp.publicKey(); // or hpke.agile.publicKeyFromBytes(s.kem, bytes)

var st: hpke.agile.Setup = undefined;
try hpke.agile.setupS(&st, s, .base, &pk, null, io, info, "", "");
var rc: hpke.agile.Context = undefined;
try hpke.agile.setupR(&rc, s, .base, st.encSlice(), &kp, null, info, "", "");
try st.context.seal(aad, pt, ct_buf[0 .. pt.len + s.tagLength()]);

// only the suites a program accepts, nothing else linked:
const A = hpke.agile.Agile(.{ .kems = &.{.dhkem_x25519_hkdf_sha256}, .kdfs = &.{.hkdf_sha256}, .aeads = &.{.chacha20poly1305} });
```

## Verify

```sh
scripts/modtest hpke
```

Test classes: RFC 9180 Appendix A (A.1 to A.4, A.6) byte-exact in all four modes
through the key-schedule, `Context`, `setup*` and single-shot entry points; Go 1.26
`crypto/hpke`'s vectors (every KEM, KDF and AEAD it offers, X448 included); a frozen replay
of the live Go differential run (*Interop*); negative paths (low-order and malformed
keys, `VerifyPSKInputs` and the §5.1.2 PSK floor, `seq` fail-closed at the ceiling,
wrong-`pkS`/`psk`/mode rejection); no-panic sweep and boundary tests; deterministic fuzz
drivers (`HPKE_FUZZ`); a ReleaseFast stack probe for secrets on the dead stack. `SPEC.md`
*Verification* lists them with their anchors.

## Interop

```sh
zig build interop-hpke                 # live: Go 1.26 crypto/hpke as the peer (needs `go`)
zig build interop-hpke -- --seed 7 --cases 90
zig build interop-hpke -- --write      # re-freeze src/go_oracle_vectors.zig
```

`tools/interop.zig` runs scenarios over 45 suites (9 KEMs x 5 KDFs, the AEAD
rotating through AES-128/256-GCM, ChaCha20-Poly1305 and export-only) against
Go: Go seals and this module opens (Go's ephemeral key is foreign), this module
seals and Go opens, exports are compared, and one flipped bit in enc /
ciphertext / aad (or a short ciphertext) must give the same verdict on both
sides. `src/go_oracle_test.zig` replays the frozen subset in `test-hpke`
without Go. The Go peer (`tools/go_oracle/`, standard library only) is a test
binary because `testing/cryptotest` is the only way to pin Go's randomness.

## Not provided

No `auth`/`auth_psk` mode for the pq KEMs, and no `validatePublicKey` for X25519: `SPEC.md`
*What is deliberately not done* and *Backlog / deferred* give the reasons and what is open.

## Provenance

The RFC 9180 core is clean-room from RFC 9180 (public IETF specification). The
draft-ietf-hpke-pq KEMs and one-stage KDFs (`pq.zig`, `kdf.zig`) are ported from Go 1.26
`crypto/hpke` (BSD-3-Clause; `NOTICE` carries the condition) and tested on its vectors.
One design reference was consulted for the core afterwards: `jedisct1/zig-hpke` (MIT),
read in a 2026-07-21 diff audit that produced the `error.InvalidLength`
hardening in `src/schedule.zig`. See `NOTICE` for the full statement.
