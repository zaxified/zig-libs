# ctap2pin

CTAP 2.1 `pinUvAuthProtocol` One and Two — the FIDO2 / WebAuthn
client-to-authenticator PIN/UV auth protocol (CTAP 2.1 §6.5.6–6.5.8):
ECDH-P256 key agreement, AES-256-CBC encryption, and HMAC-SHA-256
authentication protecting the PIN/UV during CTAP2. The crypto layer both
a CTAP2 platform and an authenticator implementation sit on.

**Status: complete — both protocols, KAT-validated** (AES-256-CBC vs NIST
SP 800-38A F.2.5/F.2.6 — CBC is this module's own, it is **not** in
`std.crypto`; HKDF vs RFC 5869 A.1; P-256 ECDH vs RFC 5903 §8.1; HMAC vs
RFC 4231; plus full two-sided protocol round-trips). See `SPEC.md`.

| File | Contents |
|---|---|
| `root.zig` | `Aes256Cbc` (NIST-validated CBC mode), `PublicKey`/`publicKeyFromScalar`/`ecdhZ` (P-256 ECDH), `One`, `Two`, `Protocol` + `Impl()` dispatch |
| `kat_vectors.zig` | NIST SP 800-38A CBC + RFC 5869 HKDF + RFC 5903 ECDH + RFC 4231 HMAC vectors, cited |
| `kat_test.zig` | Byte-exact KAT assertions + protocol round-trip/tamper/length tests |

Provenance: clean-room from the FIDO Alliance CTAP 2.1 specification §6.5.6–6.5.8,
a public specification; every KAT is a published NIST/RFC vector. No third-party
authenticator or client source was consulted. Detail in this module's own
[`NOTICE`](NOTICE); it carries no condition beyond zig-libs' MIT license.

## Import

```zig
const ctap2pin = @import("ctap2pin");
```

## API surface

All randomness is caller-supplied (fresh platform ECDH scalar per
transaction; fresh IV per protocol-Two encryption) — no internal RNG.

**Key agreement** (platform side; the authenticator side is symmetric):

```zig
const P = ctap2pin.Impl(.two); // or use ctap2pin.One / ctap2pin.Two directly
const peer = ctap2pin.PublicKey{ .x = cose_x, .y = cose_y }; // authenticator's COSE key
const enc = try P.encapsulate(fresh_random_scalar, peer);
// enc.platform_key_agreement → send to the authenticator
// enc.shared_secret          → One: [32]u8; Two: [64]u8 (hmacKey ‖ aesKey)
```

**Encrypt / decrypt** (whole 16-byte blocks, no padding):

```zig
// Protocol One: zero IV, ciphertext only.
try ctap2pin.One.encrypt(secret, ct[0..pt.len], pt);
try ctap2pin.One.decrypt(secret, pt2[0..ct.len], ct);

// Protocol Two: caller-supplied random IV, output = IV ‖ ciphertext.
try ctap2pin.Two.encrypt(secret, fresh_iv, ct[0..pt.len + 16], pt);
try ctap2pin.Two.decrypt(secret, pt2[0..try ctap2pin.Two.decryptedLength(ct.len)], ct);
```

**Authenticate / verify** (verify is constant-time, fail-closed):

```zig
const sig1 = ctap2pin.One.authenticate(secret, msg); // [16]u8 (truncated HMAC)
const sig2 = ctap2pin.Two.authenticate(secret, msg); // [32]u8 (full HMAC, hmacKey half)
if (!ctap2pin.Two.verify(secret, msg, sig)) return error.PinAuthInvalid;
```

**Raw CBC** (the std-gap primitive, usable on its own):

```zig
try ctap2pin.Aes256Cbc.encrypt(dst, plaintext, key, iv);
try ctap2pin.Aes256Cbc.decrypt(dst, ciphertext, key, iv);
```

## Test

```
zig build test-ctap2pin
zig build test-ctap2pin -Doptimize=ReleaseFast
```
