# blindrsa

RSA Blind Signatures (RFC 9474, "RSABSSA") — the primitive behind
anonymous-token schemes such as Privacy Pass: a client gets a message
signed by a server WITHOUT the server ever seeing the message, and the
resulting signature is unlinkable to the blinded exchange that produced
it. Built directly on the sibling `rsa` module's RFC 8017 primitives
(`rsaep`/`rsavp1`/`rsadp`/`rsadpCrt`/`rsasp1`, `verifyPss`) — this module
adds only the blind-signature-specific layer on top.

**Status: complete.** All four RFC 9474 §4 operations (`blind`,
`blindSign`, `finalize`, `verify`) plus `pssEncode` (EMSA-PSS-ENCODE) and
`prepareIdentity`/`prepareRandomize` are implemented and validated
byte-exact against RFC 9474 Appendix A.1 and A.4 — including `blind`
itself, via the deterministic `blindWithFactor` seam fed the RFC's own
fixed blinding factor. `blindSign` implements RFC 9474 §7.2's RECOMMENDED
private-op blinding on top of the mandatory fail-closed self-check — see
[SPEC.md](SPEC.md) for the design and the constant-time posture.

| File | Contents |
|---|---|
| `root.zig` | The four RFC 9474 operations (+ `blindWithFactor` KAT seam), `pssEncode` (delegates to `rsa.emsaPssEncode`), `prepareIdentity`/`prepareRandomize`, `Context`, and the masked composite-modulus inverse (`feInvert`/`maskedInvert`, calling `rsa.bigModInverse`) |
| `kat_vectors.zig` | RFC 9474 Appendix A.1 (RSABSSA-SHA384-PSS-Randomized) and A.4 (RSABSSA-SHA384-PSSZERO-Deterministic) official test vectors, transcribed from the RFC's own published hex, plus the recomputed blinding factor `r` (= the RFC's `inv`⁻¹ mod n, cross-checked in Python) |
| `kat_test.zig` | Byte-exact KAT assertions for all four operations + fail-closed reject tests + random-path round-trips (RFC key and a fresh `rsa.generate` keypair) |

## Import

```zig
const blindrsa = @import("blindrsa");
const rsa = @import("rsa");
```

## The four operations (RFC 9474 §4)

```zig
// Server's RSA keypair (any rsa.SecretKey/rsa.PublicKey — parsed, or
// rsa.generate'd).
const pk: rsa.PublicKey = ...;
const sk: rsa.SecretKey = ...;

// 0. Prepare the message. -Randomized variants (RECOMMENDED) prepend a
//    fresh 32-byte prefix so identical msgs don't yield linkable
//    prepared_msgs; -Deterministic variants use the message unchanged.
var prep_buf: [blindrsa.randomizer_len + msg.len]u8 = undefined;
const prepared_msg = blindrsa.prepareRandomize(msg, random, &prep_buf);
// or: const prepared_msg = blindrsa.prepareIdentity(msg);

// 1. Blind (client): encode + blind prepared_msg against the server's
//    public key. `salt` is 48 random bytes for -PSS, empty for -PSSZERO.
var ctx: blindrsa.Context = undefined;
var blinded_buf: [blindrsa.max_modulus_len]u8 = undefined;
const blinded_msg = try blindrsa.blind(pk, Sha384, prepared_msg, salt, random, &ctx, &blinded_buf);

// 2. BlindSign (server): sign the OPAQUE blinded_msg — never sees
//    prepared_msg. `random` feeds the RFC 9474 §7.2 private-op blinding
//    (side-channel hardening; the output is deterministic regardless).
var blind_sig_buf: [blindrsa.max_modulus_len]u8 = undefined;
const blind_sig = try blindrsa.blindSign(sk, pk, random, blinded_msg, &blind_sig_buf);

// 3. Finalize (client): unblind, then verify before trusting the result
//    (fail-closed — never returns an unverified signature).
var sig_buf: [blindrsa.max_modulus_len]u8 = undefined;
const sig = try blindrsa.finalize(pk, Sha384, blind_sig, &ctx, &sig_buf);

// 4. Verify (anyone): plain RSASSA-PSS-VERIFY over prepared_msg.
try blindrsa.verify(pk, Sha384, prepared_msg, sig, salt.len);
```

`sig` verifies against `prepared_msg` under the server's ORDINARY RSA
public key — a verifier needs no knowledge that a blind-signing protocol
was involved, same "the output is a plain, standard signature" property
the sibling `adaptor` module's Schnorr adaptor signatures have relative to
`bip340`.

## RSABSSA variants (RFC 9474 §5)

All four use SHA-384; they differ only in PSS salt length and message
preparation — both are parameters to `blind`/`verify`, not separate
functions. The RECOMMENDED variants are the `-Randomized` ones.

| Variant | salt_len | Prepare |
|---|---:|---|
| RSABSSA-SHA384-PSS-Randomized (RECOMMENDED) | 48 | `prepareRandomize` |
| RSABSSA-SHA384-PSSZERO-Randomized (RECOMMENDED) | 0 | `prepareRandomize` |
| RSABSSA-SHA384-PSS-Deterministic | 48 | `prepareIdentity` |
| RSABSSA-SHA384-PSSZERO-Deterministic | 0 | `prepareIdentity` |

## Import graph

```
blindrsa → rsa → std.crypto.ff / std.crypto.hash
```

## Verify

```
zig build test-blindrsa                      # 36/36 pass (Debug)
zig build test-blindrsa -Doptimize=ReleaseFast   # 36/36 pass
zig fmt --check modules/blindrsa/
```

Every stage is validated byte-exact against RFC 9474 Appendix A.1's and
A.4's published values (`encoded_msg`, `blinded_msg`, `inv`, `blind_sig`,
`sig`), including fail-closed reject tests (tampered signature/blind_sig,
wrong message, wrong salt length, mismatched `Context`, out-of-range
inputs, non-invertible blinding factors), plus full random-path
round-trips over the RFC's 4096-bit key and a freshly `rsa.generate`d
keypair — see SPEC.md's "Verification" for the complete list.

Provenance: see [NOTICE](NOTICE).
