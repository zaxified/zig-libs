# ibe

Standalone **Boneh-Franklin Identity-Based Encryption** ("FullIdent",
CRYPTO 2001 §4.2) over `bls12_381`: any string is a public key (an
email address, a device serial, a policy tag); a trusted Private Key
Generator (PKG) — **you**, via `setup`/`extract` — derives the matching
private key on demand. Encrypt to an identity before its holder has
ever contacted the PKG; decrypt once the private key has been
extracted.

**Status: REAL — fully implemented, no stubs.** `setup`, `extract`,
`encrypt`, and `decrypt` are all real, built on `bls12_381`'s
already-proven field/group/pairing/hash-to-curve primitives.

**How it is anchored.** The encrypt/decrypt *assembly* is checked
against a foreign artifact: `ibe.Scheme` is a `comptime` seam over the
ciphersuite, and the tests instantiate this module's own
`encrypt`/`decrypt`/`fp12Pow`/`Ciphertext` code with **drand's**
parameters and require it to reproduce a genuine ciphertext produced by
drand's own Go `tle` CLI, byte for byte. This module's own *parameters*
— its DSTs and hash tags, and the one deliberate divergence from
`tlock` (no drand-style Gt cube) — cannot be anchored externally at
all: RFC 9380 §3.1 requires every application to pick its own DST, so
there is no foreign value for ours to match, and with no external byte
target the cube is a free choice. Those rest on the round-trip,
pairing-consistency and soundness tests, and that is the end state.
See [SPEC.md](SPEC.md)'s "KAT plan" for both halves, including the
mutations that showed the anchor catches what the self-consistency
tests structurally cannot.

**Relationship to `tlock`**: `tlock` (this repo) is the SAME
Boneh-Franklin primitive specialized so the PKG is a drand randomness
beacon and the identity is a future round number — a *timelock*. `ibe`
is the general case: you run the PKG yourself, for any identity string,
at any time.

| File | Contents |
|---|---|
| `root.zig` | Module doc, `meta`, re-exports, dark-tests aggregator |
| `ciphersuite.zig` | `h1` (identity -> `G1`), `h2`/`h3`/`h4` (this module's own domain-separated hash constructions), `randomSigma` |
| `ibe.zig` | `KeyPair`, `setup`/`extract` (the PKG API), `Ciphertext` `(U ∈ G2, V, W)` struct + byte codec, `encrypt`/`decrypt` + the private `fp12Pow` `Gt`-exponentiation helper |
| `kat_test.zig` | Round-trip, pairing-consistency and soundness (tamper/wrong-key rejection) KATs, plus the drand-parameterised interop anchor (test-only `tlock` import) |

## Import

```zig
const ibe = @import("ibe");
```

## API

```zig
// Setup: generate a fresh PKG keypair. msk MUST stay secret (whoever
// holds it can extract a private key for ANY identity).
// Secrets (msk, d_id, sigma, the plaintext) are written in place and passed
// by pointer, never returned through the stack.
var kp: ibe.KeyPair = undefined;
ibe.setup(&kp, io); // kp.msk: Fr, kp.mpk: g2.Affine
defer kp.deinit();

// Extract: derive an identity's private key. Deterministic in (msk, id).
var d_id: g1.Affine = undefined;
ibe.extract(&d_id, &kp.msk, "alice@example.com");

// Encrypt: anyone with mpk can encrypt to any identity string, even
// before that identity has ever contacted the PKG.
// message/sigma: fixed 32-byte blocks (ibe.block_bytes) — wide enough
// to carry a 256-bit symmetric key directly (KEM-then-DEM for larger
// payloads).
var sigma: [ibe.block_bytes]u8 = undefined;
ibe.ciphersuite.randomSigma(&sigma, io); // production entropy
const ct = ibe.encrypt(kp.mpk, "alice@example.com", &message, &sigma);

// Decrypt: only the identity's private key can recover the message.
var plaintext: [ibe.block_bytes]u8 = undefined;
try ibe.decrypt(&plaintext, &d_id, ct);
// Returns error.FoCheckFailed (never a garbage plaintext) if the
// ciphertext was tampered with or d_id doesn't match the identity ct
// was encrypted under.

const bytes = ct.toBytes();               // 160 bytes: U(96) || V(32) || W(32)
const ct2 = try ibe.Ciphertext.fromBytes(bytes);
```

## Randomness

`setup`'s `msk` is drawn via `bls12_381.Fr.random(io)` internally.
`encrypt`'s `sigma` (BF-IBE's random pad) is a PLAIN PARAMETER, not
read from `std.Io` inside `encrypt` itself — mirroring `tlock`/`bbs`/
`frost`'s "randomness is an explicit input" convention:

```zig
// Real entropy (production):
var sigma: [ibe.block_bytes]u8 = undefined;
ibe.ciphersuite.randomSigma(&sigma, io);

// A fixed value (KAT reproducibility / deterministic ciphertext pinning):
const sigma = [_]u8{0x11} ** ibe.block_bytes;
```

## Import graph

```
ibe → bls12_381 (G1/G2 point arithmetic, the pairing, RFC 9380 hash-to-curve)

tests only:
ibe → tlock  (drand's ciphersuite + its frozen drand interop fixture)
```

`meta.deps = .{"bls12_381"}`. `tlock` is a `test_deps` entry in
`build.zig`, never part of the published module — `zig build
check-testonly` proves it.

## Verify

```
zig build test-ibe --summary all                    # Debug
zig build test-ibe -Doptimize=ReleaseFast --summary all
zig fmt --check modules/ibe/
```

All tests PASS in both Debug and ReleaseFast — ciphersuite hash
tests, `Ciphertext` codec tests, `setup`/`extract` tests, the private
`fp12Pow` algebraic-law tests, and `kat_test.zig`'s round-trip,
pairing-consistency, soundness/CCA-rejection and drand-anchor KATs.

Provenance: see [NOTICE](NOTICE).
