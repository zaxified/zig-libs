# tlock

drand-style **timelock encryption**: encrypt to a FUTURE round of a
drand randomness beacon; decryption becomes possible only once the
beacon publishes that round's threshold-BLS signature. Under the hood
this is Boneh-Franklin Identity-Based Encryption ("FullIdent", CRYPTO
2001) over `bls12_381`, where the "identity" is the round number and
the round signature IS the IBE private key. Builds directly on the
finished `bls12_381` module. Models `drand/tlock` (Go,
Gailly/Melissaris/Romailler) and `drand/kyber`'s `encrypt/ibe` package,
targeting the League of Entropy's **quicknet** beacon
(`SigsOnG1ID`/`"bls-unchained-g1-rfc9380"` scheme).

**Status: REAL — interop-verified.** The ciphersuite machinery
(`beaconId`/`h1`/`h2`/`h3`/`h4`) and the `Ciphertext` wire struct +
byte codec are implemented and tested for real — including a byte-exact
pairing sanity check against a GENUINE, live-fetched quicknet round
signature (see [SPEC.md](SPEC.md)'s "KAT plan"). The two irreducible
cryptographic cores, `encrypt`/`decrypt` (the BF-IBE FullIdent
assembly + the Fiat-Shamir-Okamoto CCA consistency check + a
module-local constant-time `fp12Pow`), are implemented behind
`gate.core_implemented = true` and byte-exact-verified IN BOTH
DIRECTIONS against a genuine ciphertext produced by drand's own Go
`tle` CLI (`kat_test.zig`'s interop vector — which caught a real
Gt-representation divergence a self-consistent round trip never could:
drand/kilic hashes the canonical pairing value's CUBE; see
`src/tlock.zig`'s `gtToDrandRepr` and [SPEC.md](SPEC.md)).

| File | Contents |
|---|---|
| `root.zig` | Module doc, `meta`, re-exports, dark-tests aggregator |
| `ciphersuite.zig` | **REAL.** `beaconId` (drand's unchained beacon digest / IBE identity), `h1` (identity -> `G1`), `h2`/`h3`/`h4` (drand/kyber's SHA-256 constructions), `randomSigma` |
| `tlock.zig` | `Ciphertext` `(U ∈ G2, V, W)` struct + byte codec (**REAL**); **FABLE CORE (REAL):** `encrypt`/`decrypt` + the private `fp12Pow`/`gtToDrandRepr` Gt helpers |
| `age.zig` | The age v1 envelope `tle` writes: `tlock` stanza, header MAC, ChaCha20-Poly1305 STREAM payload, ASCII armor — files of any length |
| `gate.zig` | The single switch (`core_implemented`, now `true`) gating `encrypt`/`decrypt`'s KAT tests |
| `kat_test.zig` | The KAT harness — real ungated hash/pairing-sanity tests (against live quicknet data), gated round-trip/tamper-rejection tests, and the byte-exact drand interop vector (decrypt + re-encrypt) |

## Import

```zig
const tlock = @import("tlock");
```

## API

```zig
// p_pub: the beacon's G2 master public key (caller-supplied, e.g. quicknet's).
// round: the future round number to encrypt to.
// message: a fixed 16-byte block (drand's own DEK width — see
//          ciphersuite.block_bytes's doc comment for why 16, not arbitrary).
// sigma: BF-IBE's random padding — an EXPLICIT parameter (see "Randomness"
//        below), sourced from ciphersuite.randomSigma(io) in production.
const ct = tlock.encrypt(p_pub, round, message, sigma);

// Once `round` is reached and the beacon publishes its signature:
const plaintext = try tlock.decrypt(round_signature, ct);
// round_signature: the beacon's published G1 threshold-BLS signature
// for `round` — this IS the BF-IBE private key. decrypt returns
// error.FoCheckFailed (never a garbage plaintext) if the ciphertext
// was tampered with or round_signature doesn't match.

const bytes = ct.toBytes();               // 128 bytes: U(96) || V(16) || W(16)
const ct2 = try tlock.Ciphertext.fromBytes(bytes);
```

All of the above — `encrypt`/`decrypt`, the `Ciphertext` codec, and the
`ciphersuite.*` hash functions — is implemented, usable, and tested now
(`gate.core_implemented = true`).

### Files of any length: the age envelope `tle` writes (`tlock.age`)

`drand/tlock`'s `tle` CLI does not ship the raw 128-byte ciphertext: it
wraps a random 16-byte file key in it as an age `tlock` stanza and encrypts
the file itself with age's STREAM (ChaCha20-Poly1305, 64 KiB chunks).
`tlock.age` reads and writes that format, binary or armored (`tle -a`).

```zig
const age = tlock.age;

// Encrypt (rnd = age.Randomness.draw(io) in production):
const file = try age.encryptAlloc(gpa, plaintext, p_pub, round, chain_hash, rnd, .{ .armor = true });
defer gpa.free(file);

// Which round must be published before this opens?
const who = try age.inspectAlloc(gpa, file); // .round, .chain_hash, .ciphertext

// Decrypt once the beacon has published that round's signature:
const pt = try age.decryptAlloc(gpa, file, round_signature, .{ .chain_hash = chain_hash });
defer gpa.free(pt);
```

Allocation-free forms, with exact sizes known up front:
`age.encrypt(out, …)` / `age.encryptedLen(round, n)`,
`age.decrypt(out, file, sig, opts)` / `age.decryptedLen(file)`,
`age.armor(out, bin)` / `age.armoredLen(n)`, `age.dearmor(out, text)` /
`age.dearmoredLenMax(n)`, `age.isArmored(bytes)`, and
`age.Header.parse(bin)`.

Decryption order is header syntax → chain hash (if given) → the stanza
(`error.FoCheckFailed` on a wrong signature) → the header MAC
(`error.HeaderMacMismatch`, constant-time compare) → the payload chunk by
chunk (`error.PayloadAuthenticationFailed`; every plaintext byte already
written is wiped). The parsers are bounded (`max_header_bytes`,
`max_stanzas`) and fail closed with typed errors. A header must carry
exactly one `tlock` stanza; other recipient stanzas are parsed, MAC-covered
and skipped.

⚠ Anchoring: the stanza body is checked byte-exact against the genuine
`tle` fixture's; the header MAC, STREAM and armor bytes are tested against
the age specification and in round trip only — no whole `.tle` file is
decrypted in the tests yet (see [SPEC.md](SPEC.md)'s KAT plan).

## Randomness

`encrypt`'s `sigma` (BF-IBE's random pad) is a PLAIN PARAMETER, not
read from `std.Io`/internal entropy directly — mirroring `bbs`/
`frost`'s "randomness is an explicit input" convention. Two sources:

```zig
// Real entropy (production):
const sigma = tlock.ciphersuite.randomSigma(io);

// A fixed value (KAT reproducibility / deterministic ciphertext pinning):
const sigma = [_]u8{0x11} ** tlock.block_bytes;
```

## Import graph

```
tlock → bls12_381  (G1/G2 point arithmetic, the pairing, RFC 9380 hash-to-curve)
      → entropy    (fail-closed draws of sigma, the file key and the payload nonce)
      → chachapoly (ChaCha20-Poly1305 for the age STREAM payload)
```

`meta.deps = .{ "bls12_381", "entropy", "chachapoly" }`.

## Verify

```
zig build test-tlock --summary all                    # Debug
zig build test-tlock -Doptimize=ReleaseFast --summary all
zig fmt --check modules/tlock/
```

With `gate.core_implemented = true` (current): all tests PASS,
no skips — the ciphersuite/hash/pairing-sanity/`Ciphertext`-codec tests,
the `fp12Pow` algebraic-law tests, the gated `encrypt`/`decrypt`
round-trip and tamper/FO-rejection tests, and the byte-exact drand
interop vector (decrypt + re-encrypt). This holds in Debug and
ReleaseFast.

Provenance: see [NOTICE](NOTICE).
