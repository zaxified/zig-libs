# timelock_envelope

A hybrid **two-lock sealed envelope**. `seal` produces a ciphertext that
`open` can decrypt only when BOTH locks hold at once:

1. **Time gate** (`tlock`) — a target drand round `R` has published its
   beacon signature. Before round `R`, the lock is closed for everyone
   (a temporal secret — nobody holds the key early).
2. **Recipient PQ key** (`hqc`) — the opener holds the HQC code-based KEM
   secret key whose public key sealed the envelope.

Content is AEAD-sealed with `chachapoly` under a key bound to BOTH locks,
so neither alone suffices — a true logical **AND**. This is the crypto
core of the S5 dead-man-switch: encrypt a secret now that becomes
readable only *after* a known wall-clock time *and* only *to* a specific
long-term recipient.

**Status: REAL — composition of already-verified siblings.** This module
reimplements no cryptography. It wires together `tlock` (interop-verified
against drand's own Go `tle`), `hqc` (byte-exact against the NIST KAT),
and `chachapoly` (byte-exact against RFC 8439 and `std`), and derives
keys with `std.crypto.kdf.hkdf`. Verified by a round-trip against real,
pairing-checked drand quicknet beacon data, the three AND-composition
negatives, per-region tamper detection, a malformed-input fuzz harness,
and permanent positive controls that prove the AND is genuinely bound
into the key (see [SPEC.md](SPEC.md)).

## ⚠️ The time lock is NOT post-quantum

`tlock` is pairing-based (BLS12-381) and therefore breakable by a
sufficiently large quantum computer (Shor). **The time gate enforces
*timing* only, not confidentiality against a quantum adversary.** The
long-term confidentiality of this envelope rests entirely on the `hqc`
PQ lock: a quantum adversary who records the ciphertext today and later
forges the timing lock still cannot read the content without the HQC
secret key. Do not read this module as a "post-quantum timelock" — the
timelock half is not post-quantum, by construction, and that is fine for
its purpose (nobody, quantum or not, holds a *future* round's signature
today). See [SPEC.md](SPEC.md)'s threat model for what an attacker
recording the ciphertext now can and cannot do.

| File | Contents |
|---|---|
| `root.zig` | Module doc, `meta`, re-exports, dark-tests aggregator |
| `envelope.zig` | The construction: `Envelope(Kem)` generic (`seal`/`open`/`parse`), the HKDF `deriveKeys`, wire constants, error sets; wire-framing + KDF-binding unit tests |
| `security_test.zig` | Acceptance harness — round-trip vs real quicknet data, the three AND negatives, per-region tamper, malformed-input fuzz, positive controls |

## Import

```zig
const timelock_envelope = @import("timelock_envelope");
const Env = timelock_envelope.Envelope128; // or Envelope192 / Envelope256
```

## API

```zig
const Env = timelock_envelope.Envelope128; // = Envelope(hqc.Hqc128)

// SEAL — needs the recipient's HQC encapsulation key, the beacon master
// public key, the future round R, and per-seal randomness.
var rnd: Env.SealRandomness = undefined;             // all three fields are secrets
rnd.generate(io);                                    // production entropy
defer rnd.wipe();
const wire = try Env.seal(allocator, plaintext, &recipient_ek, p_pub, round, &rnd);
defer allocator.free(wire);

// OPEN — needs the recipient's HQC secret key AND the beacon's published
// signature for `round` (available only at/after R). Returns a typed
// error, never a garbage plaintext, if either lock is unsatisfied or any
// byte was tampered with.
const plaintext = try Env.open(allocator, wire, &recipient_dk, round_signature);
defer allocator.free(plaintext);
```

- `recipient_ek` / `recipient_dk` — an `hqc` KEM keypair
  (`hqc.Hqc128.keypair(&kp, &seed)`), the PQ lock's public/secret halves.
- `p_pub` — the drand beacon master public key (`G2`), caller-supplied
  exactly as `tlock` requires (e.g. League-of-Entropy quicknet's).
- `round_signature` — the beacon's published threshold-BLS signature
  (`G1`) for `round`; this is the time lock's key, and it does not exist
  until round `R` is reached.

`open` returns one of: `TimeGateClosed` (wrong/premature round
signature), `AuthFailed` (wrong HQC key, or tampered content/header),
`MalformedTimeLock` / `BadMagic` / `UnsupportedVersion` / `SuiteMismatch`
/ `Truncated` / `LengthMismatch` (malformed wire buffer).

### Streaming — files of any size (wire version 2)

```zig
// SEAL from any std.Io.Reader to any std.Io.Writer, ~128 KiB of memory.
try Env.sealStream(gpa, &file_writer.interface, &file_reader.interface, &recipient_ek, p_pub, round, &rnd);
try file_writer.interface.flush();

// OPEN chunk by chunk. ⚠ Each written chunk is authentic and in order, but
// the plaintext is COMPLETE only when openStream returns without error —
// on an error, discard what was written.
try Env.openStream(gpa, &out_writer.interface, &in_reader.interface, &recipient_dk, round_signature);
```

Same two locks and the same AND; the content is an age-style STREAM
(64 KiB ChaCha20-Poly1305 chunks — `tlock.age.PayloadStream`, the code
`tlock`'s Go-`tle` decryptor runs) under a key that also binds a SHA-256
of the header and both locks. Truncation, reordering, dropped or appended
chunks all fail a tag. `openStream` errors: those of `open`, plus
`MalformedPayload` (no payload / malformed last chunk); `LengthMismatch`
does not exist here. Version 1 (`seal`/`open`) and version 2 each refuse
the other's wire with `UnsupportedVersion`.

### Randomness

Per the repo convention (`tlock`/`hqc`/`bbs`), `seal`'s randomness is an
explicit input (`Env.SealRandomness`) so tests are deterministic. Use
`rnd.generate(io)` in production; supply fixed bytes in a
test. It bundles the time secret, `tlock`'s FO pad, and the HQC encaps
coins.

## Wire format (overview)

A flat, versioned, self-describing byte buffer (little-endian header):

```
magic "TLE1" | version | suite_id | flags | round(u64 LE) | pt_len(u32 LE)
             | tlock_ct(128) | hqc_ct(Kem.ct_bytes)          ← AEAD AAD
             | tag(16) | aead_ct(pt_len)
```

The header plus both lock ciphertexts are authenticated as the AEAD AAD;
the AEAD nonce is *derived* (never stored). Version 2 (streaming) drops
`pt_len` and the single tag:

```
magic "TLE1" | 2 | suite_id | flags | round(u64 LE) | tlock_ct(128) | hqc_ct
             | chunk_0 | … | chunk_last              (STREAM, 64 KiB + 16 each)
```
 Field-by-field layout, the
KDF inputs/domain-separation, and the nonce derivation are in
[SPEC.md](SPEC.md).

## Import graph

```
timelock_envelope → tlock  (→ bls12_381)   time lock
                  → hqc                     PQ lock
                  → chachapoly              content AEAD
                  → std.crypto.kdf.hkdf     key derivation
```

`meta.deps = .{ "tlock", "hqc", "chachapoly" }`. (`bls12_381` types are
reached transitively via `tlock`.)

## Verify

```
zig build test-timelock_envelope --summary all                    # Debug
zig build test-timelock_envelope -Doptimize=ReleaseFast --summary all
zig fmt --check modules/timelock_envelope/
```

All **21** tests pass in both Debug and ReleaseFast. (The fuzz test's
body runs deterministically in normal test mode; interactive `--fuzz`
mode is currently blocked by an unrelated Zig 0.16 `test_runner` bug,
repo-wide.)

Provenance: this module is a clean-room composition; the drand quicknet
KAT vector it reuses for its timelock round-trip is `tlock`'s, whose
provenance is in `modules/tlock/NOTICE`. See [SPEC.md](SPEC.md).
