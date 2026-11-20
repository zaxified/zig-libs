# bulletproofs

Bulletproofs zero-knowledge range proofs (Bünz, Bootle, Boneh, Poelstra,
Wuille, Maxwell, "Bulletproofs: Short Proofs for Confidential Transactions
and More", IEEE S&P 2018) over Ristretto255
(`std.crypto.ecc.Ristretto255`): prove a Pedersen-committed value `v` lies
in `[0, 2^n)` (`n` typically 64) without revealing `v`, in a proof whose
size is **logarithmic** in `n` — the construction behind Confidential
Transactions, Monero-style range proofs, and many zk-rollup circuits.
Several values can share one **aggregated** proof (paper §4.3), whose size
grows with `log2(n*m)` for `m` values.

The generator derivation, the Pedersen commitment, the Merlin Fiat-Shamir transcript, both proof structs'
byte codecs, the scalar/vector/multi-scalar-mult helpers, the Inner-Product Argument and the range-proof
construction/reduction are all implemented, and `gate.core_implemented` is `true`, so `kat_test.zig`'s
full completeness + soundness suite runs. See [SPEC.md](SPEC.md) for the design and the verification
methodology.

| File | Contents |
|---|---|
| `root.zig` | Module doc, `meta`, re-exports, dark-tests aggregator |
| `generators.zig` | `Generators` — deterministic NUMS generator derivation (`g`, `h`, `g_vec`, `h_vec`); `initParties` for aggregated proofs |
| `transcript.zig` | `Transcript` — Merlin v1.0 (STROBE-128) Fiat-Shamir transcript, byte-compatible with the `merlin` crate |
| `scalarvec.zig` | Scalar/vector arithmetic (`innerProduct`, `hadamard`, `addVec`/`subVec`/`scaleVec`, `powers`), `multiScalarMul` (constant time, secret scalars) and `multiScalarMulVartime` (public scalars) over Ristretto255 |
| `ipa.zig` | `proveIpa`/`verifyIpa`; `InnerProductProof`'s struct and byte codec |
| `rangeproof.zig` | `prove`/`verify`, aggregated `proveMultiple`/`verifyMultiple`, `verifyBatch` (many proofs, one MSM); `commit`, `deltaYZ`/`deltaYZMultiple`, `RangeProof`'s struct and byte codec |
| `gate.zig` | The single switch (`core_implemented`) gating the two cores' tests |
| `kat_test.zig` | The property/soundness harness (completeness + soundness scenarios) |
| `aggregate_test.zig`, `batch_test.zig` | Aggregated proofs (m = 1..8, malformed batches, reordered/swapped/dropped commitments); batch verification |
| `verify_b8_diff_test.zig` | The verifier held byte-exact to the plain one (SPEC § B8) |
| `interop_test.zig` | The external anchor: merlin transcripts and dalek range proofs, single and aggregated, in both directions (`interop_vectors.zig`, from `tools/dalek/`) |
| `fuzz_test.zig`, `stackprobe_test.zig`, `ctgrind_harness.zig` | Decoder/prove-verify fuzz, dead-stack probe, constant-time harness |

## Import

```zig
const bulletproofs = @import("bulletproofs");
```

## API

```zig
const gens = try bulletproofs.Generators.init(allocator, 64); // n = 64-bit range
defer gens.deinit(allocator);

const v: u64 = 12345;
const gamma = ...; // caller-supplied random blinding scalar
const commitment = bulletproofs.commit(gens, v_as_scalar_bytes, gamma);

var prove_transcript = bulletproofs.Transcript.init(bulletproofs.rangeproof_domain);
const proof = try bulletproofs.prove(allocator, io, gens, &prove_transcript, &v, gamma);
defer proof.deinit(allocator);

var verify_transcript = bulletproofs.Transcript.init(bulletproofs.rangeproof_domain);
const ok = bulletproofs.verify(gens, &verify_transcript, commitment, proof); // true
```

`prove` rejects an out-of-range `v` (`error.ValueOutOfRange`) at
construction time, before any commitment is built.

Aggregated: `m` values (a power of two) in one proof, over generators for at
least `m` parties. The verifier takes the commitments in the prover's order.

```zig
const gens = try bulletproofs.Generators.initParties(allocator, 64, 4); // up to 4 values
defer gens.deinit(allocator);

const values = [_]u64{ 10, 20, 30, 40 };
const gammas: [4][32]u8 = ...; // one blinding per value
// commitments[j] = bulletproofs.commit(gens, values[j] as scalar bytes, gammas[j])

var pt = bulletproofs.Transcript.init(bulletproofs.rangeproof_domain);
const proof = try bulletproofs.proveMultiple(allocator, io, gens, &pt, &values, &gammas);
defer proof.deinit(allocator);

var vt = bulletproofs.Transcript.init(bulletproofs.rangeproof_domain);
const ok = bulletproofs.verifyMultiple(gens, &vt, &commitments, proof); // true
```

Many independent proofs (single or aggregated, mixed sizes, one `gens`)
verify faster together — one multi-scalar multiplication, random weights from
`io`:

```zig
var t1 = bulletproofs.Transcript.init(bulletproofs.rangeproof_domain);
var t2 = bulletproofs.Transcript.init(bulletproofs.rangeproof_domain);
const all_ok = try bulletproofs.verifyBatch(gens, io, &.{
    .{ .transcript = &t1, .commitments = &commitments, .proof = proof },
    .{ .transcript = &t2, .commitments = &other_commitments, .proof = other_proof },
});
```

`proveMultiple` refuses an empty batch, a length that is not a power of
two, mismatched `gammas`, or more values than `gens` has parties
(`error.InvalidAggregation`), and any value out of range
(`error.ValueOutOfRange`). One caller holds every witness; dalek's
multi-party dealer/party protocol is not offered.

## Caveats

- **Proving needs an `std.Io`** for its secret blinding: `prove`/
  `proveMultiple` draw it from `io.randomSecure` (the OS, every call, no
  fallback — a predictable-blinding proof leaks the witness, so an entropy
  failure is `error.EntropyUnavailable`, never a weaker source). Any target.
- **Constant-time on the prover's secrets, measured.** Every term of `multiScalarMul` goes through
  the constant-time ladder unconditionally, including zero, and `src/ctgrind_harness.zig` measures
  **0 in-file contexts** with `v` and `gamma` tainted through `prove`. ⚠ The
  blinding `prove` draws internally is outside that measurement. See SPEC.md.
- `n` and `m` are powers of two; dalek interoperates for `n` in {8, 16,
  32, 64} (it refuses other widths). Several independent proofs verify
  together with `verifyBatch` (above).

## Wire compatibility — dalek-cryptography/bulletproofs 4.0

The transcript (Merlin), the generators and the byte
layout are dalek's, so proofs cross in both directions: a dalek
`RangeProof::to_bytes()` decodes with `RangeProof.fromBytesAlloc` and
verifies with `verify`, and a proof from `prove` verifies under dalek's
`verify_single`; the same holds for aggregated proofs (`proveMultiple` ↔
dalek's `prove_multiple`/`verify_multiple`, generators of party `j` from
chain `'G'/'H' || LE32(j)`). Both sides must start the transcript with the same label
(dalek leaves it to the application; this module's default is
`rangeproof_domain`). `interop_test.zig` asserts both directions against
vectors the crates produced (`tools/dalek/`). Not compatible
with secp256k1-zkp or Monero (other curves and transcripts).

## Import graph

```
bulletproofs → ct25519 (scalarvec.mulCt, the constant-time secret-scalar ladder)
bulletproofs → std.crypto.ecc.Ristretto255 / std.crypto.core.keccak / std.crypto.hash.sha3
```

One sibling-module dependency, `ct25519` (`meta.deps = .{"ct25519"}`).

## Not provided

No multi-party dealer/party protocol, no `n > 64` witnesses, no R1CS/circuit proofs, no secp256k1-zkp or Monero
compatibility; see SPEC.md *What is deliberately not done* and *Backlog / deferred*.

## Verify

```
zig build test-bulletproofs                    # Debug
zig build test-bulletproofs -Doptimize=ReleaseFast
zig fmt --check modules/bulletproofs/
```

With `gate.core_implemented = true`, `kat_test.zig`'s suite runs as real,
executed assertions: completeness (several in-range values, `n=8`,
including `v=0` and the boundary `v=2^n-1`, plus a standalone IPA
completeness check), out-of-range rejection, an exhaustive per-field
tamper suite (every proof element — `A`/`S`/`T1`/`T2`/`tau_x`/`mu`/`t_hat`,
every IPA `L_i`/`R_i`, and the final `a`/`b` — flipped and re-verified,
each must reject), cross-commitment rejection, and mismatched-`n`
rejection. `interop_test.zig` adds the byte-exact external anchor (merlin
challenges, dalek proofs accepted here, this module's proofs accepted by
dalek); see [SPEC.md](SPEC.md) "Anchoring".

Provenance: see [NOTICE](NOTICE).
