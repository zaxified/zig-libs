# bulletproofs

Bulletproofs zero-knowledge range proofs (Bünz, Bootle, Boneh, Poelstra,
Wuille, Maxwell, "Bulletproofs: Short Proofs for Confidential Transactions
and More", IEEE S&P 2018) over Ristretto255
(`std.crypto.ecc.Ristretto255`): prove a Pedersen-committed value `v` lies
in `[0, 2^n)` (`n` typically 64) without revealing `v`, in a proof whose
size is **logarithmic** in `n` — the construction behind Confidential
Transactions, Monero-style range proofs, and many zk-rollup circuits.

**Status: complete.** The generator derivation, the Pedersen commitment,
the Merlin Fiat-Shamir transcript, both proof structs' byte
codecs, and every mechanical scalar/vector/multi-scalar-mult helper are
REAL and tested. The two genuinely irreducible zero-knowledge cores — the
Inner-Product Argument (`ipa.zig`'s `proveIpa`/`verifyIpa`) and the
range-proof polynomial construction/reduction (`rangeproof.zig`'s
`prove`/`verify`) — are implemented and `gate.core_implemented` is `true`,
so `kat_test.zig`'s full completeness + soundness suite runs for real
(green in Debug + ReleaseFast). See [SPEC.md](SPEC.md) for the
design and the verification methodology.

| File | Contents |
|---|---|
| `root.zig` | Module doc, `meta`, re-exports, dark-tests aggregator |
| `generators.zig` | **REAL.** `Generators` — deterministic NUMS generator derivation (`g`, `h`, `g_vec`, `h_vec`) |
| `transcript.zig` | **REAL.** `Transcript` — Merlin v1.0 (STROBE-128) Fiat-Shamir transcript, byte-compatible with the `merlin` crate |
| `scalarvec.zig` | **REAL.** Scalar/vector arithmetic (`innerProduct`, `hadamard`, `addVec`/`subVec`/`scaleVec`, `powers`) + `multiScalarMul` over Ristretto255 |
| `ipa.zig` | **FABLE CORE (implemented):** `proveIpa`/`verifyIpa`. `InnerProductProof`'s struct + byte codec are REAL |
| `rangeproof.zig` | **FABLE CORE (implemented):** `prove`/`verify`. `commit`, `deltaYZ`, and `RangeProof`'s struct + byte codec are REAL |
| `gate.zig` | The single switch (`core_implemented`) gating the two cores' tests |
| `kat_test.zig` | The property/soundness KAT harness (completeness + soundness scenarios) |
| `interop_test.zig` | The external anchor: merlin transcripts and dalek range proofs in both directions (`interop_vectors.zig`, from `tools/dalek/`) |

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
const proof = try bulletproofs.prove(allocator, gens, &prove_transcript, &v, gamma);
defer proof.deinit(allocator);

var verify_transcript = bulletproofs.Transcript.init(bulletproofs.rangeproof_domain);
const ok = bulletproofs.verify(gens, &verify_transcript, commitment, proof); // true
```

`prove` rejects an out-of-range `v` (`error.ValueOutOfRange`) at
construction time, before any commitment is built.

## Caveats

- **Proving is Linux-only** (`meta.platform = .linux`). `prove` draws its
  secret blinding via `getrandom(2)` directly (`@compileError` on non-Linux
  — a predictable-blinding proof leaks the witness, so it never silently
  degrades). `verify`/`verifyIpa`/`commit`/`deltaYZ`/`proveIpa` (witness
  passed in) and both byte codecs are platform-independent; only the
  internal-entropy `prove` path is gated.
- **Constant-time on the prover's secrets, measured.** This bullet used to
  say the opposite — that `multiScalarMul` skipped zero scalars and leaked the
  committed value's bit pattern. Audit finding F2 fixed that; the doc did not
  catch up until 2026-09-09. Every term now goes through `mulCt`
  unconditionally, including zero, and `src/ctgrind_harness.zig` measures
  **0 in-file contexts** with `v` and `gamma` tainted through `prove`. ⚠ The
  blinding `prove` draws internally is outside that measurement. See SPEC.md.
- **Single-value proofs only**, `n` a power of two; dalek interoperates
  for `n` in {8, 16, 32, 64} (it refuses other widths).

## Wire compatibility — dalek-cryptography/bulletproofs 4.0

Since 2026-09-30 the transcript (Merlin), the generators and the byte
layout are dalek's, so proofs cross in both directions: a dalek
`RangeProof::to_bytes()` decodes with `RangeProof.fromBytesAlloc` and
verifies with `verify`, and a proof from `prove` verifies under dalek's
`verify_single`. Both sides must start the transcript with the same label
(dalek leaves it to the application; this module's default is
`rangeproof_domain`). `interop_test.zig` asserts both directions against
vectors the crates produced (`tools/dalek/`). Proofs made before that date
by this module do not verify any more (see CHANGELOG.md). Not compatible
with secp256k1-zkp or Monero (other curves and transcripts).

## Import graph

```
bulletproofs → ct25519 (scalarvec.mulCt, the constant-time secret-scalar ladder)
bulletproofs → std.crypto.ecc.Ristretto255 / std.crypto.core.keccak / std.crypto.hash.sha3
```

One sibling-module dependency, `ct25519` (`meta.deps = .{"ct25519"}`) — this
line previously claimed `meta.deps = .{}`, the same stale claim `NOTICE` made
before audit finding B11's 2026-09-09 fix corrected it there; this copy of
the claim was missed at the time and is corrected now (found while verifying
this file's other claims against the tree for the B1/B10 fixes below).

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
