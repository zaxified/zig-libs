# bulletproofs

Bulletproofs zero-knowledge range proofs (Bünz, Bootle, Boneh, Poelstra,
Wuille, Maxwell, "Bulletproofs: Short Proofs for Confidential Transactions
and More", IEEE S&P 2018) over Ristretto255
(`std.crypto.ecc.Ristretto255`): prove a Pedersen-committed value `v` lies
in `[0, 2^n)` (`n` typically 64) without revealing `v`, in a proof whose
size is **logarithmic** in `n` — the construction behind Confidential
Transactions, Monero-style range proofs, and many zk-rollup circuits.

**Status: complete.** The generator derivation, the Pedersen commitment,
the self-contained Fiat-Shamir transcript, both proof structs' byte
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
| `transcript.zig` | **REAL.** `Transcript` — self-contained SHA-512 Fiat-Shamir transcript (NOT dalek/Merlin-compatible — see below) |
| `scalarvec.zig` | **REAL.** Scalar/vector arithmetic (`innerProduct`, `hadamard`, `addVec`/`subVec`/`scaleVec`, `powers`) + `multiScalarMul` over Ristretto255 |
| `ipa.zig` | **FABLE CORE (implemented):** `proveIpa`/`verifyIpa`. `InnerProductProof`'s struct + byte codec are REAL |
| `rangeproof.zig` | **FABLE CORE (implemented):** `prove`/`verify`. `commit`, `deltaYZ`, and `RangeProof`'s struct + byte codec are REAL |
| `gate.zig` | The single switch (`core_implemented`) gating the two cores' tests |
| `kat_test.zig` | The property/soundness KAT harness (completeness + soundness scenarios) |

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
const proof = try bulletproofs.prove(allocator, gens, &prove_transcript, v, gamma);
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
- **Not constant-time.** `scalarvec.multiScalarMul` skips zero scalars, so
  forming commitment `A` takes time dependent on the committed value's bit
  pattern (a mild prover-side timing side-channel). The proof's PRIVACY
  rests on its zero-knowledge property, not on constant-time proving, so
  the ZK guarantee is unaffected — noted for host threat-modelling.
- **Not wire-compatible with dalek / any other Bulletproofs
  implementation** — this module's Fiat-Shamir transcript is its own
  SHA-512 chain (see below); verification is property/soundness-based, not
  byte-exact against a third-party vector.

## Transcript — module-defined, not dalek/Merlin-compatible

This module's Fiat-Shamir transcript (`transcript.zig`) is a
self-contained SHA-512 hash chain, not Merlin (the STROBE-based
transcript protocol dalek's `bulletproofs` crate uses). Every
Bulletproofs implementation's transcript is implementation-defined — the
paper does not pin one down — so a proof from this module verifies only
against this module's own `verify`/`verifyIpa`; it is internally
self-consistent (soundness holds end-to-end) but **not** wire-compatible
with dalek, libsecp256k1-zkp, or any other implementation. See
[SPEC.md](SPEC.md) for the full rationale.

## Import graph

```
bulletproofs → std.crypto.ecc.Ristretto255 / std.crypto.hash.sha2.Sha512
```

No sibling-module dependencies (`meta.deps = .{}`).

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
rejection. See [SPEC.md](SPEC.md) for why no byte-exact third-party vector
is possible here — property + soundness testing is this module's complete,
final verification methodology.

Provenance: see [NOTICE](NOTICE).
