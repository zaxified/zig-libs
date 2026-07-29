# fss

Function Secret Sharing — a 2-party single-point **Distributed Point
Function** (DPF) via the Boyle–Gilboa–Ishai optimized tree construction
("Function Secret Sharing: Improvements and Extensions", ACM CCS 2016). A
point function `f_{α,β}(x) = β if x==α else 0` is secret-shared into two short
keys `(k0,k1)` so that `Eval(0,k0,x) + Eval(1,k1,x) == f_{α,β}(x)` in the
output group `Z_{2^{8L}}` for every `x`, while **each key alone hides
`(α,β)`**. Keys are `O(λ·n)`, not `O(2^n)`. This is the primitive under
Prio/Poplar private analytics (Firefox telemetry, Apple–Google exposure
notifications), Riposte metadata-private messaging, and 2-server PIR.

**Status: Phase-1 COMPLETE.** The PRG, output group, key types + byte codec,
the full-domain checker, and the entire verification harness are REAL and
tested — and the Fable-irreducible core — the **correction-word construction**
(`Dpf(n,L).genWithSeeds`, BGI16 Fig.1) and its matching traversal (`.eval`) —
is implemented (`gate.core_implemented = true`). Every formerly-gated test now
executes: full-domain exhaustive reconstruction, the byte-exact KAT vs the
independent reference vectors, the security smell test, and the CW-perturbation
positive control (all pass, no skips, Debug + ReleaseFast). See [SPEC.md](SPEC.md)
for the construction, the output-group choice, the exact Fable boundary, and the
external-reference anchoring.

| File | Contents |
|---|---|
| `root.zig` | Module doc, `meta`, re-exports (`Dpf`, `prg`, `group`, `kat_vectors`), dark-tests aggregator |
| `prg.zig` | **REAL.** SHA-256 length-doubling PRG `G` + seed→group `convert` (exact byte definitions pinned in-file) |
| `group.zig` | **REAL.** `Z2k(L)` — the `Z_{2^{8L}}` output group (add/sub/neg + byte codec) |
| `dpf.zig` | `Dpf(n,L)`. **REAL:** `Cw`/`Key` types, `serializeCw`/`toBytes`/`fromBytes`, `evalAll`, `firstMismatch`. **FABLE CORE (implemented):** `genWithSeeds`, `eval` |
| `mpf.zig` | `Mpf(n,L,k)` — **multi-point** FSS: `k` independent `Dpf` instances summed. No new cryptographic surface, no failure probability, keys linear in `k` |
| `gate.zig` | The single switch (`core_implemented = true`) marking the correction-word core done |
| `kat_vectors.zig` | Recorded independent-reference KAT vectors (the anti-self-consistency anchor) |
| `kat_test.zig` | The deterministic verification harness + positive controls |
| `mpf_test.zig` | The multi-point harness, incl. the KAT anchor inherited by composition and the seed-reuse leak control |

## Import

```zig
const fss = @import("fss");
```

## API

```zig
const D = fss.Dpf(8, 4); // domain {0,1}^8 = 256 points, output group Z_{2^32}

// Caller supplies two independent, secret, cryptographically-random 16-byte
// seeds (the DPF's only randomness — see Caveats). Same seeds ⇒ same keys.
const keys = D.genWithSeeds(alpha, beta, seed0, seed1); // [2]D.Key
const k0 = keys[0];
const k1 = keys[1];

// Single-point evaluation (O(n)); the two shares reconstruct f_{α,β}(x):
const share0 = D.eval(0, k0, x);
const share1 = D.eval(1, k1, x);
const y = D.G.add(share0, share1); // == beta if x==alpha else 0

// Full-domain evaluation (into a caller buffer of D.domain_size elements):
var out0: [D.domain_size]D.Elem = undefined;
D.evalAll(0, k0, &out0);

// Verification oracle: first x where the two evals fail to reconstruct, or null.
const bad = D.firstMismatch(&out0, &out1, alpha, beta);

// Keys serialize compactly; k0 and k1 share the CW portion, differ only in seed:
var buf: [D.Key.serialized_len]u8 = undefined;
k0.toBytes(&buf);
const restored = D.Key.fromBytes(&buf);
```

### Multi-point (`k` points at once)

```zig
const M = fss.Mpf(8, 4, 3); // 3 points over {0,1}^8, output group Z_{2^32}

// 2k seeds: one INDEPENDENT pair per instance. Byte-identical seeds are
// rejected with error.SeedReuse — see Caveats for why this one is enforced.
const keys = try M.genWithSeeds(alphas, betas, seeds0, seeds1); // [2]M.Key

// eval = the multi-point function itself (the k instances summed):
const y = M.eval(0, keys[0], x) +% M.eval(1, keys[1], x); // == Σ_j β_j·1{x==α_j}

// evalEach = the k components, unsummed — what a consumer wanting k SEPARATE
// results needs (pir's k-record retrieval is exactly this):
var each: [3]M.Elem = undefined;
M.evalEach(0, keys[0], x, &each);

// Same codec shape as Dpf: fixed length, no count field.
var buf: [M.Key.serialized_len]u8 = undefined; // == 3 * D.Key.serialized_len
keys[0].toBytes(&buf);
```

Repeated points are a **multiset**: `α_j == α_l` makes the shared function
`β_j + β_l` there. `k` is compile-time, like `n` and `L`.

## Caveats

- **Seeds are caller-supplied and secret.** `genWithSeeds` takes the two root
  seeds as arguments rather than drawing entropy itself — that is what keeps
  the module pure `.any` computation (no OS/CSPRNG dependency). The caller MUST
  pass two independent, unpredictable, secret 16-byte seeds from a real CSPRNG;
  reusing or leaking a seed breaks the hiding property.
- **PRG is module-defined (SHA-256), NOT interoperable with other DPF
  libraries.** Keys from this module verify only against this module's `Eval`
  (like `bulletproofs`' module-defined transcript). Google's DPF vectors use
  fixed-key AES and are not matched byte-exact — see [SPEC.md](SPEC.md).
- **`Eval`'s control-bit-gated branches are not yet constant-time reviewed**
  (side-channel hardening is a scoped-out increment).
- **Multi-point seeds must be independent ACROSS instances, not just within a
  pair.** Reusing one seed pair for two instances makes the two points'
  **shared prefix** readable from the correction words — a leak of the
  *relationship* between the points, which is why `Mpf.genWithSeeds` rejects
  byte-identical seeds outright. The check catches the plumbing bug only;
  distinct-but-correlated seeds pass it and are still your bug.
- **The key encoding is canonical on output but tolerant on input.** Each
  control-bit CW occupies a whole byte, of which only the low bit is read back,
  so two distinct byte strings can decode to the same key. Harmless here
  (nothing signs or dedups a key); if you hash or compare key bytes,
  canonicalize with `fromBytes` → `toBytes` first. See [SPEC.md](SPEC.md).

## Import graph

```
fss → std.crypto.hash.sha2.Sha256   (std-only; meta.deps = .{})
```

## Verify

```
zig build test-fss                          # Debug — all pass, no skips
zig build test-fss -Doptimize=ReleaseFast   # all pass, no skips
zig build test-fss --fuzz --release=safe    # the real fuzzer (NOT Debug — see SPEC.md)
zig fmt --check modules/fss/
```

All tests execute (the gate is `true`): the four formerly-gated
core-dependent tests (full-domain correctness, byte-exact KAT, security smell,
CW-perturbation control) plus the deterministic positive controls
(`brokenAllBeta`/`brokenAllZero` → the `firstMismatch` checker), which are
core-independent and prove the harness has teeth on their own.

Provenance: clean-room from the BGI16 paper (ACM CCS 2016); no third-party
source ported or studied. Per `CONVENTIONS.md §5` this needs no `NOTICE` entry
— see [SPEC.md](SPEC.md) for the citation and the verification methodology.
