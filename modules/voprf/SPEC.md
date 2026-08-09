# voprf — module spec

RFC 9497 Oblivious Pseudorandom Functions, **ristretto255-SHA512
ciphersuite (§4.1) only**. Status: **complete** — all three modes
implemented and KAT-validated byte-exact against RFC 9497 Appendix A.1
(see `src/kat_test.zig`).

## What an OPRF is

A two-party protocol computing `output = F(skS, input)` where the
server holds `skS`, the client holds `input`, and afterwards the server
has learned nothing about `input` (it only ever sees a randomly blinded
group element) and the client has learned nothing about `skS` beyond
the single PRF output. Building block for Privacy Pass, OPAQUE,
password-breach lookup (à la "Have I Been Pwned" k-anonymity
upgrades), private set membership, etc.

## Modes built

| Mode | Byte | Built | What it adds |
|------|------|-------|--------------|
| OPRF | 0x00 | yes | base protocol: `blind` → `blindEvaluate` → `finalize` |
| VOPRF | 0x01 | yes | server proves DLEQ `log_G(pkS) == log_blinded(evaluated)`; client verifies before unblinding |
| POPRF | 0x02 | yes | public `info` input tweaks the key: `t = skS + HashToScalar("Info"‖len‖info)`, evaluation is `t^-1 *`, proof is against the client-derivable `tweakedKey = G*m + pkS` with the composite lists **swapped** (the proven relation is `t*evaluated == blinded`) |

POPRF was in-scope-if-cheap and turned out cheap: it reuses the whole
DLEQ engine and hash layer; only `poprfInfoScalar`, the tweak/inverse
arithmetic, and the `info` block in the Finalize hash are new.

Other ciphersuites (decaf448-SHAKE256, P-256/P-384/P-521) are out of
scope: no consumer in this repo needs them, and each would drag in a
different group + hash pairing (P-* would also need the full RFC 9380
`hash_to_curve` simplified-SWU pipeline, which std does not ship).

## The DLEQ construction (RFC 9497 §2.2)

A batched, Fiat-Shamir-transformed Chaum-Pedersen proof that one scalar
`k` satisfies `B = k*A` and `D[i] = k*C[i]` for every element of two
equal-length lists — constant proof size (2 scalars, 64 bytes)
regardless of batch size. Exact transcript order (the part that MUST be
byte-exact — every length is I2OSP(len, 2) big-endian):

1. `seed = SHA-512( len(Bm)‖Bm ‖ len(seedDST)‖seedDST )`,
   `seedDST = "Seed-" || contextString`.
2. Per element `i`:
   `di = HashToScalar( len(seed)‖seed ‖ I2OSP(i,2) ‖ len(Ci)‖Ci ‖
   len(Di)‖Di ‖ "Composite" )`; composites `M = Σ di*C[i]` and
   `Z = k*M` (prover, `ComputeCompositesFast`) or `Z = Σ di*D[i]`
   (verifier, `ComputeComposites`).
3. Prover picks fresh random `r`, forms `t2 = r*A`, `t3 = r*M`;
   challenge `c = HashToScalar( len(Bm)‖Bm ‖ len(M)‖M ‖ len(Z)‖Z ‖
   len(t2)‖t2 ‖ len(t3)‖t3 ‖ "Challenge" )`; response
   `s = r - c*k (mod L)`. Proof = `(c, s)`.
4. Verifier recomputes `t2 = s*A + c*B`, `t3 = s*M + c*Z`, re-derives
   the challenge, and compares with `proof.c` (timing-safe here).

`HashToScalar` everywhere is `expand_message_xmd(SHA-512, msg,
"HashToScalar-"‖contextString, 64)` reduced little-endian mod the group
order; `contextString = "OPRFV1-" ‖ I2OSP(mode,1) ‖ "-" ‖
"ristretto255-SHA512"` — so proofs are domain-separated per mode.

## Threat model

- **Malicious server (VOPRF/POPRF)**: may try to evaluate under a
  different key (e.g. to partition users). Countered by the DLEQ proof;
  `finalizeVerifiable`/`finalizePoprf` verify BEFORE unblinding and
  fail closed with `error.InvalidProof` (typed error, never a panic,
  no output on failure).
- **Curious server (all modes)**: sees only `blind * HashToGroup(input)`
  with a fresh uniformly random `blind` — information-theoretically
  independent of `input`.
- **Malicious client**: sees `skS * blindedElement` (+ ZK proof, which
  by zero-knowledge reveals nothing beyond validity). §7.2.3's static
  Diffie-Hellman/security-limit considerations (rotate keys before
  ~2^30-ish evaluations for tight bounds) are the application's
  responsibility.
- **Wire attacker**: all deserializers validate — `Element.fromBytes`
  enforces canonical ristretto255 decoding AND rejects the identity
  (§4.1 DeserializeElement); `deserializeScalar`/`Proof.fromBytes`
  enforce canonical scalars. Applications MUST deserialize received
  elements through these (per §3.3).
- **Side channels**: `skS`, the client `blind` (and its inverse), POPRF's
  `t`/`t_inv` and the DLEQ nonce `r` are multiplied by the sibling
  **`ct25519`**, not by `Ristretto255.mul`.

  This SPEC used to say they "only touch constant-time std paths
  (`Ristretto255.mul`, …)", and that was **false**. std's `mul` is a
  constant-time 4-bit-window ladder that then ends with
  `try q.rejectIdentity()` — a branch on a scalar-derived value — and the
  error union it returns forced a `catch` at all nine secret-scalar call
  sites in `root.zig`, so the leak was reproduced once per site. Reading
  "the ladder is constant-time" and stopping there is exactly how the
  claim survived an audit that graded the module `A6 const-time: PASS` on
  the same reasoning. `ct25519` is std's identical ladder with that tail
  removed: the neutral element is a value, there is no error union, and
  no call site can branch on the scalar. Verified with a ctgrind-style
  valgrind harness (`MAKE_MEM_UNDEFINED` over `skS`/`blind`/`r`), not by
  re-reading the source.

  PUBLIC scalars stay on std's `mul` on purpose: `verifyProof`'s `s`/`c`
  are wire data, the composite `di` are hashes of wire elements, and
  POPRF's `m` is a hash of the public `info` — nothing there is secret,
  and the rejections are genuine fail-closed checks on peer input.

  The proof-challenge comparison uses `std.crypto.timing_safe.eql`. The
  `skS == 0` retry in `deriveKeyPair`, POPRF's `t == 0` check and
  `unblind`'s zero-blind check branch exactly where RFC 9497's own
  pseudocode branches; they are the only secret-dependent branches left,
  and each guards an operation that is undefined at zero rather than
  reporting the result of a multiplication.
- **Randomness**: this module has NO internal RNG. The `blind` scalar
  and the proof randomness `r` are caller-supplied (`scalarFromWideBytes`
  turns 64 CSPRNG bytes into a uniform scalar, §4.7.2). Reusing `r`
  across proofs, or a predictable `blind`, breaks the respective
  security property — that contract is on the caller, and is what makes
  the RFC's `ProofRandomScalar` KATs reproducible.

## What the KATs pin (RFC 9497 Appendix A.1, byte-exact)

- `deriveKeyPair` → `skSm` (all modes) + `pkSm` (VOPRF/POPRF)
- `blind`/`blindPoprf` → every `BlindedElement` (transitively pins
  `HashToGroup` = `expandMessageXmd` + `Ristretto255.fromUniform`)
- `blindEvaluate*` → every `EvaluationElement`
- `generateProof` with the vector's `ProofRandomScalar` → every `Proof`,
  including both batch-size-2 vectors (pins the full transcript order)
- `verifyProof` accepts each published proof; rejects bit-flipped `c`,
  bit-flipped `s`, wrong `pkS`, and swapped batch elements
- `finalize*` → every `Output`; direct `evaluate*` agrees with each
  blinded round trip; fresh-key e2e round trips for all three modes
- `expandMessageXmd` standalone vs RFC 9380 Appendix K.3

## Left out (deliberately)

- **Other ciphersuites** — see above.
- **`GenerateKeyPair`/`RandomScalar` with an internal RNG** (§3.2/§2.1)
  — no-RNG module policy; `deriveKeyPair` + caller-supplied randomness
  cover both KATs and production use.
- **§5.2's high-level client/server context objects** — this module
  exposes the RFC's functional layer; session plumbing belongs to the
  consumer.
- **expand_message_xmd with `len_in_bytes > 64`** (`ell > 1`) — this
  ciphersuite only ever asks for 64 bytes; the comptime assert makes the
  limitation explicit.
