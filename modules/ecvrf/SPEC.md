# ecvrf — SPEC

ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381); see [README.md](README.md) for
purpose and API. Provenance: see [NOTICE](NOTICE).

**Status: implemented.** All of RFC 9381 §5's ciphersuite-generic
algorithms and §5.5's ECVRF-EDWARDS25519-SHA512-TAI parameter fixing are
real — see "Implementation notes" below.

## Design

- **Source of truth**: RFC 9381 (IRTF CFRG, Informational, August 2023)
  §5 (`ECVRF_prove`/`ECVRF_proof_to_hash`/`ECVRF_verify` and their §5.4
  auxiliary functions) and §5.5 (ciphersuite parameter fixing), plus RFC
  8032 §5.1.2/§5.1.5 as §5.5 itself references for point/scalar encoding
  and secret-key derivation. Clean-room from both RFC texts — no
  third-party ECVRF implementation consulted; see `NOTICE`.
- **No new curve/field arithmetic.** Unlike this repository's `ed448`/
  `decaf448`/`bls12_381` (which had to build a curve family std lacks),
  ECVRF-EDWARDS25519-SHA512-TAI reuses `std.crypto.ecc.Edwards25519`
  wholesale — same curve, same encoding (RFC 8032 §5.1.2's compressed
  `y`+sign-bit form IS `Edwards25519.toBytes`/`fromBytes`), same hash
  (SHA-512). This module is pure protocol orchestration: hash framing,
  the try-and-increment hash-to-curve loop, and a Schnorr-shaped
  DLEQ-style challenge/response over two bases (`B` and `H`) proving `x`
  is the same secret scalar behind both `Y = x*B` and `Gamma = x*H`.
  `Edwards25519.mulDoubleBasePublic` is exactly `ECVRF_verify`'s `U =
  s*B - c*Y` / `V = s*H - c*Gamma` primitive, used as-is.
- **`suite_string = 0x03`, not `0x04`.** RFC 9381 §5.5 defines two
  edwards25519 ciphersuites back to back: ECVRF-EDWARDS25519-SHA512-TAI
  (`suite_string = 0x03`, try-and-increment `encode_to_curve`) and
  ECVRF-EDWARDS25519-SHA512-ELL2 (`suite_string = 0x04`, RFC 9380
  Elligator2 `encode_to_curve`, "identical... except that..."). Every
  hash in the scheme (`encodeToCurve`, `challengeGeneration`,
  `proofToHash`) begins with `suite_string`, so using the wrong byte
  silently produces a self-consistent but RFC-non-interoperable VRF —
  this is the single easiest transcription mistake in this ciphersuite,
  and is called out explicitly in `ecvrf.zig`'s module doc comment and
  `root.zig`'s own `suite_string` test.
- **`ECVRF_challenge_generation` hashes FIVE points, `Y` first.** RFC
  9381 §5.4.3's signature is `ECVRF_challenge_generation(P1, P2, P3, P4,
  P5)`; §5.1 step 6 calls it as `challenge_generation(Y, H, Gamma, k*B,
  k*H)` and §5.3 step 10 as `challenge_generation(Y, H, Gamma, U, V)` —
  the public key `Y` is ALWAYS `P1`, hashed alongside `H`/`Gamma` and the
  two "commitment" points. Skimming the surrounding prose (which mostly
  discusses `H`/`Gamma`/`U`/`V`) makes it easy to drop `Y` and build a
  4-point challenge instead — that would still round-trip against
  self-generated proofs (since both `prove` and `verify` would agree on
  the same, wrong, 4-point hash) but would fail against RFC 9381
  Appendix B.3's byte-exact vectors and would weaken the "trusted
  collision resistance" property (RFC 9381 §3/§7) the RFC's own security
  argument relies on `Y` being bound into the challenge. `ecvrf.zig`'s
  `challengeGeneration` takes exactly five 32-byte point encodings and
  every call site supplies `Y` (or `y_string`, its freshly re-encoded
  form) first.
- **Little-endian, throughout.** RFC 9381 §5.5 fixes this ciphersuite's
  `int_to_string`/`string_to_int` to RFC 8032 §5.1.2's convention — the
  OPPOSITE of ECVRF-P256-SHA256-TAI's big-endian I2OSP/OS2IP in the very
  same document. `point_to_string`/`string_to_point` need no conversion
  (`Edwards25519.toBytes`/`fromBytes` already speak this encoding); `c`
  (16 bytes) and `s` (32 bytes) inside `pi_string` are raw little-endian
  integers — `s` is byte-identical to an
  `Edwards25519.scalar.CompressedScalar`, and `c` is zero-extended on
  its HIGH end (`padChallenge`, appending 16 zero bytes after the 16
  challenge bytes) before any scalar-field arithmetic, matching
  little-endian zero-extension (append high zero bytes, not prepend).
- **`Y`/`PK_string` is always the canonical re-encoding.** RFC 9381's
  parameter list defines `PK_string = point_to_string(Y)` unconditionally
  — not "whatever octet string the caller passed in". `verify` therefore
  decodes the caller's `PublicKey` bytes to a point and re-encodes
  (`y_point.toBytes()`) before using that as BOTH `encode_to_curve_salt`
  and `ECVRF_challenge_generation`'s `P1`, exactly mirroring what `prove`
  does with its freshly-derived `Y = x*B`. For every canonically-encoded
  key (the only kind `validateKey`/`Edwards25519.fromBytes` accept as
  valid to begin with) this is a no-op and does not affect any vector;
  it only matters for a hypothetical non-canonical-but-decodable input,
  where re-encoding is the RFC-literal choice over trusting raw caller
  bytes.
- **`validate_key` is always TRUE.** RFC 9381 §5.3 lets an implementation
  support only one of `validate_key ∈ {TRUE, FALSE}`, as long as it
  documents which. This module supports only TRUE — `verify` always runs
  `ECVRF_validate_key` (§5.4.5: cofactor-clear the decoded public key,
  reject if the result is the identity element) before proceeding. No
  unvalidated-key verification path is exposed.

## Threat model / limits

- **Secret-scalar multiplication is constant-time — but NOT via std's
  `Edwards25519.mul`.** This bullet previously claimed `prove` got that
  property by "relying on std's primitive". That claim was **false**, and
  measurement is what caught it. `Edwards25519.mul` is constant-time in
  its ladder (4-bit fixed window, `cMov` table select, 64 unconditional
  iterations) but ends in `pcMul16`'s `try q.rejectIdentity()` — i.e.
  `if (q.x.isZero())`, a **branch on a value derived from the scalar**,
  which then propagates an error union that forces the caller to branch
  a second time. `prove`/`publicKey` did exactly that at five call sites
  (`catch @panic(...)` / `catch unreachable`), leaking whether the secret
  scalar `x` or the secret nonce `k` was zero mod the group order.
  The sibling module `ct25519` (`ct25519.mul`/`mulBase`) replaces it: std's
  own ladder with the trailing rejection removed, returning the neutral
  element as an ordinary value, no error union, so no call site can branch
  on the scalar at all. `ecvrf.zig` used to carry its own private copy of
  that ladder; it now depends on `ct25519` instead, so the same fix (and
  its correctness/timing test coverage) is shared with `voprf`, `opaque`,
  `signal` and `bulletproofs` rather than duplicated per module. No
  validation was dropped — see `ecvrf.zig`'s module doc comment for why the
  rejection was provably dead for `x` (clamping puts it strictly between
  `4L` and `5L`) and harmless for `k` (`validateKey` rejects a degenerate
  public key on the VERIFIER side, which is where that check belongs).

  **Verified, not asserted**, and since 2026-08-11 by a **committed
  program** rather than by numbers taken once by hand:
  [`src/ctgrind_harness.zig`](src/ctgrind_harness.zig), run by
  `scripts/ctgrind.sh ecvrf`. It marks the 32-byte secret key
  `MAKE_MEM_UNDEFINED`, forces a volatile reload, and drives it through
  `publicKey` + `prove`.

  **Full control table** (zig 0.16.0, valgrind 3.26.0, x86_64,
  ReleaseFast, 2026-08-11; `in-file` = memcheck CONTEXTS whose stack
  names `ecvrf.zig`):

  | `-fvalgrind` | sk tainted | total contexts | in `ecvrf.zig` | exit |
  |---|---|---|---|---|
  | yes | **yes** | 7 | **3** | 99 |
  | yes | no | 0 | 0 | 0 *(control)* |
  | **no** | yes | 0 | 0 | 0 *(trap)* |

  **The number the dependency on `ct25519` is actually about is zero**:
  `scripts/ctgrind.sh ecvrf --pattern 'ct25519|root[.]zig'` reports
  **0** contexts in the constant-time ladder, for all nine secret-scalar
  multiplications `publicKey`/`prove` perform. The remaining 4 of the 7
  total are inside the harness's own non-constant-time hex formatter —
  the propagation witness that makes that zero mean "no branch found"
  rather than "the taint never arrived".

  The three `ecvrf.zig` contexts are branches on `Y`/`H`, not on a
  secret. `Y` is the published public key and
  `H = encode_to_curve(PK_string, alpha)` is recomputed by every
  verifier from public inputs; they show up at all only because this
  harness taints `sk`, from which `Y` is derived, and memcheck has no
  notion of "public function of a secret". Their timing dependence on
  `alpha` is the separate, RFC-acknowledged try-and-increment property
  documented below. Located exactly (`--stacks`):

  - `ecvrf.zig:230` — `Edwards25519.fromBytes`'s validity branch inside
    `encodeToCurve`'s try-and-increment loop;
  - `ecvrf.zig:232` — that loop's `rejectIdentity() catch continue`;
  - `ecvrf.zig:344` — `prove`'s own
    `Edwards25519.fromBytes(h_string) catch unreachable`.

  *(Corrected 2026-08-11: an earlier version of this bullet said all
  three were "inside `encodeToCurve`". The third is in `prove` itself —
  same conclusion, since it decodes the same public `H`, but the stated
  location was wrong. It also claimed a re-run "with `Y` explicitly
  declassified reports 0 errors / 0 contexts"; that run is not
  reproducible from outside the module, because `prove` recomputes `Y`
  internally from `sk`, so there is no seam at which a caller can
  declassify it. The `--pattern` measurement above is what replaces it,
  and it pins the stronger of the two claims.)*

  **Teeth, measured 2026-08-11.** Re-creating the historical defect —
  pointing `prove`'s three secret-scalar multiplications back at
  `std.crypto.ecc.Edwards25519`'s ladder, whose trailing
  `rejectIdentity` branches on a scalar-derived value — moves the table
  from **7 total / 3 in `ecvrf.zig`** to **12 / 8**, with the
  `edwards25519.zig` attribution going 2 → 7. That is the same shape as
  the "before" figure this bullet used to quote from memory (11 errors /
  10 contexts), and it is now reproducible. Reverted; `cmp` against a
  pre-mutation copy confirmed byte-identical.

  What is still NOT hardened: the SHA-512 framing and byte copies around
  those calls, beyond what std's own primitives provide.
- **`verify` is deliberately variable-time** — `mulDoubleBasePublic`,
  `Edwards25519.fromBytes`/`neg`, and the final byte comparison all
  operate on public inputs only (the public key, the input `alpha`, and
  the proof under test), mirroring `std.crypto.sign.Ed25519`'s own
  verifier and this repository's `bip340`/`xeddsa`/`adaptor` convention.
- **Try-and-increment's timing depends on `alpha_string`.** RFC 9381
  §5.4.1.1 itself warns: "this algorithm SHOULD be avoided in
  applications where it is important that the VRF input alpha remain
  secret." `encodeToCurve`'s loop count (typically 1-2 iterations, per
  the RFC's own analysis) leaks through timing whether `alpha` is
  chosen such that early counters succeed or fail — a non-issue for
  every use case RFC 9381 itself motivates (leader election, NSEC5),
  where `alpha` is public by construction, but a real constraint if
  this module is ever repurposed with a secret `alpha`.
- **`decodeProof` does not subgroup-check `Gamma`.** RFC 9381 §5.4.4
  does not ask for one (only "`Gamma` decodes to a valid curve point"
  and "`s < q`") — a `Gamma` in a low-order subgroup is caught
  downstream by `ECVRF_verify`'s challenge comparison failing (a forged
  low-order `Gamma` cannot satisfy `V = s*H - c*Gamma` for a `c` that
  also matches `U = s*B - c*Y`, absent breaking the discrete-log
  assumption), matching the RFC's own design — not a gap relative to
  the spec, but worth stating since `Y` (the actual public key) DOES get
  an explicit low-order check (`validateKey`) while `Gamma` (part of the
  proof, not the key) does not.
- **`s` is checked non-canonical (`s >= q` rejected, RFC 9381 §5.4.4
  step 8) but `c` is not range-checked beyond its fixed 16-byte width**
  — `c < 2^128` structurally (it is exactly `cLen` bytes), always `< q`
  (`q ~ 2^252`), so no separate canonicality check is meaningful or
  required for `c`.
- **Secret material is zeroed after use.** `expandSecretKey`'s clamped
  scalar `x` and the SHA-512 `prefix`/intermediate 64-byte digests
  touched by `prove`/`nonceGeneration` are `std.crypto.secureZero`'d via
  `defer` — best-effort hygiene against process-memory scraping, not a
  guarantee against a determined local attacker (no memory locking /
  `mlock`, matching this repository's other secret-scalar-handling
  modules, e.g. `xeddsa.zig`).
- **Degenerate-key/nonce panics are probability-~2^-252 events, not
  attacker-reachable.** `publicKey`/`prove` `@panic` if the clamped
  secret scalar or the derived nonce reduces to `0 mod q` — the same
  posture `xeddsa.zig`'s `calculateKeyPair`/`sign` take for the
  analogous cases, and RFC 9381 itself gives no "then what" for these
  (they are not part of the "output INVALID" fail-closed surface, which
  is reserved for attacker-controlled inputs to `verify`, not a
  key-holder's own degenerate secret material).

## Out of scope (this module)

- **ECVRF-P256-SHA256-TAI / -SSWU** (RFC 9381 §5.5) — the NIST P-256
  ciphersuites. Would need `std.crypto.ecc`'s P-256 support plus SEC1
  point compression/decompression (`point_to_string`/`string_to_point`
  per SEC1 §2.3.3/§2.3.4) — a real but separate piece of work, not
  attempted here.
- **ECVRF-EDWARDS25519-SHA512-ELL2** (RFC 9381 §5.5, `suite_string =
  0x04`) — same curve and hash as this module, but `encode_to_curve` via
  RFC 9380's Elligator2 map instead of try-and-increment.
  `Edwards25519.fromUniform`/`elligator2` already exist in std (used
  internally by std's own `fromString`), so this would be a
  comparatively low-effort follow-up module — genuinely deferred, not
  ruled out.
- **RSA-FDH-VRF-SHA256/384/512** (RFC 9381 Appendix A) — an entirely
  different, non-elliptic-curve VRF construction (RSA full-domain-hash
  signatures under the hood). Would reuse this repository's `rsa`
  module's primitives but is a distinct algorithm family, not a
  ciphersuite variant of ECVRF.
- **Batch verification** — RFC 9381 does not define one for ECVRF (unlike
  Schnorr/EdDSA, where batching multiple `sB - cA` checks is a common
  optimization); not attempted here.

## Verification

- `zig build test-ecvrf` (Debug) and `zig build -Doptimize=ReleaseFast
  test-ecvrf`: **all tests pass in both modes** (verified 2026-07-16).
  `zig fmt --check modules/ecvrf/` is clean.
- Byte-exact KATs: RFC 9381 Appendix B.3's three official
  ECVRF-EDWARDS25519-SHA512-TAI vectors (Examples 16/17/18), each
  checked at every layer the RFC publishes an intermediate value for —
  `SK -> x` (`secretScalar`), `SK -> PK` (`publicKey`), `(PK, alpha) ->
  H` (`encodeToCurve`, including an independent re-derivation of the
  published `try_and_increment` counter), `(SK, H) -> k_string -> k`
  (`nonceGenerationString`/`nonceGeneration`), `(SK, alpha) -> pi`
  (`prove`, the full 80-byte proof), `pi -> beta`
  (`proofToHash`/`verify`) — plus negative/tamper tests RFC 9381 does
  not itself publish: independently flipping a byte inside `Gamma`/`c`/
  `s` (each of `pi`'s three fields), a wrong `alpha`, a non-canonical
  `s` caught at `decodeProof`, and small-order/identity public keys
  caught at `validateKey` — every one rejects cleanly (`error.
  InvalidProof`/`error.InvalidPublicKey`), never a panic on
  attacker-controlled input.
