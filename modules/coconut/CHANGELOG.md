# coconut — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: the `coconut-crypto` cross-check of the PS core and threshold aggregation moves from "Where we are behind" to "Where we are ahead".
- **2026-10-05** — Mutation run: 30 of 36 killed, 6 equivalent; 7 tests added and
  1 extended (the σ₁' = 1 universal forgery, a ν and an `s` with an order-3
  component, the proof's own mask, extra disclosed values, a zero `r'` draw,
  every `ShowProof.fromBytes` refusal, `signPartial`/`aggregateCredential`
  input refusals, a zero Lagrange node, mismatched vk shares). No code change.
- **2026-10-03** — `decodeG1`/`decodeG2` rely on `bls12_381`'s checked decoders, which
  now refuse a point outside the subgroup themselves (the hole of `c8d601e7` closed
  at the source).
- **2026-10-03** — **BREAKING (API + transcript):** the show proof is bound to the
  verifier, and the verifier states what it asked for. `proveCredential` /
  `proveCredentialSeededForTest` take a trailing `context: []const u8` (the verifier's
  nonce, session id and name), hashed into the challenge right after the DST; the DST
  is now `…SHOW-V02_CHALLENGE_`, so V01 proofs no longer verify. `verifyCredential`
  takes `disclosed` (the mask the verifier asked for) before `disclosed_values` and
  `context` after it; a proof revealing a different set returns `false`. Before, the
  mask came from the proof: a gate expecting attribute 0 accepted a proof revealing
  attribute 2 with the same value, and any recorded show replayed to any verifier of
  the same authority set. Migration: add the two arguments at every call; issue a
  fresh nonce per show and refuse repeats. Relation audit MED items 1–2.

- **2026-10-03** — **⛔ Security fix: no subgroup check → universal forgery.** Every
  `G1`/`G2` point a credential or show proof carries was decoded with
  `fromBytesCompressed`, which checks the curve only. A point `T` whose order divides
  the `G1` cofactor is invisible to the pairing (the ate pairing is a power of the
  reduced Tate pairing, trivial on `[r]E`), so `σ = (T, 1)` passed `psVerifyPlain` for
  every key and every attribute vector, and a show proof built from public data alone
  (`σ₁' = T`, `σ₂' = ν = 1`, blinding `r = 0`) passed `verifyCredential` — no
  authority needed. Now `Credential`/`PartialCredential`/`ShowProof.fromBytes` refuse
  points outside the subgroup (`error.InvalidEncoding`), `psVerifyPlain` and
  `verifyCredential` check every point again (in-memory structs never pass a
  decoder), and `signPartial` refuses an `h` outside `G1` or the identity (`[e]T`
  would hand out the signing exponent mod the order of `T`). Regression test builds
  both forgeries; with the verify check removed it fails on `ShowForgeryAccepted`.
  Found by the 2026-10-03 relation audit. ⚠ Behaviour change: inputs that used to
  decode now return `error.InvalidEncoding`; none of them could come from an honest
  party.

- **2026-09-30** — **NO CONSUMER-VISIBLE CHANGE:** the Pointcheval-Sanders core and threshold aggregation are now cross-checked against the foreign `coconut-crypto` 0.14 (`src/interop_test.zig`, vectors from `tools/vectors`): our `psVerifyPlain` accepts foreign aggregated credentials, `aggregateCredential`/`aggregateVerificationKeys` reproduce the foreign aggregate sigma and group key byte for byte (2-of-3, 3-of-5, q = 1..4, several subsets). The show-proof NIZK stays SELF. Anchor grade oracle SELF -> MIXED.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **authority_sign 69 / user_issue 3 / user_show 51**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. No constant-time claim exists in `SPEC.md` or `README.md`; nothing was added. Three targets split by which party holds the secret (authority key share, user attributes at local commitment, user attributes plus blinding at proof showing). ⭐ Independently reproduced `bls12_381`'s `ctSelect` finding with the identical disassembled sequence `bt %esi,%edx; jae` — the second witness that turned it from one measurement's surprise into a settled result. ⭐ This agent also added the campaign's third context class: **over-taint artifact** — `ff.zig`'s `conditionalAdd`/`conditionalSub`/`limbsCmpLt` are real `je`/`jne` but branch on a limb COUNT or a Montgomery-form FLAG, not on the secret's value, and light up only because the harness taints the whole opaque `Fe` struct including its metadata (as `bls12_381`'s own harness also does). ⚠ Not adjusted for single-process over-taint either.

- **2026-09-07** — `fuzzShowProofDecode` had only ever decoded the empty slice. It drew its
  bytes with `smith.bytes(&buf)` and then took a length from
  `smith.valueRangeAtMost(u16, 0, 1024)`; a ranged `Smith` draw reads eight octets as a
  little-endian `u64` and returns the range MINIMUM when fewer remain, and `bytes` had already
  consumed them — so `len` was 0 on every input and `ShowProof.fromBytes` refused on its
  `bytes.len < 2` line. The "attacker-controlled count vs. actual buffer length" surface the
  harness's own comment describes was never entered once. Now one `smith.slice(&buf)` call,
  plus an eight-seed corpus built through the module's own `toBytes` (a valid `ShowProof`
  carries four compressed group elements and three `Fr` scalars, so nothing hand-written gets
  past `g1.fromBytesCompressed`) covering the round-trip encoding, a short encoding, an
  out-of-range `disclosed` octet, a `q` of `0xFFFF` against the real length, `q = 0`, an extra
  scalar, an all-zero body and a two-octet stub. Measured: **0 of 8 seeds non-empty, 0 proofs
  decoded and 0 disclosure octets walked before; 8 of 8 non-empty, 1 decoded, 3 disclosure
  octets walked and 7 typed errors after.**

- **2026-08-12** — **BREAKING:** `keygen` and `proveCredential` take `io: std.Io` instead of
  `random: std.Random`, and draw from `std.Io.random` — contractually a
  CSPRNG. The old shape did not merely permit the mistake, it *taught* it:
  `keygen`'s doc comment said "seed it for deterministic tests" with nothing
  saying "and never in production". A consumer who followed that advice
  shipped an authority master secret `(x, y₁…y_q)` that is a pure function of
  the seed — anyone who recovers the seed issues arbitrary valid credentials
  for the whole system, and the `t`-of-`n` threshold split becomes decoration
  because the dealer's secret never had to be reassembled from shares. On the
  show side, witness nonces that repeat across two proofs let a verifier who
  sees both extract the HIDDEN attributes and the blinding `r` by the standard
  two-transcript Sigma-protocol argument, i.e. exactly the privacy selective
  disclosure exists to provide.

  The guarantee is now at the type: a `std.Random.DefaultPrng` is not
  expressible at a `std.Io` parameter. This is the `bbs`/`ibe`/`tlock` shape.

  **Migration:** obtain an `Io` (`std.Io.Threaded.init(gpa, .{})` then
  `.io()`) and pass it where the `std.Random` used to go. Coconut has no
  published byte-exact test vector (`SPEC.md` §3), so no consumer needs a
  deterministic issuance; test suites that do can call the new
  `keygenSeededForTest` / `proveCredentialSeededForTest`, whose names are the
  signal. New public `Entropy` union backs both paths.
- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on `asonnino/coconut` (Python) /
  `nymtech/coconut` (Rust/Go) — no byte-exact vector exists for Coconut; anchored
  internally on the deterministic PS pairing-verify identity (design reference, not a
  test anchor).
