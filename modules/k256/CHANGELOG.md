# k256 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-11** — **BREAKING:** `Fe`'s backing field renamed `limbs` ->
  `_limbs` (audit F8, LOW). The old name was a plain public struct member,
  so any code could construct `Fe{ .limbs = raw }` and bypass every
  canonicalizing constructor (`fromBytes`, `fromInt`, arithmetic ops),
  silently violating `Fe`'s own documented invariant ("always canonical
  between operations") — measured: `isZero()`/`isOdd()` gave the wrong
  answer for a raw, non-canonical value. Zig has no field-level privacy, so
  this is the same leading-underscore "internal, don't construct directly"
  convention already used elsewhere in this repo, not a compiler-enforced
  guarantee — but it does mean any code (in or out of this repo) spelling
  `Fe{ .limbs = ... }` will now fail to compile. No in-repo consumer of the
  11 that depend on this module ever touched the field directly (verified
  by grep, before and after); all 11 re-run green.
- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** added Wycheproof ECDSA
  secp256k1/SHA-256 verification vectors (audit G3, MED) — this module
  shipped zero ECDSA test vectors of its own (only BIP340 Schnorr vectors).
  357 vectors (234 P1363 + 123 Bitcoin/low-S), run against `sign.ecdsaVerify`
  and `sign.ecdsaVerifyLowS` in `wycheproof_kat_test.zig`. Third-party data
  under Apache-2.0, attributed in `NOTICE`; generator is
  `modules/k256/tools/gen-k256-wycheproof.py`, mirroring the sibling `p256`
  module's own Wycheproof fixture. No production code changed; the point of
  this entry is the fixture existing, not a behaviour change.

- **2026-09-09** — Licensing: added `NOTICE` (kind `third-party attribution`). No code changed,
  but a source comment was corrected. This module reproduces two bodies of published values and
  had a record for neither: BIP340's own test vectors (`src/kat_vectors.zig`, BSD-2-Clause,
  author Pieter Wuille) and BOLT#11's first worked example (`src/ecdsa_recover.zig`'s
  `spec_privkey`/`spec_node_id`/`spec_hash`/`spec_r`/`spec_s`, `lightning/bolts`, CC-BY 4.0).
  The only statement about the first was a `see ../../NOTICE` that resolved to a file which has
  never existed. ⛔ The second was described in-source as "a test oracle under NOTICE policy §0";
  it is not — §0's carve-out is for a program that was RUN, and it says explicitly that numbers
  read out of an upstream source file are reproduced data. That reading also put this module on
  the opposite side of `lnwire`'s and `lninvoice`'s answer about the identical upstream. Both
  licences are now reproduced or linked as their terms require, and the comment says so.
- **2026-09-08** — Test-only follow-up to the 2026-09-07 entry below, which
  fixed one knob per harness and left a second one dead. `fuzzFromSec1`'s tag
  selector has a `4 =>` branch that draws an ARBITRARY octet with
  `smith.value(u8)`, and no seed carried the word that draw reads — so it read
  an exhausted input and returned the range minimum, `0x00`, on every replay.
  The seed labelled "an arbitrary tag octet" was therefore byte-identical in
  effect to the `tag == 0` seed beside it, while the guard test recorded the
  branch as taken, because `tags_seen[4]` says the branch RAN and says nothing
  about what it drew. Two seeds now carry that word (`0x99`, and `0x02` over a
  body that matches it), and the guard pins the number of distinct octets the
  branch actually wrote. `fuzzFeFromBytes`'s two inner boundary knobs
  (`offset`, `plus`) were already alive but only pinned indirectly through
  `accepted`; they are now counted and pinned in their own right. No API,
  wire or production change.

- **2026-09-07** — Test-only, no production change: all three fuzz targets ran one input,
  and two of them had branches that had never executed. `fuzzFromSec1` and
  `fuzzBip340Verify` each opened `smith.bytes(...)` and then drew a length with
  `smith.valueRangeAtMost`; a ranged `Smith` draw reads eight octets as a little-endian
  `u64` and returns the range MINIMUM when fewer than eight remain, and `bytes` had already
  eaten them - so `fromSec1` was handed a zero-length slice every round with the point
  unread in `buf`, and `bip340Verify`'s message, which participates in the challenge hash
  and which the harness's own comment says is "fuzzed independently", was the empty string
  every round. Both now draw with `smith.slice`. `fuzzFeFromBytes` was the sharper one: its
  four knobs are all drawn AFTER `smith.bytes`, so with the input exhausted every
  `smith.value(bool)` returned false - the `p` / `p-1` / `p+1` boundary bias the harness's
  comment is entirely about had **never run once**, and neither had the little-endian
  loader. Corpora added for all three, built from the module's own
  `toCompressedSec1`/`toUncompressedSec1`/`bip340Sign` (a secp256k1 point or a verifying
  Schnorr signature is not reachable from arbitrary bytes), each seed carrying the `u64`
  tail its knobs read. Measured by the three new `corpus:` guards - SEC1: 9 non-empty
  seeds, 4 accepted, **3 distinct points**, four of the six tag branches exercised; BIP340:
  1 signature accepted and **188 message octets entering the challenge hash** (0 before);
  `Fe.fromBytes`: **3 boundary inputs and 2 little-endian loads** (0 and 0 before), 4
  accepted. A note for the next author: the `Fe` seeds were first written with
  `testkit.fuzz.seed`, which prepends the `u32` length `Smith.slice` reads - but that
  harness opens with `smith.bytes`, which reads no header, so the prefix shifted the whole
  payload and every knob still read false. The guard's `boundary` count is what caught it.

- **2026-08-13** — Neither BREAKING nor BEHAVIOURAL: **no shipped code path changed**,
  and every number the module publishes about itself is the same as before. What
  changed is the evidence. (a) A test with teeth for the deterministic nonce:
  `ecdsa_recover.zig` now pins BOLT#11's first worked example byte-exact
  (`sign` → the published `(r, s, recid)`). Until now, replacing `rfc6979Nonce`
  with a constant — private-key recovery from any two signatures — left all 34
  of this module's tests green at exit 0; the only red in the repository was the
  consumer `lninvoice`. Measured: that mutation now fails this module's own
  suite, and nothing else in it. (b) A fifth ctgrind target, `ecdsa`, for
  `ecdsa_recover.sign` — a shipped secret path that had no target and was not on
  the harness's "deliberately not pinned" list either. It measures 15 contexts /
  10 in-file, all itemised in `SPEC.md`; the RFC 6979 §3.2 nonce-retry branch
  among them is now documented at the source with its ≈2^-127 probability
  instead of being invisible. (c) `SPEC.md` and the harness doc comment
  corrected where they disagreed with what the harness actually prints: the
  group contexts are at `group.zig:277`/`:346`, not `:75`; 9 of `sign`'s 11 are
  not `rejectIdentity`; and `bip340Sign` never calls `Secp256k1.mul`, so its two
  group contexts are `group.zig:346` twice. (d) `normalize`'s `blackBox`
  barriers are now shown load-bearing by measurement (28 new contexts when they
  alone are removed); `Fe.sub`'s single barrier is recorded as having **no**
  such measurement behind it.
- **2026-07-28** — New `k256.ecdsa_recover` — RFC 6979 deterministic-nonce ECDSA signing
  and public-key recovery (`Q = r⁻¹(sR - eG)`), moved here from the
  sibling `lninvoice` module, which had implemented them locally because
  `k256` shipped only Schnorr and ECDSA *verify*. `lninvoice` re-exports
  them, so its callers are unaffected; the algorithm is unchanged.
- **2026-07-21** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against
  BIP340's published test vectors.
- **2026-07-18** — Performance: gained an asm/Montgomery core (part of a collection-wide
  performance campaign that also covered the sibling `p256`/`montint`
  modules; the root changelog records no further detail than this).
