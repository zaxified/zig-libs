# k256 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
