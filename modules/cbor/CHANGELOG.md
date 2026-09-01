# cbor — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-01** — Security audit (extended scope, `cbor` + the `cose` sub-layer).
  **Remote CPU DoS, fixed:** `cose`'s duplicate-label check compares every pair of entries,
  and its input comes off the wire — `webauthn` hands `parseCredentialKey` the unbounded tail
  of a client-supplied `authData`. Measured in ReleaseFast, one call: 24 KB of input cost
  22 ms, 96 KB cost 370 ms, 768 KB cost **26 seconds** of one core, the cost quadrupling for
  every doubling while `decode` stayed linear. Bounded by `cose.max_map_entries` (256, about
  thirty times any legitimate COSE map) rather than by making the scan asymptotically
  cleverer, which keeps `parseKey`/`parseSign1` allocation-free as documented. After the fix
  the same 768 KB input costs 0 µs.
  **AKP key confusion, fixed:** `parseKey` bound an AKP key's REQUIRED `alg` to nothing. A key
  declaring ML-DSA-87 with ML-DSA-44's 1312 bytes was accepted, and the natural consumer
  expression — the one this module's own KAT writes — is then a 1280-byte out-of-bounds read
  in ReleaseFast, straight into a signature verifier. Not inferring the parameter set from the
  length was correct and deliberate; it is not the same as not checking it, and the sibling
  `jwt`, on the JOSE half of the same RFC 9964, has checked it since it landed. Lengths now
  come from `std.crypto.sign.mldsa`'s own types rather than transcribed literals, and
  `akpPublicKeyLen` is exported so a consumer with an unlisted `alg` can apply the same rule.
  A key may also no longer claim another family's algorithm (`AlgKtyMismatch`), which is the
  rule `jwt` already applies; an `alg` this module does not register still round-trips.
  **Leak, fixed:** `encode` had no `errdefer` on its output buffer, so any failure inside
  `encodeInto` — or in `toOwnedSlice`'s own final resize — abandoned every byte already
  produced (129 allocated, 0 freed, on both the plain and the canonical path). Third instance
  of this class here after `decode`'s partial tree and `encodeMap`'s canonical scratch, and
  the last unguarded entry point.
  **Duplicate labels are now detected for non-integer labels too.** RFC 9052 §3 says *labels*,
  not integer labels: a duplicated `tstr` label, or a duplicated integer above `maxInt(i64)`,
  compared as unequal and reached the caller in `Sign1.unprotected`, where a first-wins
  consumer resolves it.
  **Guards that held nothing, now pinned** — each verified by a red mutation: `peekByte`'s
  bound (relaxing it is a silent one-past-end read in ReleaseFast whose value then steers
  decoding; `readBytes` got this boundary test in 2026-08 and `peekByte` did not),
  `readMap`'s errdefer paths under *allocator* failure rather than wire failure (`readArray`'s
  equivalent was covered, `readMap`'s was not), `14ef4331`'s own canonical-scratch leak fix
  (previously caught only by the example's leak-checking allocator, so a plain
  `zig build test-cbor` showed green), duplicate labels at a distance greater than one, the
  AKP `pub` length and its missing/wrong-typed cases, an over-long `COSE_Sign1` array, `toI64`
  at the signed boundary, `writeHead`'s shortest-form width boundaries, major-7 reserved
  additional-info 28–30, and the nested-indefinite-chunk rejection.
  **Documented:** `max_depth` is a public knob whose recursion is what the cap protects —
  measured, raising it to a "generous" value replaces a typed `DepthLimitExceeded` with a
  SIGSEGV (Debug 8192, ReleaseFast 32768 on an 8 MiB stack). SPEC named EC2/OKP as the only
  modelled key types and named only `-4` as the private label, when AKP's `priv` sits at `-2`
  — the same number that means `x` under a different `kty`. The example claimed to show what
  a COSE consumer does and never touched the COSE layer; it now parses RFC 9052 C.2.1,
  confirms `protected` comes back as the original bytes, and checks `Sig_structure` against
  the bytes `cose-wg/Examples` publishes.
  All four external anchors re-verified against their sources: RFC 9964 Appendix A.2 (12/12
  fields), `cose-wg/Examples` sign-fail-01 and sign-pass-02 (4/4), and `cbor/test-vectors`
  `appendix_a.json` (81/82 — the one omission is `f818`, which this module documents and
  rejects, and RFC 8949 §3.3 and its Appendix A both confirm that is right).

- **2026-08-23** — `encode` with `EncodeOptions.canonical` no longer leaks. The
  canonical path allocates a scratch array of `(encoded key, entry)` pairs to
  sort map entries by encoded-key bytes, plus one buffer per key, and freed
  neither — so every canonical encode of a map leaked, on the first call, for
  any caller not using an arena. Found by running the new
  `example/main.zig` under `DebugAllocator`; the module's own canonical-map
  tests could not see it, because they run on an `ArenaAllocator`, which frees
  everything regardless. Confirmed by mutation: with the fix removed,
  `zig build test-cbor` still passes and `zig build run-example-cbor` reports
  three leaked allocations.

- **2026-08-22** — `cose.parseKey` accepts the AKP key type (RFC 9964 §3,
  `kty` 7), with the ML-DSA algorithm identifiers -48/-49/-50 and a new
  `Key.akp` variant carrying the required `alg` and the raw `pub` bytes.
  `alg` is required rather than optional here because RFC 9964 makes it so:
  an AKP key's bytes are formatted by whatever `alg` says, and the parameter
  set is never inferred from the key length.

  This changed how `parseKey` reads a key, and the reason is worth keeping:
  **COSE parameter labels are scoped to the key type.** Label -1 is `crv` for
  EC2/OKP and `pub` for AKP, so nothing below -1 may be read before `kty` is
  known. `parseKey` used to read `crv` and `x` up front for every key type;
  those reads now live inside their branches. A test pins it by parsing a real
  AKP key whose -1 is a 1312-byte string rather than a curve identifier.

  Anchored on RFC 9964 Appendix A.2: all three published `COSE_Key` examples
  parse, and the `pub` each yields verifies that example's own signature over
  its own `Sig_structure` bytes -- so the parse and the cryptographic use are
  pinned together rather than separately.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  8949 Appendix A's published test vectors.
- **2026-07-21** — New module: CBOR (RFC 8949) codec — decode/encode all 8 major types,
  definite + indefinite length, a `canonical` deterministic-encoding option (§4.2.1
  bytewise map-key sort); untrusted-input hardened.
