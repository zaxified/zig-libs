# cbor — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
