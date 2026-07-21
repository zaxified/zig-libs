# cbor — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: RFC 8949 / RFC
9052 are public specifications; clean-room, no third-party implementation ported or consulted
(CONVENTIONS.md §5 merger doctrine — no NOTICE entry).

## Design & invariants

- **`Value`** is a tagged union over all 8 RFC 8949 major types: `uint`/`negint` (integers, negint
  stores the unsigned magnitude `n` where the real value is `-1 - n`, avoiding the need for an
  `i65`), `bytes`/`text`, `array`/`map` (`map` is an ordered `[]MapEntry`, insertion/wire order
  preserved — CBOR does not require unique keys and this type doesn't enforce it), `tag`
  (`{number: u64, value: *const Value}`), and major-type-7's `simple`/`bool`/`null_value`/
  `undefined_value`/`f16`/`f32`/`f64`. Everything a `decode()` call returns is allocated via the
  caller's `allocator` (dupe'd from the input for byte/text strings, freshly built for
  array/map/tag) — the input `bytes` slice does not need to outlive the call, unlike some
  arena-borrowing modules in this collection (`jsonshape`) that alias the parse input.
- **Decode is a straightforward recursive-descent** over the major-type/additional-info header
  structure (`Decoder.decodeValue`), with one dispatch table per concern: `readArgFull` (argument
  parse, reporting `.indefinite` for additional-info 31 on the four major types that allow it),
  `readByteString`/`readTextString` (definite: one bounds-checked slice+dupe; indefinite: chunk
  loop, `Malformed` if a chunk is the wrong major type or itself indefinite — chunks may not
  nest per RFC 8949 §3.2.3), `readArray`/`readMap` (definite: loop `n` times; indefinite: loop
  until `0xff`), `decodeSimpleOrFloat` (major 7's many sub-cases, including rejecting the
  non-canonical/invalid 1-byte-argument encoding of small simple values <32 per §3.3).
- **Untrusted-input hardening is structural, not a bolted-on limit:**
  - **Depth cap** (`DecodeOptions.max_depth`, default 64) checked once per `decodeValue` call,
    incremented on every array element, map key, map value, and tag payload — covers the general
    depth-bomb case (deep array nesting) and the map/tag variants, not just arrays.
  - **No pre-allocation from a declared length.** `readBytes(len)` bounds-checks `len` against
    `self.bytes.len - self.pos` (the *actual* remaining input) before ever calling the allocator —
    a `u64` length of `2^64-1` costs one comparison. Array/map element counts are never
    `alloc(T, n)`'d up front; `readArray`/`readMap` `std.ArrayList.append` one decoded element at a
    time, so a bogus huge declared count `n` is bounded by how many complete elements the actual
    input bytes can supply (each element decode consumes ≥1 real byte and fails `Truncated` at
    EOF) — never by `n` itself.
  - **Fail-closed typed errors.** `DecodeError` is a closed set (`Truncated`, `Malformed`,
    `DepthLimitExceeded`, `TrailingGarbage`, `OutOfMemory`); no code path panics or performs an
    out-of-bounds read on malformed input — verified by the hostile-input KATs (truncated header,
    declared-length-exceeds-input, depth bomb, trailing garbage, reserved additional-info,
    bare `break`, wrong-major-type indefinite chunk, invalid UTF-8) plus an arbitrary-bytes fuzz
    test (`std.testing.fuzz`) in `kat_test.zig`.
  - **Text strings are UTF-8 validated** on decode (`std.unicode.utf8ValidateSlice`), both definite
    and per-chunk for indefinite — RFC 8949 §3.1 requires major-type-3 content to be valid UTF-8.
- **Encode is definite-length + shortest-form by default** (RFC 8949 §4.1 "preferred
  serialization" — `writeHead` picks the smallest additional-info form for the argument), matching
  every "roundtrip: true" row of the RFC 8949 Appendix A table byte-exact without needing the
  `canonical` option. `EncodeOptions.canonical = true` adds RFC 8949 §4.2.1's map-key rule:
  entries are re-ordered by the bytewise order of their own *encoded* key bytes (`encodeMap` builds
  each key's encoding once via a scratch buffer, sorts `(key_bytes, entry)` pairs with
  `std.mem.sort` + `std.mem.order`, then emits key-bytes-then-encoded-value in that order). Two
  positive-control tests assert the exact byte sequence for both the un-sorted (default) and
  sorted (canonical) encodings of the same map — not just "output changed" — so a broken/absent/
  reversed/numeric-instead-of-bytewise sort fails the test (`kat_test.zig`).
- **What `canonical` does *not* cover** (documented, not silently missing): float-width
  minimization (RFC 8949 preferred serialization also allows shrinking a float to the shortest
  width that round-trips exactly; this module's `Value.f16`/`.f32`/`.f64` always re-encodes at its
  own width) and bignum/tag-2/3 canonicalization. `canonical` here means exactly "map keys sorted
  bytewise", not a full RFC 8949 §4.2.1 conformance claim beyond that.
- **Concurrency:** reentrant, no shared state; pure logic, no I/O.

## COSE layer (`cose.zig`)

- Thin typed layer over `cbor.Value` — `parseKey`/`parseSign1` walk an already-decoded `Value`
  (they never call `cbor.decode` themselves and allocate nothing; returned slices borrow the
  `Value` tree), `encodeEc2Key`/`encodeOkpKey`/`encodeSign1` build a `cbor.Value` (or, for
  `encodeSign1`, call `cbor.encode` directly) ready to hand to `cbor.encode`.
- **Label lookup** (`mapGet`/`labelMatches`) uses `Value.toI64` to match a map key against a signed
  COSE label regardless of whether it's encoded as `uint` (non-negative labels like `kty`=1) or
  `negint` (negative labels like `crv`=-1) — COSE labels are RFC 9052/9053 registered small
  integers on both sides of zero.
- **EC2** (RFC 9053 §7.1: kty=2, params crv=-1/x=-2/y=-3) and **OKP** (§7.2: kty=1, crv=-1/x=-2,
  no `y`) are the only key types modeled; `parseKey` returns `error.UnsupportedKty` for anything
  else (RSA, symmetric). Field `x`/`y` are opaque big-endian byte slices — not curve-validated
  here, matching `ctap2pin`'s `PublicKey{x,y}` design (the consuming curve module, e.g. `p256`'s
  `Fe.fromBytes`/`fromAffineCoordinates`, does that validation).
- **`d` (private key, label -4) is never referenced anywhere in this module** — a deliberate scope
  boundary, not an oversight: this is a verifier/public-key-consumer layer.
- **`COSE_Sign1`** (`parseSign1`/`encodeSign1`): the bare 4-element array `[protected, unprotected,
  payload, signature]` (RFC 9052 §4.2); `parseSign1` also accepts the same array wrapped in tag 18
  without checking the tag number (a caller that cares can inspect `value.tag.number` first).
  `sigStructure` builds the exact `Sig_structure` bytes (§4.4: `["Signature1", protected,
  external_aad, payload]`) a signature algorithm signs/verifies over — this module goes no further;
  the signature math is the sibling curve modules' job.

## Threat model / out of scope

`decode` is the security boundary — it is the only function in this module that touches untrusted
bytes, and it is fail-closed (typed `DecodeError`, never a panic/OOB — see hardening above).
`encode`/the `cose` layer operate on caller-constructed or already-decoded `Value` trees and are
not re-validated against a "misuse" contract (e.g. `Value.simple` outside `0..19 ∪ 32..255`, or a
`cose.Ec2Key` with a non-32-byte `x`/`y`, are programmer errors, not hostile input — `decode` itself
never produces such a `Value`, so this only matters for hand-built trees). No cryptographic
operation is implemented or claimed here: `cose.sigStructure` produces bytes to be signed/verified
by a different module; this module does not check a signature, does not validate a certificate
chain, and does not enforce any policy over `alg`/`kty`/`crv` values (an unlisted `alg` still
round-trips as a raw `i64` — see `cose.zig`'s doc comment on the algorithm-identifier constants
being "a selection", not a closed enum).

## Verification

RFC 8949 Appendix A, cross-checked against the community `cbor/test-vectors` repository's
`appendix_a.json` (a direct machine-readable transcription of the RFC table, not hand-typed from
memory) — every row decodes to its documented value; every "roundtrip: true" (definite-length,
shortest-form) row also re-encodes byte-exact; every "roundtrip: false" (indefinite-length) row is
checked to decode to the identical logical value as encoding+re-decoding it through this module.
Two canonical-encoding positive controls assert the *exact* byte sequence of both the default
(insertion-order) and `canonical = true` (bytewise-sorted) encodings of the same non-trivial map.
Nine hostile-input cases (truncated multi-byte header, declared array/byte-string length exceeding
available input, a 200-deep nesting bomb against the default 64-deep cap — plus a sanity check that
ordinary shallow nesting still succeeds, trailing garbage, reserved additional-info, bare `break`,
wrong-major-type indefinite chunk, invalid UTF-8, empty input) each assert the specific typed
`DecodeError`, plus an arbitrary-bytes `std.testing.fuzz` test asserting decode never panics.
`cose.zig` adds its own KATs: EC2/OKP `COSE_Key` round-trip (including a byte-identical re-encode
check) using the ctap2pin-style field layout, missing-field/unsupported-kty error cases, and
`COSE_Sign1` round-trip (including a detached-payload and a tag-18-wrapped variant) plus a
`Sig_structure`-shape check. Verified green in Debug and ReleaseFast; `zig fmt --check modules/cbor`
clean. Run: `zig build test-cbor`.

## Backlog / deferred

See README "Deferred": indefinite-length round-trip fidelity, float-width minimization, bignum
arithmetic, and COSE scope (`COSE_Mac0`/`COSE_Encrypt0`/multi-signer `COSE_Sign`, RSA/symmetric key
types, private-key material) are all out of scope for this pass — see README for the per-item
rationale.

## Status

`extract · any · codec · reentrant` + deps: none (std only) — canonical source is `pub const meta`
in src/root.zig.
