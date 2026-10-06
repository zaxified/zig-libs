# decaf448

The decaf448 prime-order group (RFC 9496, "The ristretto255 and decaf448
Groups", §5), built on `ed448`'s edwards448 curve arithmetic. Sibling to
`std.crypto.ecc.Ristretto255` one curve family up: where ristretto255
wraps Curve25519 to eliminate its cofactor-8 pitfalls, decaf448 wraps
edwards448 to eliminate its cofactor-4 pitfalls, giving protocols built
on `ed448` the clean prime-order-group abstraction RFC 9496 §1 motivates
(no ad hoc cofactor-clearing tweaks, no "which validation criteria are
these, exactly" ambiguity). Closes the `decaf448` item `ed448`'s own
module doc comment explicitly deferred.

Consumers: anything layering a prime-order-group protocol on top of the
448-bit curve family — threshold signing, VRFs, anonymous credentials,
or any construction whose security proof assumes a clean prime-order
group rather than a cofactor-4 curve.

**Status: COMPLETE.** The group-element type, every mechanical group
operation, the 56-byte scalar wire-width bridge to `ed448.scalar`, the
RFC 9496 §5.1 implementation constants (self-checked), and a byte-exact
KAT harness against the official RFC 9496 Appendix B decaf448 vectors
are all real. The four irreducible decaf-specific field-math cores —
`sqrtRatioM1`, `Element.encode`, `Element.decode`, and the inner `MAP`
primitive behind `oneWayMap` — are implemented and the gate is `true`;
see [SPEC.md](SPEC.md) for the split and each core's full contract.

| File | Contents |
|---|---|
| `gate.zig` | `core_implemented` — the single switch gating the four stubs' KAT tests |
| `scalar.zig` | The scalar field mod `l` in decaf448's 56-byte encoding: `add`/`sub`/`negate`/`mul`/`invert`, `reduce`/`fromWide`, `random`, bridged to `ed448.scalar`'s 57-byte arithmetic (same order `l == L`) |
| `hash.zig` | `expandMessageXof` (RFC 9380, SHAKE256), `hashToElement` (`hash_to_decaf448`), `hashToScalar` (RFC 9497 decaf448-SHAKE256) |
| `hash_kat_test.zig` | RFC 9380 K.6 and RFC 9497 A.2 (decaf448-SHAKE256) vectors, byte-exact |
| `element.zig` | `Element` (the group type), the RFC 9496 §5.1 constants, `sqrtRatioM1`, `Element.encode`/`.decode`, `oneWayMap` (all implemented) |
| `kat_vectors.zig` | Official RFC 9496 Appendix B.1/B.2/B.3 decaf448 test vectors |
| `kat_test.zig` | Byte-exact KAT assertions against `kat_vectors.zig` through the public API, gated |

## Import

```zig
const decaf448 = @import("decaf448");
const Element = decaf448.Element;
```

## Group operations (real today)

```zig
const g = Element.generator;      // RFC 9496 §5: internally 2*B
const id = Element.identity;

const p = Element.add(g, g);
const q = Element.sub(p, g);      // == g
const r = Element.negate(g);
try std.testing.expect(Element.add(g, r).equals(id));

var two = decaf448.scalar.zero;
two[0] = 2;
try std.testing.expect(Element.scalarMul(g, two).equals(p));
```

## Wire codec (real)

```zig
const bytes = Element.encode(g);        // 56-byte RFC 9496 §5.3.2 encoding
const back = try Element.decode(bytes); // RFC 9496 §5.3.1, rejects invalid
try std.testing.expect(back.equals(g));
```

## Scalars

Scalars are `decaf448.scalar.CompressedScalar` (`[56]u8`, little-endian,
canonical `< l`). Every operation is constant-time in its secret inputs.

```zig
const sc = decaf448.scalar;
const k = try sc.random(io);             // 114 bytes of io.randomSecure, wide-reduced
const k_inv = sc.invert(k);              // Fermat a^(l-2); invert(0) == 0
std.debug.assert(std.mem.eql(u8, &sc.mul(k, k_inv), &sc.one));
const d = sc.sub(sc.add(k, sc.one), k);  // == one
const n = sc.negate(k);                  // add(k, n) == zero
const h = sc.fromWide(digest114);        // reduce a 114-byte digest mod l
const h64 = sc.reduce(64, bytes64);      // any width up to 114 bytes
try sc.rejectNonCanonical(wire_scalar);  // validate a received scalar
```

`random` returns `error.EntropyUnavailable` rather than falling back to a
weak seed; `invert` of zero is zero, so check for zero where that matters.

## Hashing to the group and to scalars

```zig
// hash_to_decaf448 (RFC 9380 Appendix C): expand_message_xof(SHAKE256, 112 bytes)
// followed by RFC 9496's element derivation (decaf448.element.oneWayMap).
const p = try decaf448.hashToElement("message", "MyApp-V1-decaf448");

// RFC 9497 decaf448-SHAKE256 HashToScalar: 64 bytes, reduced mod l.
const s = try decaf448.hashToScalar("message", "MyApp-V1-scalar");

// The expander on its own (RFC 9380 §5.3.2):
var out: [64]u8 = undefined;
try decaf448.hash.expandMessageXof(&out, "message", "MyApp-V1-xof");
```

The DST must be 1..255 bytes (`error.DstEmpty` / `error.DstTooLong`; an
oversize DST is not reduced for you) and `expandMessageXof` produces at most
65535 bytes (`error.OutputTooLong`). These are the RFC 9497
`HashToGroup`/`HashToScalar` for the decaf448-SHAKE256 suite when given
`"HashToGroup-" || contextString` / `"HashToScalar-" || contextString`.

`decaf448.gate.core_implemented` is `true` — the four field-math cores
are implemented and every KAT runs.

## Import graph

```
decaf448 → ed448 (edwards448 Point + Fp448 field, both already real)
         → std only, otherwise (SHAKE256 from std.crypto.hash.sha3)
```

## Verify

```
zig build test-decaf448                          # Debug
zig build -Doptimize=ReleaseFast test-decaf448   # ReleaseFast
zig fmt --check modules/decaf448/
```

All tests pass in both Debug and ReleaseFast — the mechanical
group-op layer, the scalar width bridge, the RFC 9496 §5.1 constant
self-checks, and the byte-exact RFC 9496 Appendix B KATs (encode of
`[0]G..[15]G`, decode round-trip, the 21 invalid-encoding rejections,
and the 7 one-way-map vectors), RFC 9380 K.6's `expand_message_xof`
vectors and RFC 9497 A.2's decaf448-SHAKE256 vectors — see [SPEC.md](SPEC.md).

Provenance: pure clean-room from RFC 9496 (no third-party source
ported); `std.crypto.ecc.Ristretto255` consulted as a structural design
reference only (API shape, one curve family down) — see [SPEC.md](SPEC.md)
and `NOTICE`'s policy §0 for why that needs no root-`NOTICE` entry.
