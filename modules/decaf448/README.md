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
| `scalar.zig` | Decaf448's 56-byte scalar wire codec, bridged to `ed448.scalar`'s 57-byte one (same underlying order `l == L`) |
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

`decaf448.gate.core_implemented` is `true` — the four field-math cores
are implemented and every KAT runs.

## Import graph

```
decaf448 → ed448 (edwards448 Point + Fp448 field, both already real)
         → std only, otherwise
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
and the 7 one-way-map vectors) — see [SPEC.md](SPEC.md).

Provenance: pure clean-room from RFC 9496 (no third-party source
ported); `std.crypto.ecc.Ristretto255` consulted as a structural design
reference only (API shape, one curve family down) — see [SPEC.md](SPEC.md)
and `NOTICE`'s policy §0 for why that needs no root-`NOTICE` entry.
