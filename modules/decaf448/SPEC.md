# decaf448 — SPEC

decaf448, the prime-order group over edwards448; see [README.md](README.md)
for purpose and API.

**Status: COMPLETE.** Wire codec structs, the mechanical
group-operation layer, the scalar wire-width bridge, and an airtight
byte-exact KAT harness against the official RFC 9496 vectors are real.
The four irreducible field-math cores were `@panic`-stubbed by the
scaffold pass behind `gate.core_implemented`; a Fable pass then
implemented ONLY those four and flipped the gate — with zero edits to
`kat_test.zig`/`kat_vectors.zig`, matching `ed448`'s and `bn254`'s own
scaffold-then-implement track record. All tests now run and pass.

## Design

- **Source of truth**: RFC 9496 ("The ristretto255 and decaf448
  Groups") §5 (decaf448 specifically) + §5.1's implementation constants
  + Appendix B's official test vectors — this module is clean-room from
  that RFC, no third-party source ported. `std.crypto.ecc.Ristretto255`
  (RFC 9496 §4, ristretto255 — the sibling construction one field down)
  is consulted as a STRUCTURAL design reference only: how a decaf/
  ristretto implementation shapes its element type, its
  encode/decode/equals/derivation API, and its internal
  `sqrtRatioM1`-style helper. No source copied — decaf448 differs from
  ristretto255 in its curve (edwards448, not Curve25519), its constants
  (`D`/`ONE_MINUS_D`/`ONE_MINUS_TWO_D`/`SQRT_MINUS_D`/
  `INVSQRT_MINUS_D`, all distinct numbers from ristretto255's
  `edwards25519d`/`sqrtm1`/etc.), AND — the one genuine algorithmic
  simplification — its `SQRT_RATIO_M1`: edwards448's field has `p ≡ 3
  (mod 4)` (unlike Curve25519's `p ≡ 5 (mod 8)`), so decaf448's version
  needs no `sqrt(-1)`-twist branch at all (RFC 9496 §5.2 vs §4.2 — see
  `element.zig`'s `sqrtRatioM1` doc comment for the exact formula
  difference).
- **Per NOTICE policy §0, this module needs no root-`NOTICE` entry.**
  RFC 9496 is a public spec (not copyrightable per the merger doctrine);
  `std.crypto.ecc.Ristretto255` was studied for algorithm/API SHAPE, not
  source-ported — the same "design reference documented in SPEC.md, no
  NOTICE entry" precedent `ed448`'s own SPEC.md sets for its
  `std.crypto.ecc.Edwards25519`/`libdecaf` field-representation
  references.
- **Internal representation: `ed448.ed448.Point`, no extra `t`
  coordinate.** RFC 9496 §2 represents every internal point in
  four-coordinate extended Edwards form `(x, y, z, t)`, `t = x*y/z`. This
  module's `Element` stores only `ed448.ed448.Point`'s three coordinates
  (`x, y, z`) — mechanically sufficient because every group operation
  this scaffold implements for real (`add`/`sub`/`negate`/`scalarMul`,
  `identity`/`generator`) delegates straight to `Point`'s already-real
  arithmetic, none of which touches `t`, and `equals` (RFC 9496 §5.3.3)
  needs only `x`/`y` (its `z`-scale-invariance is argued in `element.
  Element.equals`'s own doc comment). Only the four Fable-core stubs
  reference `t0`/`z0` together; `encode`'s doc comment spells out where a
  full implementation must derive `t0 = x0*y0*z0^-1` (one `Fe.invert`)
  from the three stored coordinates.
- **Scalar width bridge (`scalar.zig`), not a full scalar
  reimplementation.** RFC 9496 §5.4: "the scalars for the decaf448 group
  are integers modulo the order `l` of the decaf448 group... the SAME
  scalar field as edwards448" — bit-identical to `ed448.scalar`'s `L`.
  The only real difference is WIRE WIDTH: RFC 8032 encodes scalars in
  57-byte containers (padding to match its point-coordinate width); RFC
  9496 §5.4 uses a tighter 56-byte container (`l < 2^446` fits without
  the extra byte). `scalar.zig` is a pure zero-pad/truncate bridge over
  `ed448.scalar`'s already-real, already-KAT-validated mod-`L`
  arithmetic — no new number theory.
- **RFC 9496 §5.1 constants: mechanical, not gated.** `D` is reused
  bit-for-bit from `ed448.ed448.d`. `ONE_MINUS_D`/`ONE_MINUS_TWO_D` are
  tiny (`< 2^17`) plain integers, built via a `smallFe` byte-layout
  helper — no square root involved. `SQRT_MINUS_D`/`INVSQRT_MINUS_D` ARE
  literally square roots of `-D`, but the RFC publishes their exact
  DECIMAL values directly (they do not need to be computed by this
  module at build/run time) — this module hardcodes their little-endian
  byte encoding (independently re-derived from the RFC's decimal text
  via Python at scaffold time, not hand-transcribed) and re-verifies
  the defining relations (`SQRT_MINUS_D^2 == -D`,
  `SQRT_MINUS_D * INVSQRT_MINUS_D == 1`) as ordinary, ungated `Fe`
  arithmetic tests — the verification is mechanical even though the
  values themselves are "square roots" by name.
- **`Fe.isOdd` already IS `IS_NEGATIVE`; `ctAbs` is a 2-line, ungated
  helper.** RFC 9496 §2.1 defines `IS_NEGATIVE(e)` as "the least
  nonnegative integer representing `e`... odd" — identical, word for
  word, to `ed448.field.Fe.isOdd`'s own doc comment. `CT_ABS` (§2.2) is
  the RFC's own one-line construction from `IS_NEGATIVE`/`CT_SELECT`/
  negation, all three of which `Fe` already provides for real — so
  `element.zig` implements `ctAbs` directly (ungated), leaving the ONE
  genuinely new primitive as `sqrtRatioM1`.

## The four Fable cores

All four live in `element.zig` (scaffolded as `@panic("TODO(fable/core):
...")` stubs, now implemented), each with the exact RFC formula in its
doc comment:

1. **`sqrtRatioM1(u: Fe, v: Fe) SqrtRatioResult`** (RFC 9496 §5.2) — the
   shared field-math primitive every other stub is built on. Returns
   `(was_square, r)`: `(true, +sqrt(u/v))` if `u/v` is a nonzero square,
   `(true, 0)` if `u == 0`, `(false, 0)` if `v == 0 != u`, else
   `(false, +sqrt(-u/v))`. decaf448's `p ≡ 3 (mod 4)` needs no twist
   constant: `r = u*(u*v)^((p-3)/4)`, verify `v*r^2 == u`, `r = ctAbs(r)`.
2. **`Element.encode(e: Element) [56]u8`** (RFC 9496 §5.3.2) — never
   fails; derives `t0` (one inversion), then the `s`-recovery formula
   using `sqrtRatioM1`/`SQRT_MINUS_D`/`INVSQRT_MINUS_D`/`ONE_MINUS_D`.
3. **`Element.decode(bytes: [56]u8) DecodeError!Element`** (RFC 9496
   §5.3.1) — rejects non-canonical (`s >= p`) and negative-`s`
   encodings up front, then reconstructs `(x, y, t)` via `sqrtRatioM1`
   and rejects if the ratio was non-square.
4. **`mapToElement(bytes: [56]u8) Element`** (RFC 9496 §5.3.4's inner
   `MAP`) — the per-56-byte-half hash-to-group primitive; `oneWayMap`
   itself (the 112-byte, split-and-add outer function) is the REAL
   orchestration, calling this core twice and adding the results
   (mechanical per the RFC's own §5.3.4 recipe).

## KAT harness

`kat_vectors.zig` embeds RFC 9496 Appendix B's decaf448 vectors,
extracted programmatically from the RFC text (not hand-transcribed —
verified byte-length-asserted against the RFC's own stated widths at
extraction time):

- **B.1** (`generator_multiples`, 16 vectors): the encodings of
  `[0]G..[15]G`. `[0]` is the identity's 56-zero-byte encoding
  (checked ungated — the one B.1 fact that needs no `encode` call).
  `encode([k]G)` byte-exact for all 16, plus decode round-trip
  (`decode(encode(P)) equals P` and re-encodes identically).
- **B.2** (`invalid_non_canonical`/`invalid_negative`/`invalid_nonsquare`,
  7 each, 21 total): every one MUST be rejected by `decode` — the three
  RFC §5.3.1 failure modes (`s >= p` → `NonCanonical`; `IS_NEGATIVE(s)`
  → `InvalidEncoding`; non-square ratio → `InvalidEncoding`).
- **B.3** (`derivation_vectors`, 7 pairs): 112-byte uniform input →
  56-byte `oneWayMap` output, byte-exact.

`[k]G` for the B.1/decode-roundtrip tests is built by `k` REAL,
UNGATED `Element.add(acc, generator)` calls (`kat_test.zig`'s
`nthMultiple`) — the exact recipe RFC 9496 Appendix B.1 itself
describes ("each successive entry is obtained by adding the generator
to the previous entry"), so the vectors being checked against `encode`
are constructed by machinery independent of the stub under test.

## Verification

- `zig build test-decaf448` (Debug) and `zig build test-decaf448
  -Doptimize=ReleaseFast`: **all tests pass, no skips, no failures, in
  both modes**. `zig fmt --check modules/decaf448/` is clean.
- A repo-hygiene grep for developer-machine home-directory paths and
  personal identifiers over `modules/decaf448/` is empty.

## Out of scope

- `hash_to_decaf448` (RFC 9380 Appendix C's domain-separated
  expand-message construction on top of `oneWayMap`) — RFC 9496
  §5.3.4's own note places this out of scope for the base group; a
  future module (or this one, extended) can layer it on once
  `oneWayMap` is real.
- Batch verification / multi-scalar-multiplication speedups — `Element.
  scalarMul` is a plain per-call delegation to `ed448.ed448.Point.mul`'s
  constant-time 4-bit fixed window (it was a double-and-add until ed448
  F1; no windowing/precomputation of decaf448's own on top).

## Constant-time note (measured)

`Element.scalarMul` is safe for a SECRET scalar, and that is measured
rather than argued. Since 2026-08-11 the measurement is a **committed
program**, not a number to take on faith:
[`src/ctgrind_harness.zig`](src/ctgrind_harness.zig), run by
`scripts/ctgrind.sh decaf448`. It marks the scalar
`MAKE_MEM_UNDEFINED`, forces a volatile reload so the optimizer cannot
feed the ladder a defined register copy, and drives it through
`Element.generator.scalarMul`.

**Full control table** (zig 0.16.0, valgrind 3.26.0, x86_64,
ReleaseFast, 2026-08-11; `in-file` = memcheck CONTEXTS whose stack
names a `decaf448` or `ed448` source):

| `-fvalgrind` | scalar tainted | total contexts | in decaf448+ed448 | exit |
|---|---|---|---|---|
| yes | **yes** | 6 | **0** | 99 |
| yes | no | 0 | 0 | 0 *(control)* |
| **no** | yes | 0 | 0 | 0 *(trap)* |

The three rows are the whole point. The **trap** row is what a
ReleaseFast build without `-fvalgrind` reports —
`std.valgrind.doClientRequest` returns early unless
`builtin.valgrind_support`, which the release modes disable, so a
"clean" run built without the switch measures nothing. The **control**
row shows an untainted scalar reports 0 everywhere, so the counts are
taint-caused. And the claim row's `total` is **non-zero** — those 6
contexts are inside the harness's own (non-constant-time) hex
formatter, which proves the taint travelled scalar → point → stdout, so
the **0** means "no branch found in the ladder", not "the taint never
arrived". The witness prints raw projective coordinates through
`Fe.toBytes` rather than `Element.encode`, because `encode` runs
`Fe.invert`, whose own validation branch is accounted for separately in
`ed448`'s harness.

Re-attribute the column yourself with
`scripts/ctgrind.sh decaf448 --pattern 'ed448[.]zig'` (also **0**), or
read the frames with `--stacks`.

**Teeth, measured 2026-08-11.** Re-introducing a variable-time
`if (nibble != 0) acc = acc.add(table[nibble]);` inside
`ed448.Point.mul` moves this table from **6 total / 0 in-file** to
**4 / 4, exit 99** — the harness genuinely reaches the ladder.
Reverted; `cmp` against a pre-mutation copy confirmed byte-identical.
*(An earlier note recorded this mutation as "report 860". That was the
ERROR count, not the context count — the same run here reports 421
errors from 4 contexts. The two units are not interchangeable.)*

This module is *not* exposed to the defect that forced `ecvrf`'s move
to `ct25519`: `std.crypto.ecc.Edwards25519.mul` ends in a
`rejectIdentity` branch on a scalar-derived value, but `ed448`'s
`Point.mul` — which is what decaf448 rides — has no such rejection and
no error union at all.
