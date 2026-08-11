# ct25519

**What it is.** Scalar multiplication on Edwards25519 / Ristretto255 that is safe
to hand a **secret** scalar, because it does not branch on one.

**Status:** gap — the one thing `std.crypto.ecc` does not offer.

**The gap.** `std.crypto.ecc.Edwards25519.mul` (and `Ristretto255.mul`, a thin
wrapper over it) is internally constant-time — a 4-bit fixed window over a
16-entry table selected with `Fe.cMov`, 64 unconditional iterations whatever the
scalar — and then its `pcMul16` ladder ends with `try q.rejectIdentity()`. That
final line is a **branch on a scalar-derived value**, and because it makes the
function return an error union it is contagious: every caller must branch again,
and the idioms that follow (`catch continue`, `catch return error.X`,
`catch @panic(...)`) take visibly different amounts of work on the two paths.

`mul` here is std's own ladder with that trailing rejection removed. The neutral
element comes back as an ordinary **value**, the function has no error union at
all, and the control flow is identical for every scalar including zero. Same
algorithm, same table, same 64 iterations — the same cost, with the leak taken
out of the tail. When the scalar is *public* (a signature's `s`, a Fiat-Shamir
challenge a verifier replays) std's `mul`/`mulPublic`/`mulDoubleBasePublic` stay
the right call and are faster; this module is only for the secret side.

**API.** `mul(p, s)` / `mulBase(s)` on `Edwards25519`, `mulRistretto(p, s)` /
`mulRistrettoBase(s)` on `Ristretto255`. The base-point table is folded at
comptime, as std folds its own.

**Deliberately absent:** any rejection of the output (that is the point) and any
`WeakPublicKey` check on the input point (a second error union, over a *public*
value). The caller validates the point. ristretto255 is a prime-order group, so
for a validated non-identity `P` the product `s·P` is the identity **iff
`s ≡ 0 (mod L)`** — a degenerate local secret, never something a peer can
induce. Protocol rules of the form "the shared secret MUST NOT be the identity"
are discharged by that argument rather than by a runtime branch on secret data.

**Consumers:** `voprf` (OPRF blind, `skS`, POPRF tweak, DLEQ nonce), `opaque`
(3DH), `signal` (XEdDSA key/nonce), `bulletproofs` (witness + blinding scalars,
and the finding that started this).

**Anchors.** Bit-exact against `std`'s `Edwards25519.mul`/`Ristretto255.mul` on
base and non-base points over deterministic pseudorandom scalars; RFC 8032 §7.1
TEST 1/TEST 2 public keys re-derived as `[clamp(SHA-512(sk)[0..32])]B`
byte-exactly; the two scalars std refuses (`s = 0`, `s = L`) pinned to the
neutral element as a value; the inputs std refuses outright (the identity, an
order-8 torsion point) checked against repeated addition; all 256 scalar bits
checked against a doubling chain; and scalar-additivity `(a+b)·B == a·B + b·B`
as a std-independent property over the window seams.

**The test suite is not the constant-time oracle.** A secret-dependent branch
that changes no output byte passes every test here — demonstrated, not
assumed. The property this module is named after is checked by a ctgrind-style
valgrind run — `scripts/ctgrind.sh ct25519` builds and runs it — and
[SPEC.md](SPEC.md) carries the full control table, the two flags without
which it silently reports a false clean, and the limits of the claim. Read it
before trusting a green `zig build test-ct25519`.

Provenance: clean-room re-derivation of the fixed-window ladder in Zig's own
`std/crypto/25519/edwards25519.zig` (MIT, part of Zig itself) with the trailing
identity rejection removed — the algorithm is the textbook 4-bit fixed-window
scalar multiplication, no third-party source ported, so no `NOTICE` entry is
required (root [`NOTICE`](../../NOTICE) §0).
