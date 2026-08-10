# ct25519 — SPEC

Scalar multiplication on Edwards25519 / Ristretto255 that is safe to hand a
**secret** scalar; see [README.md](README.md) for purpose and API.
Provenance: clean-room re-derivation of the fixed-window ladder in Zig's own
`std/crypto/25519/edwards25519.zig` — see the `Provenance:` line in
[README.md](README.md) and root [`NOTICE`](../../NOTICE) §0.

## Design

- **Source of truth**: `std.crypto.ecc.Edwards25519`'s own constant-time
  ladder. This module is not a new algorithm and must never become one — it
  is std's `pcMul16` with exactly one thing removed. Anything else that
  diverges from std is a bug in this module, and the differential tests exist
  to say so.
- **std recon (confirmed against `lib/std/crypto/25519/edwards25519.zig`,
  0.16.0)**:
  - `mul(p, s)` is `pc = if (p.is_base) basePointPc else precompute(p, 15)`
    (with `xpc[4].rejectIdentity() catch return error.WeakPublicKey`), then
    `pcMul16(&pc, s, false)`.
  - `pcMul16` is a 4-bit fixed window: `q = identity`, then 64 iterations
    from `pos = 252` down to `0` in steps of 4, each an unconditional
    `pcSelect(16, pc, slot)` + `add`, followed by four `dbl`s except on the
    last. `pcSelect` is branch-free: `t = identity`, then a `cMov` of every
    entry `1..15` under the mask `((slot ^ i) -% 1) >> 8) & 1`.
  - `pcMul16` **ends with `try q.rejectIdentity()`** (`:266`). That single
    line is the entire reason this module exists: `rejectIdentity` is
    `if (p.x.isZero())`, a branch on a value derived from the scalar, and
    the error union it forces makes the branch contagious — every caller
    has to branch a second time to handle `error.IdentityElement`.
  - `precompute(p, 15)` builds `pc[i] = i·p` by `pc[i/2].dbl()` for even `i`
    and `pc[i-1].add(p)` for odd; `basePointPc` folds it at comptime.
  - `Ristretto255.mul` is `.{ .p = try p.p.mul(s) }` — a thin wrapper, so it
    inherits the rejection unchanged. `Ristretto255.basePoint` is
    `.{ .p = Curve.basePoint }`, so its `is_base` flag is set and the
    comptime table is reached through it.
- **What this module changes**: the trailing `rejectIdentity` is gone and
  the input-point `WeakPublicKey` check is gone. Nothing else. `precompute`
  and `pcSelect` are transcriptions of std's private versions (std does not
  export them), and `base_pc` is the same comptime fold. Same table, same 64
  iterations, same cost.
- **`pc[0]` is dead by construction.** `precompute` writes
  `pc[0] = identityElement` and `pcSelect` starts its `cMov` chain at `i = 1`
  (returning the identity when `slot == 0`), so index 0 is never read. It is
  kept for shape-parity with std. A fault injected into `pc[0]` is green
  because the code is dead, not because the tests are weak — noted here so a
  future auditor does not re-derive that the hard way.
- **All 256 scalar bits are consumed.** The top window at `pos = 252` covers
  bits 252..255, so `mul(P, s)` is `s·P` for the full 256-bit integer `s`,
  not for `s mod L`. A caller that needs the reduced value reduces first
  (`scalar.reduce`/`reduce64`), exactly as it must for std.

## Threat model / limits

- **The claim.** `mul`/`mulBase`/`mulRistretto`/`mulRistrettoBase` execute
  the same sequence of operations for every scalar, including zero and
  including `s ≡ 0 (mod L)`, and none of them can return an error, so no
  call site can branch on the scalar either. That is the whole claim.
- **What the claim is NOT.** It is a claim about *this source* and about the
  machine code LLVM emits from it on the builds measured below. It is not a
  claim about the microarchitecture: nothing here constrains cache behaviour,
  execution-port contention, data-dependent µop latency, or speculation, and
  a `cMov` is not guaranteed by any ISA contract to be constant-time. Nor is
  it a claim that holds under an arbitrary future compiler — LLVM is free to
  rematerialise a branch out of a mask, and only a re-run of the check below
  can say whether it did. **Overclaiming this is the single most common
  defect the 2026-08 audit found; the honest boundary is the deliverable.**
- **Points are the caller's problem.** `mul` performs no validation of `p` —
  no identity check, no low-order check. That is deliberate (a second error
  union, over what is public data in every consumer), and it is a contract:
  where the point is attacker-supplied the caller MUST reject the identity
  and, on raw Edwards25519 (cofactor 8), low-order points, before calling.
  ristretto255 has prime order, so a decoded non-identity element is enough.
- **How "the shared secret MUST NOT be the identity" is discharged.** Over a
  prime-order group with a validated non-identity `P`, `s·P` is the identity
  **iff `s ≡ 0 (mod L)`** — a degenerate *local* secret, never something a
  peer can induce with any element it can encode. Protocol rules of that
  shape are therefore satisfied structurally, by validating `P` and
  generating `s` properly, and not by a runtime branch on secret-derived
  data. `opaque` (RFC 9807 §6.4.1.1) and `voprf` both rely on exactly this.
- **Public scalars belong on std.** A signature's `s`, a Fiat-Shamir
  challenge a verifier replays, a hash of public `info` — for those, std's
  `mulPublic`/`mulDoubleBasePublic` are variable-time *by design*, correct,
  and faster. This module is only for the secret side; routing public
  scalars through it buys nothing and costs speed.
- **No secrets are held.** The module allocates nothing, keeps no state and
  has no RNG; the only secret-derived values are the caller's scalar (a
  by-value parameter) and the running `q`, both of which die with the frame.
  There is nothing for `secureZero` to own here — zeroization is the
  caller's, on the scalar it supplied.

## Verification

- **External anchor (class B, EXTERNAL).** RFC 8032 §7.1 TEST 1 and TEST 2
  publish Ed25519 public keys; the test re-derives each as
  `[clamp(SHA-512(sk)[0..32])]B` and requires the exact published 32 bytes.
  This is the only oracle in the module whose authority comes from outside
  the Zig tree, and it is the only one that could catch a defect *shared*
  with std — which matters precisely because the ladder here is a
  re-derivation of std's.
- **Differential vs std**, on the base point and on non-base points, over
  deterministic pseudorandom scalars (SHA-512 stream reduced mod `L`), plus
  the Ristretto255 wrapper. std is the reference for every case std is
  willing to answer.
- **Where std refuses**, an std-independent oracle is used instead:
  - `s = 0` and `s = L` are pinned to the neutral element **as a value**
    (std raises `error.IdentityElement` for both — the test pins that too,
    so the reason the module exists cannot silently evaporate);
  - a point of order exactly 8 and the identity point — inputs std rejects
    with `error.WeakPublicKey` — are checked against **repeated addition**
    for `k = 0..9`, which depends on neither ladder;
  - scalar bits 250..255 individually, and `2^256 − 1`, are checked against
    **a doubling chain** as well as against std.
- **Std-independent property**: `(a+b)·B == a·B + b·B` over the window
  seams.
- **Type-level**: all four entry points are asserted to carry no error
  union, and std's `mul` is asserted to carry one — the shape claim itself
  is a test.

### Constant-time check (ctgrind-style, valgrind memcheck)

Reasoning is not the evidence here; the harness is. Mark the scalar
uninitialised with valgrind's client request and let memcheck report every
conditional jump whose outcome depends on it:

```zig
// ctgrind.zig — build alongside src/root.zig
var s = Edwards25519.scalar.reduce64(runtime_wide_bytes); // NOT a constant
mc.makeMemUndefined(&s);
const sv: *volatile [32]u8 = &s;   // see the two traps below
const sec: [32]u8 = sv.*;
const a = ct.mul(p_runtime, sec);
const b = ct.mulBase(sec);
const c = ct.mulRistretto(p_r_runtime, sec);
const d = ct.mulRistrettoBase(sec);
```

```sh
zig build-exe ctgrind.zig -OReleaseFast -fvalgrind    # BOTH flags are load-bearing
valgrind -q --error-exitcode=9 ./ctgrind              # judge by the exit code
```

Result at 2026-08-10 (zig 0.16.0, valgrind 3.26.0, x86_64):
**0 errors, exit 0.**

**Two traps that make this harness silently meaningless — check for them
before believing a clean run.**

1. **`-fvalgrind` is mandatory outside Debug.** `std.valgrind.doClientRequest`
   opens with `if (!builtin.valgrind_support) return default;`, and
   `valgrind_support` is off by default in the release modes. Without the
   flag every client request compiles to nothing and the harness reports
   `0 errors` *unconditionally*. Measured: with a literal
   `if (s[0] == 7) return identityElement;` injected into `mul`, ReleaseFast
   without `-fvalgrind` reported **0 errors, exit 0**; with `-fvalgrind`,
   **4 contexts at `mul`, exit 9**.
2. **The volatile reload is mandatory.** Without it the optimizer keeps a
   *defined* register copy of `s` from the hash that produced it and the
   ladder never reads the memory that was marked — same false clean.
3. Run it at **ReleaseFast**, not Debug or ReleaseSafe. There, Zig's own
   integer-overflow safety checks inside `std.crypto.25519.field`
   (`Fe.mul`/`sq`/`add`/`sub`/`_carry128`) are themselves conditional jumps
   on the tainted limbs and flood the report (>1000 contexts). Their outcome
   is invariant — the limbs are masked to 51 bits and cannot overflow — so
   they are not a leak, but they bury the signal.

**Always re-run the positive control after changing the harness.** A ctgrind
run that reports nothing is indistinguishable from a ctgrind run that is not
wired up.

### What the in-suite tests provably cannot catch

A secret-dependent branch that does not change any output byte is invisible
to every test in this file, by construction. Injecting

```zig
var z: u8 = 0;
for (s) |b| z |= b;
if (z == 0) return Edwards25519.identityElement;   // exactly the defect the module exists to prevent
```

into `mul` leaves `zig build test-ct25519` **green (exit 0)** — the output is
byte-identical on every input — while the ctgrind harness above catches it
(**exit 9**, 4 contexts at `mul`). That asymmetry is the reason the harness
is documented here rather than treated as optional: **for this module the
valgrind run is not a nicety, it is the only oracle for the property the
module is named after.** Re-run it after any change to `mul`, `pcSelect` or
`precompute`.
