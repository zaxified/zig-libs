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

Reasoning is not the evidence here; the harness is, and — since 2026-08-11 —
it is a **committed program**, not a code block a reader has to retype:
[`src/ctgrind_harness.zig`](src/ctgrind_harness.zig), driven by
[`../../scripts/ctgrind.sh`](../../scripts/ctgrind.sh). It
marks a runtime (not comptime-folded) scalar uninitialised with valgrind's
client request, forces a volatile reload so the optimizer cannot keep a
defined register copy from before the taint, drives it through either
`mulRistrettoBase` (`--target ct25519`, what all of `voprf`'s secret-scalar
call sites reduce to) or `std.crypto.ecc.Ristretto255.mul`
(`--target std` — the function this module replaces, run as the negative
control), and finally prints the result through `std.debug.print`
(deliberately not constant-time) as a propagation witness. Run it:

```sh
scripts/ctgrind.sh ct25519
```

**Full control table**, ReleaseFast, zig 0.16.0, valgrind 3.26.0, x86_64,
2026-08-11 (`in-file` = memcheck error CONTEXTS, not error count, whose
stack includes the named file — the number the "constant-time" claim is
actually about; `total` includes the harness's own `std.debug.print`, which
is not constant-time by design — see "propagation witness" above):

| target | `-fvalgrind` | scalar tainted | total contexts | contexts in target's own code | exit |
|---|---|---|---|---|---|
| `ct25519` (`mulRistrettoBase`) | yes | **yes** | 2 | **0** in `root.zig` | 99 |
| `ct25519` | yes | no | 0 | 0 | 0 *(control)* |
| `ct25519` | **no** | yes | 0 | 0 | 0 *(trap)* |
| `std` (`Ristretto255.mul`) | yes | **yes** | 3 | **1** in `edwards25519.zig` | 99 |
| `std` | yes | no | 0 | 0 | 0 *(control)* |
| `std` | **no** | yes | 0 | 0 | 0 *(trap)* |

Reading each row:

- **Row 1 is the claim**, measured: tainting the scalar and driving it
  through this module's own `mul` produces **zero** memcheck contexts
  anywhere in `root.zig`. The 2 total contexts are both inside the harness's
  `std.debug.print` (`Io.Writer.printHex`) — proof the taint reached the
  *output*, so "zero in `root.zig`" means "no branch found", not "taint
  never arrived here".
- **Row 2 is the paired negative control** the first row is meaningless
  without: with the identical binary and the identical code path, an
  *untainted* scalar reports zero everywhere, including the print. If row 1
  read 2/0 regardless of whether the scalar was tainted, that would mean the
  print always trips memcheck for some unrelated reason — it does not.
- **Row 3 is the trap**, reproduced deliberately: built *without*
  `-fvalgrind`, `std.valgrind.doClientRequest`'s
  `if (!builtin.valgrind_support) return default;` makes `MAKE_MEM_UNDEFINED`
  silently do nothing, so even a genuinely tainted scalar reports 0/0 — a
  clean run that measured nothing, not evidence of anything.
- **Rows 4-6 are the actual point of the exercise**: the *same* harness, the
  *same* tainted scalar, routed through `std.crypto.ecc.Ristretto255.mul`
  instead — the function `ct25519` exists to replace. Row 4 reports a real
  context **inside `edwards25519.zig`**, at exactly the line this module's
  doc comments name: `pcMul16`'s `try q.rejectIdentity()`
  (`edwards25519.zig:266`, `if (p.x.isZero()) return error.IdentityElement;`
  in `rejectIdentity` itself). That the *same* harness, the *same* scalar,
  the *same* build flags produce a real hit on std and none on this module
  is what makes row 1's zero mean "this module removed the leak", not
  "this harness cannot see leaks". Rows 5-6 are std's own paired control and
  trap, included for symmetry — they read exactly like ct25519's.

**Reproduce the claim row directly:**

```sh
scripts/capped zig build-exe modules/ct25519/src/ctgrind_harness.zig \
    -OReleaseFast -fno-strip -fvalgrind -femit-bin=/tmp/ct25519_ctgrind
valgrind --tool=memcheck --error-exitcode=99 /tmp/ct25519_ctgrind ct25519 yes
```

**Two traps that make this harness silently meaningless — both are now
rows in the table above rather than assumed.**

1. **`-fvalgrind` is mandatory outside Debug** (table rows 3, 6). Without it
   every client request compiles to nothing and the harness reports
   `0 errors` *unconditionally*, tainted or not.
2. **The volatile reload is mandatory** (`reloadVolatile` in the harness).
   Without it the optimizer can keep a *defined* register copy of the scalar
   from the hash that produced it, and the ladder never reads the memory
   that was marked — same false clean, and nothing in the table above would
   catch it, since it looks identical to a genuinely clean run.
3. Run it at **ReleaseFast**, not Debug or ReleaseSafe. There, Zig's own
   integer-overflow safety checks inside `std.crypto.25519.field`
   (`Fe.mul`/`sq`/`add`/`sub`/`_carry128`) are themselves conditional jumps
   on the tainted limbs and flood the report. **Measured**: the identical
   `ct25519`/tainted/`-fvalgrind` build at `-OReleaseSafe` reports
   **89 956 errors from 1000 contexts** — 1000 being valgrind's own default
   `--error-limit` cutoff ("More than 1000 different errors detected. I'm
   not reporting any more."), i.e. the true count is capped, not exactly
   1000. Their outcome is invariant — the limbs are masked to 51 bits and
   cannot overflow — so they are not a leak, but they bury the signal
   completely, which is why the claim above is stated for ReleaseFast only.

**Teeth, re-verified 2026-08-11.** Injecting
`var z: u8 = 0; for (s) |b| z |= b; if (z == 0) return identityElement;` at
the top of `mul` and re-running `scripts/ctgrind.sh ct25519` moves row 1 from
`2 total / 0 in-file` to **`3 total / 1 in root.zig`, exit 99** — the harness
catches the exact defect class the module exists to prevent. Reverted;
`cmp` against a pre-mutation copy confirmed byte-identical, `git diff
--stat` empty.

**Always re-run the positive control after changing the harness.** A ctgrind
run that reports nothing is indistinguishable from a ctgrind run that is not
wired up — which is why the table above keeps both controls next to the
claim instead of stating the claim alone.

**What stops the harness rotting.** `zig build check-ctgrind` compiles it
(with `-fvalgrind`, so the client-request bodies are actually analysed) and
is part of `zig build test`; it runs no valgrind, so the gate neither needs
that tool installed nor pays for a memcheck run. `scripts/ctgrind.sh --check`
re-measures and compares against `scripts/ctgrind-expected.tsv`, asserting
that every control and trap row is 0 and that this table's in-file counts are
unchanged. Neither compares the prose above against either — see
`scripts/README.md` § Constant-time harnesses for exactly what each does and
does not catch.

### What the in-suite tests provably cannot catch

A secret-dependent branch that does not change any output byte is invisible
to every test in this file, by construction. Injecting

```zig
var z: u8 = 0;
for (s) |b| z |= b;
if (z == 0) return Edwards25519.identityElement;   // exactly the defect the module exists to prevent
```

into `mul` leaves `zig build test-ct25519` **green (exit 0)** — the output is
byte-identical on every input — while `scripts/ctgrind.sh ct25519` catches it
(**exit 99**, 1 context in `root.zig`, up from 0 — see "Teeth, re-verified
2026-08-11" above for the exact command and revert). That asymmetry is the
reason the harness is documented here rather than treated as optional:
**for this module the valgrind run is not a nicety, it is the only oracle
for the property the module is named after.** Re-run it after any change to
`mul`, `pcSelect` or `precompute`.
