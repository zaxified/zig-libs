# spake2plus — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-08** — **BREAKING + FIX (secrets on the dead stack, HIGH):** every secret path left
  the password-derived scalars, the ephemerals, `Z`/`V` and the whole key schedule on the dead stack,
  in the module's frames and in the caller's (by-value scalar params, by-value results, a result
  inside an error union). New ReleaseFast probe `src/stackprobe_test.zig` (5 calls per entry point,
  two cases, negative + positive control), BEFORE the fix, residues per entry point (case 0 / 5
  calls): `computeW0W1` pbkdf 15, `w0` 10, `w1` 30; `computeL` `w1` 10; `proverStart` `x` 10, `w0` 5;
  `verifierStart` `y` 10, `w0` 5; `deriveKeys` `K_main` 20, `K_confirmP` 20, `K_confirmV` 20,
  `K_shared` 20, `TT` 5, `w0` 5; `kdf(64)` confirmation keys 30; `mac` HMAC key pad 10;
  `proverFinish` `w0` 5, `w1` 10, `x` 10, `V` 10, `TT` 70, `K_main` 20, `K_confirmP` 30,
  `K_confirmV` 20, `K_shared` 20 (reaching 2.4 KiB down, i.e. into the caller's frames);
  `verifierConfirm` `y` 10, `Z` 5, `V` 5, `TT` 30, all four keys 10-20; `verifierFinish` `y` 10,
  `Z` 10, `V` 10, `TT` 60, all four keys 20-30. AFTER: 0 residues in all ten, NEG=0, POS>=1.
  API (all in-repo callers, the example, README and the ctgrind harness' call sites migrated):
  `w0`/`w1`/`x`/`y` are `*const [32]u8`; `computeW0W1(out: *W0W1, pbkdf_output)`,
  `deriveKeys(out: *DerivedKeys, tt)`, `kdf(comptime len, out: *[len]u8, salt, ikm, info)`,
  `proverFinish(out: *ProverFinishResult, allocator, ..., w0, w1, x, ...)` and
  `verifierFinish(out: *VerifierFinishResult, ...)` return `!void` and zero `out` (and set
  `out.tt = &.{}`) on error; `computeTranscript` takes `z`, `v`, `w0` by pointer. Public results
  (`computeL`'s `L`, the shares, `verifierConfirm`'s `confirm_v`) stay return values. Every
  secret-touching entry point runs its body under a burn (`src/burn.zig`: 32 KiB for the
  multiplying cores, measured 8.6-10.8 KiB deep before; 4 KiB for hash/MAC/KDF, measured
  0.9-1.7 KiB); multiplies are `P256.mulInto`. Kept value-shaped: `mac` (its tag is the public
  confirmation message; its key pads are burned) and `hash`. Internally a tag that failed the
  confirmation compare is wiped (it is a valid forgery for the peer's confirmation).

- **2026-10-05** — **Fix (secret hygiene, no API change):** `verifierConfirm`, and `proverFinish`/
  `verifierFinish` on `ConfirmationMismatch`, freed their own transcript `TT` (which ends in `w0`
  and is a one-call pre-image of `K_shared`) without zeroing it; in ReleaseFast `free` leaves the
  bytes in place. They are now zeroed first. Tests: first dated mutation run (33 mutants, 30
  killed, 2 equivalent; `SPEC.md` § "Mutation run 2026-10-05") — `computeW0W1` refuses 81 octets,
  and a ReleaseFast-only test checks every module-freed transcript is zero at free time.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **w0w1 4 / computel 3 / proverstart 7 / verifierstart 7 / proverfinish 12 / verifierfinish 10**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. First measurement behind `SPEC.md`'s two claims ("EVERY scalar multiplication MUST use P256's constant-time mul" and "Key-confirmation MUST be constant-time-compared"). ⭐ The confirmation MAC measured clean: exactly one context each, the unavoidable branch on the aggregate accept/reject the return value already discloses, with **no contexts from inside the byte-comparison loop**. `root.zig`'s own source-text test already said it "cannot measure timing" and that whether `p256`'s `mul` is branch-free "is p256's to prove — that gap is recorded, not closed here"; this harness is that measurement. ⚠ The password is the secret here, and a password has far less entropy than a key, so any real dependence would be worth more to an attacker than the same dependence on a 256-bit scalar — which is why the canonicality checks on `w0`/`w1`/`x`/`y` are recorded even though none of those values ever crosses the wire.

- **2026-09-07** — Fuzz reach: `fuzzShareDecode`'s "half the draws come from a REAL
  encoding" branch had never executed once. The branch gate was `smith.value(bool)`, the
  harness's FIRST draw; a `Smith` scalar draw reads eight octets as a little-endian `u64`
  and returns the range minimum when fewer remain, and the target carried no corpus, so
  outside `--fuzz` the one input it ever ran was empty, the bool was always false, and
  `smith.bytes` over an empty input left the share all zeroes. Every run decoded 65 zero
  octets — tag 0 with a 64-octet body, `error.InvalidEncoding` — so neither `M` nor `N`
  nor any near-miss ever reached `fromSec1`, and `proverFinish` returned before any scalar
  multiplication. The 2026-09-01 fix for the harness's SHAPE (buffer pinned at
  `share_length`, no more 33-octet compressed draws) bought nothing while the DRAW was
  still collapsed. The coin flip is gone: the share now comes from one byte-first
  `smith.slice`, and the real encodings are a written corpus of 10 seeds — `M`, `N` and
  `G` uncompressed, `M` with a flipped y-octet, a flipped tag, an identity tag over a
  64-octet body, x = p, the unreachable compressed form, a bare tag and the empty share.
  A corpus guard pins 9 non-empty, 3 parsed and 3 on-curve.

- **2026-09-01** — Security audit. `verifierConfirm`'s documented gate did not hold:
  `VerifierConfirmResult` withheld the `k_shared` FIELD while returning `tt` and `k_main`,
  and each of those is a one-call pre-image of `K_shared` through this module's own public
  `deriveKeys`/`kdf` — measured, at the moment the Verifier has never seen a `confirmP`,
  which is exactly the "silently-unauthenticated key" SPEC.md named as the worse defect.
  The struct now carries `confirm_v` and nothing else and frees its own transcript; the
  byte-exact coverage the removed fields carried is unchanged, since `verifierFinish`
  recomputes and returns the same values after the confirmation check. Scoped honestly in
  the docs: this stops a caller's accident, not a hostile Verifier, which holds every input
  needed to recompute the schedule anyway.
  Guards that held nothing, now pinned: `verifierConfirm`'s two RFC 9383 §6
  group-membership checks (added as a third wire-facing entry point in `7386e724` and never
  added to the §6 test set — both could be deleted with the suite green in Debug and
  ReleaseFast), and all twelve `rejectNonCanonical` call sites (the group operation reduces
  mod `n` silently, so `basePoint.mul(n+1) == basePoint.mul(1)` — without the guard a
  non-canonical encoding aliases onto a canonical one). Added the mismatched-password run
  the suite never had, and a source-text gate on the constant-time claim, after
  `computeL`'s multiply over the secret `w1` was swapped for the variable-time `mulPublic`
  with all 29 tests green. ⚠ That gate pins the CALL SITE, not timing: `p256` has no
  `ctgrind_harness.zig`, so neither module is in the `ct` set covering `k256`/`montint`.
  `fuzzShareDecode` rebuilt: it drew a random length in [0, 96] and reached a parsing point
  0.008% of the time, **never once in the 65-byte uncompressed form that is the only
  encoding this module accepts** (0 of 20,000,000 draws) — it was fuzzing the compressed
  path no caller can reach. Now fixed at `share_length`, half the draws perturbing a real
  encoding, driven through the public entry point: 10.0% reach the parse, all uncompressed.
  Docs: `NOTICE` still declared the module a scaffold of `@panic` stubs and carried no
  BoringSSL provenance entry; SPEC.md called `computeW0W1` unanchored in four places and
  omitted the BoringSSL goldens from its anchor evidence; both named `std.crypto.ecc.P256`
  as the group. SPEC.md gained the two obligations it was missing for a PAKE — the
  fail-closed entropy source `x`/`y` must come from (CONVENTIONS.md §2.2; a predictable `y`
  makes `w0*N = shareV - y*P` recoverable and collapses this to an OFFLINE dictionary
  attack) and failed-attempt rate limiting, which RFC 9383 §6 does not require and an
  implementer reading it as a checklist will therefore omit.
- **2026-08-23** — False-anchor fix: the documented "Protocol flow" (README.md) could not
  actually run. `proverFinish` requires the Verifier's `confirmV` as an input and
  `verifierFinish` requires the Prover's `confirmP` as an input, so two genuinely blind
  parties deadlocked — neither could produce a value the other needed first. This went
  unnoticed because `kat_test.zig`'s end-to-end test fed the Verifier's probe call the RFC
  9383 Appendix C vector's already-published `confirmP`, and `example/main.zig` worked
  around it by reconstructing `verifierFinish`'s internals from lower-level primitives.
  Fixed additively: a new `verifierConfirm` function computes the Verifier's `Z`/`V`/`TT`/
  key schedule and emits `confirmV` with no `confirmP` input required (matching RFC 9383
  Appendix A.5's actual message order, where the Verifier transmits `confirmV` before ever
  seeing `confirmP`) — deliberately does NOT return `K_shared`, since RFC 9383 §3.3
  requires validating the peer's confirmation before either party may consider the
  protocol complete. `proverFinish`/`verifierFinish` are unchanged. README.md, SPEC.md,
  and `example/main.zig` updated to the real, runnable, blind two-party flow; `kat_test.zig`
  gained a byte-exact KAT for `verifierConfirm` and a property test that drives both parties
  with no foreknowledge of either confirmation value (proven, via temporary removal of
  `verifierConfirm`, to fail to compile against the prior API).
- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Byte-exact against RFC 9383
  Appendix C's published test vectors.
- **2026-07-12** — New module: SPAKE2+ — an augmented (asymmetric) PAKE (RFC 9383),
  P-256/SHA-256/HKDF/HMAC ciphersuite (the Matter/Thread commissioning PAKE) —
  `proverStart`/`verifierStart`.
