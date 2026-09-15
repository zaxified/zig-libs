# bulletproofs — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-15** — Audit finding B12. Security fix, no API change: `prove` left
  secrets on the dead stack that `secureZero` on its named locals could not
  reach. Measured at ReleaseFast after `prove(n=64)` returned: `v_bytes` ×1 on
  the audited tree; `v_bytes` ×1, `z²·γ` ×1 (with the public challenge `z`
  that is the blinding factor, and with `V` the witness) and 6 of the 132
  random blinding scalars on the tree before this change. `prove` now runs its
  computation one frame down (`proveInner`) and zeroes 128 KiB of stack below
  it before returning, on the error path too; the call tree reaches 46 856 B for
  every `n` from 8 to 128. `stackprobe_test.zig` used to print one count for
  `v`; it now asserts zero residue for `v`, `v_bytes`, `γ`, `z²·γ` and every
  random scalar `prove` drew (recorded by a test-build-only hook in
  `randomScalar`), beside a negative and a positive control.

- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE (prover performance):** audit
  finding B9. The prover's constant-time MSMs (`A`, `S`, every IPA `L`/`R`)
  ran one full ladder per term; `multiScalarMul` now calls
  `ct25519.mulMultiRistretto`, Straus's interleaved window with the doublings
  shared across terms — still constant-time in every scalar, zero included.
  Same group element as the old loop, which is kept verbatim as the
  reference of the new `B9 diff` test; the `ipa` ctgrind output digest is
  unchanged. ReleaseFast A/B: `prove` n=64 47.3 → 34.6 ms (1.37×), n=32
  23.4 → 15.7 ms (1.50×); `verify` (untouched) 0.99×/1.00×.

- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE (verifier performance):**
  audit finding B8. `verify` no longer materialises the rescaled generators
  `h'_i = y^{-i}*H_i` — `n` constant-time ladders over data with no secret in
  it. `y^{-i}` is folded into the coefficients of the two MSMs `h'` fed
  instead (`(c*s)*H == c*(s*H)`, exact in the prime-order group for every
  scalar, zero included). Measured A/B against the previous verifier, same
  process, ReleaseFast, CPU time, 9 interleaved rounds, median µs per
  verify: n=8 2394 → 2048 (1.17×), n=32 4950 → 3305 (1.50×), n=64 7887 →
  4720 (**1.67×**); the paired per-round ratio never fell below 1.12, 1.45
  and 1.44 respectively. `prove` is untouched (its `h'` feeds the recursive
  IPA fold as real points). `verify`'s and `verifyIpa`'s signatures and
  verdicts are unchanged; new internal decls, not re-exported from `root.zig`:
  `ipa.equationSides`/`ipa.EquationSides` (`verifyIpa`'s body with an
  optional per-index H scale) and `rangeproof.verifyTraced`/`VerifyTrace`.
  The previous verifier is kept verbatim in `src/verify_b8_diff_test.zig`,
  which requires `P` and both IPA equation sides to be byte-identical between
  the two on honest proofs at n=1..64 and on every forgery class listed
  there; see SPEC.md "B8".

- **2026-09-11** — **API CHANGE:** `prove`'s secret witness parameter changes
  from `v: u64` to `v: *const u64` (audit finding B12). The old by-value
  parameter left a copy on the caller-owned argument-passing stack slot that
  `prove`'s own `secureZero` calls (already covering `v_bytes` and every
  other witness-derived scratch buffer) could not reach; `prove` also now
  reads `v.*` into a local it owns exactly once and `secureZero`s that
  local, rather than dereferencing the pointer 64 times across the
  bit-decomposition loop (measured: doing so gave the optimizer room to
  spill the value to an equally uncleaned second copy). `Q3` of
  `QUESTIONS-ROUND-2.md`: a signature change forced by a measured leak is
  free on a module with zero consumers in this repository (confirmed:
  `rg -n '"bulletproofs"' build.zig` names only the module's own entry, and
  no `example-apps/*/build.zig` references it). ⚠ **Not fully closed**: a
  dead-stack scan (`src/stackprobe_test.zig`) still measures 1 residual copy
  of `v` after both changes above, traced to a second materialization of
  `v_bytes` around the `commit(gens, v_bytes, gamma)` call that the same
  `secureZero` does not reach — see `A1/bulletproofs.md` B12 and the probe's
  doc comment. All call sites in this module (`kat_test.zig`,
  `ctgrind_harness.zig`, `example/main.zig`) and the README snippet are
  updated to pass `v` by pointer.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** the last three stale claims from audit finding B11 are corrected, all verified against the tree rather than taken from the record. `NOTICE` said **"Status: scaffold"** with `ipa.proveIpa`/`rangeproof.prove` described as `@panic("TODO(fable/core): …")` stubs — there is not one such stub left and `gate.core_implemented` is `true`; it also said `meta.deps = .{}` when it is `.{"ct25519"}`. `SPEC.md` listed a "Pippenger/windowed `multiScalarMul`" as out of scope, but `scalarvec.multiScalarMulVartime` exists and `ipa.verifyIpa` uses it (deliberately variable-time: its inputs are the public proof and public generators; a windowed CONSTANT-time MSM, which the prover would need, is what is still absent). ⭐ The other two B11 rows — README and SPEC "Caveats" claiming the prover is "Not constant-time" — were already fixed on 2026-09-09 by the ctgrind pass, so they are left alone; an audit record is always older than the tree. ⚠ The "scaffold" wording is corrected in place with a note saying it stood long after it was true: a status line that under-reports is the same defect as one that over-reports, and this module had one of each at the same time.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **rangeproof 0 / ipa 0**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. **Zero in-file contexts in both targets** — nothing in `rangeproof.zig`, `ipa.zig`, `scalarvec.zig`, `generators.zig`, `transcript.zig`, or the `ct25519` delegate. ⭐ This is why `SPEC.md`'s and `README.md`'s "Not constant-time" caveat was rewritten in the same commit: it described a `catch continue` that audit finding F2 removed, and which now survives only in comments about the shape it replaced. The staleness ran in the unusual direction — the code improved and the documentation advertised a side channel the module no longer has. ⚠ `prove` draws its own blinding internally via `getrandom(2)`; the harness cannot taint that without editing the module, so it is outside this measurement and the SPEC says so.

- **2026-09-07** — **Test-only: both proof decoders were only ever handed the
  empty slice.** `ipa.fuzzFromBytesAlloc` and `rangeproof.fuzzFromBytesAlloc`
  opened with `smith.bytes(&buf)` and then drew
  `smith.valueRangeAtMost(u16, 0, buf.len)`; `bytes` consumes
  `@min(buf.len, in.len)` octets, so the ranged draw found fewer than the
  eight it reads as a little-endian `u64` and returned the range MINIMUM.
  `len` was 0 for every input the ordinary test lane can carry, and both
  decoders refused it on their length guard (`bytes.len < 4`,
  `bytes.len < 32*7`) without reading an octet — **`Ristretto255.fromBytes`
  had never been called from either target, nor had the attacker-declared
  `rounds` field ever been read.** Both now draw with one `smith.slice(&buf)`
  over hand-written corpora built around that field. Measured 2026-09-07:
  **IPA 0 of 13 seeds non-empty and 0 proofs decoded before, 12 and 4 after,
  over 17 decoded rounds; range proof 0 of 12 and 0 before, 11 and 3 after,
  over 7 nested IPA rounds.** ⭐ `accepted > 0` would have been a weak guard
  in both: a `rounds = 0` inner-product proof is legal and carries no points
  at all, so the guards pin the rounds decoded — the attacker-declared work
  the decoder actually performed — beside the accepted count. The corpora
  include `rounds = 0xffffffff`, whose `expected_len` is 274 GB and which must
  be refused before any allocation.

- **2026-07-18** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on
  dalek-cryptography/bulletproofs (Rust) / libsecp256k1-zkp (design reference, not a
  test anchor).
- **2026-07-16** — New module: Bulletproofs — zero-knowledge range proofs over
  Ristretto255 (Bünz/Bootle/Boneh/Poelstra/Wuille/Maxwell, IEEE S&P 2018, eprint
  2017/1066) — prove a Pedersen-committed value.
