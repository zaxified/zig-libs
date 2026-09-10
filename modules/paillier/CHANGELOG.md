# paillier — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — A1 fix campaign, wave 3 (F1/F2/F5 of `A1/paillier.md`;
  see that file's "Dispozice 2026-09-10" for the measurements). No public
  signature changed.
  - **F1 (HIGH) fixed:** `encryptRandom`'s rejection sampling
    (`sampleNonzeroLtN`) now redraws explicitly against `n` itself. The old
    redraw compared against `n_sq` instead (dead: an `n_len`-byte draw can
    never reach `n_sq`), so roughly the top of the masked range silently
    folded onto its residue `r - n` rather than being redrawn — measured
    **738 of 4,000 draws (18.45%) landed >= n** before the fix, **0 of
    4,000** after (fresh in-tree measurement; the audit's own independent
    probe, different key/seed, measured 28.90% of 50,000).
  - **F2 (HIGH) narrowed, not closed:** `decrypt`'s helper functions
    (`decryptNonCrtX`, `decryptCrtX`) took the whole `SecretKey`/`CrtParams`
    by value, leaving copies of secret material in their own stack frames
    that `SecretKey.deinit()` — which only reaches the caller's struct —
    could never zero. Switched both to pointer parameters, zeroed the
    secret exponent's limb form in `montPowSecret`, and zeroed
    `decrypt`'s own by-value copy on every exit path. A poisoned-stack probe
    (kept in-tree, ReleaseFast-only) measured **10 full-value secret copies
    before the fix → 1 after** (λ limb image 1→0, λ big-endian 2→0, μ 2→1,
    dp 2→0, dq 2→0, CRT block 1→0). The one remaining μ copy is traced to
    `decrypt`'s last line passing a secret `Fe` by value into
    `std.crypto.ff.Modulus.mul` — a standard-library parameter-passing copy
    this module has no address to zero (confirmed by giving `mul` a
    module-controlled local to pass instead: no change in the count).
    **Left open** in `A1/paillier.md`.
  - **F5 (MED) fixed:** `mulPlaintext` routed through `montint`
    (`montModexpSecret`, the same path `decrypt`'s non-CRT fallback uses)
    instead of `std.crypto.ff.Modulus.pow`. Measured (2048-bit key,
    `k ~ 2^256`, 40 reps): **132.8 ms/op → 25.2 ms/op (~5.3× faster)**,
    ratio to `decrypt` **17.1× → 3.2×**. Still constant-time in `k`'s
    *value* (full-width ladder, no exponent-width trim); correctness
    unchanged per the existing homomorphic-property tests.
  - SPEC.md's "Constant-time discipline" and "Design & invariants", and
    README.md, described `decrypt`/`mulPlaintext` as using
    `std.crypto.ff.Modulus.pow` — stale since `6b587a5` (montint + CRT) and
    now this session's F5; updated to describe `montint`, and README now
    shows `SecretKey.deinit()` in the API example (it was the only way to
    clear a key and wasn't mentioned) — paillier F3/F12, wave-3 audit.
  - Touches `src/root.zig`, which carries a `scripts/ctgrind-expected.tsv`
    pin (4 rows, added `c2eee166` after this audit was written) — these
    edits invalidate that pin's source digest; needs a coordinator re-pin
    before the tier-A ctgrind queue is trusted again for this module.

- **2026-09-10 (mop-up)** — A1 fix campaign, closing out what wave-3 left
  unattempted (`A1/paillier.md` F6/F7/F10; see that file's "Dispozice
  2026-09-10 (mop-up)" for the measurements). No public signature changed.
  - **F6 narrowed, not closed.** Its first half (the three byte-loader fuzz
    harnesses reach only the empty-string input via a broken length draw)
    was **already fixed, not by this session**: a different commit
    (2026-09-07, see below) replaced `fuzzedFieldBytes` with a
    corpus-seeded `smith.slice` before this session started — the audit's
    own commit reference predates that fix by a month of in-repo history,
    so this half of F6 was stale on arrival. Confirmed in-tree rather than
    assumed: the code the finding describes (`smith.bytes` + a post-hoc
    ranged length draw) is not present. Its second half — **`decrypt`,
    the only entry point that processes a value from a possibly-hostile
    counterparty, has no fuzz harness at all** — is still true (confirmed:
    `grep -c 'test "fuzz'` finds the three byte-loader targets and no
    fourth). Adding one needs a value oracle (compare against a second,
    simpler decryption), not just "didn't panic" — left open, M-effort.
  - **F7 narrowed, not closed:** added two permanent regression tests.
    (1) `encryptRandom` freshness — pins that repeated calls on the same
    key/message never produce the same ciphertext (kills the audit's own
    "m5" mutant, constant `r`); RED confirmed by temporarily hardcoding
    `sampleNonzeroLtN`'s return value (fails on the 2nd draw), GREEN
    restored. (2) a composite-factor rejection test — but the audit's own
    "m11" claim (that `fromPrimesImpl`'s `rem.eqlZero()` invertibility
    check, ~line 790, is "precisely the guard composite rejection relies
    on") turned out to be **REFUTED**: disabling that exact check and
    exhaustively re-running `fromPrimes` over all 64×63 ordered pairs of
    composites in [4, 99] produced a byte-identical accept/reject
    partition with the check on and off. Something else (most likely
    `bigModInverse`'s implicit `gcd = 1` check a few lines later) is doing
    the actual rejecting — not traced further. The new test pins the
    *observed* behavior (this class of composite factors is rejected), not
    the specific line. `m7` (Miller-Rabin round count untested against a
    weak witness), `m8` (`topBitsMatch` untested at its `generate` call
    site) and `m9`/`m10` ("test passes by the wrong route", not confirmed
    redundant the way `m1`/`m2`/`m16` were) remain open — each needs
    deliberately engineered adversarial values or PRNG streams, out of this
    session's budget.
  - **F10 closed:** its two components were (a) a numeric characterization
    of composite-factor garbage decryption, already documented
    qualitatively in SPEC.md and requiring no code change, and (b) the same
    "m11 is mutation-invisible" claim F7 addresses above — now refuted with
    evidence rather than left as an unverified audit assertion.
  - **F8 left open — question for the user**, not attempted: no minimum
    key-size floor on `PublicKey.fromBytes`/`SecretKey.fromBytes`/
    `fromPrimes` (unlike `rsa`'s 512-bit floor), but the module's own KATs
    use an 8-bit toy key (`kat_p = 11, kat_q = 17`) — a floor would need a
    test-only bypass or a rewritten KAT. See `A1/paillier.md`.
  - Touches `src/root.zig` again — same stale-ctgrind-pin note as the
    wave-3 entry above applies to these edits too.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **crt 331 / noncrt 141 / mul 12 / addm 10**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. ⭐ Confirms both leads `threshold_ecdsa` raised indirectly, and CORRECTS one: the L-function's variable-time `divFloor` is real on every run, but at `root.zig:1253`, not the `:1205`/`:1213` that report cited — `:1205` is the PUBLIC ciphertext check and correctly never fires under taint. `mulPlaintext`'s `if (k.isZero())` at `root.zig:1304` is confirmed exactly, is a direct branch on a raw secret exponent, and is **not mentioned anywhere in SPEC.md** — an undocumented gap rather than a contradicted claim. ⭐ SPEC's binomial-shortcut claim ("a possibly-secret plaintext `m` never enters a bit-scanned exponent path") is true of this module's own control flow but NOT end to end: `std.crypto.ff.Modulus.mul`'s Montgomery machinery branches on `m`, **verified by disassembly to be a real `test`/`jne` and not a `cmov`** — the first agent in this campaign to settle that question by instruction rather than argument.

- **2026-09-07** — The three byte-loader fuzz targets had never parsed a field. Every draw
  went through `fuzzedFieldBytes`, which opened with `smith.bytes(buf)` and then took its
  length from a ranged draw — and a ranged draw returns the range minimum once `bytes` has
  eaten the input, so the length was 0 for every field on every input. With no corpus
  either, the lane ran exactly one call per target: `PublicKey.fromBytes("", null)`,
  `SecretKey.fromBytes("", "", "")`, `Ciphertext.fromBytes(pk, "")`. ⛔ Two of the biases
  the helper existed for were dead for a second, independent reason: they hung on
  `smith.value(bool)` drawn *after* the byte draw, so the input was exhausted and the bool
  was false every time. The leading-zero run (`stripLeadingZeros`) never happened once, and
  `g_bytes` was `null` on every single run — `PublicKey.fromBytes`'s explicit-generator
  branch had **never executed**, and no corpus could have fixed that without changing the
  harness. The draw is now one `smith.slice`, an empty second frame means "standard
  generator `g = n+1`" so the seed decides, and both biases live in the corpus where they
  are reproducible: the boundary lengths are seeds sized by the same `boundaryLen` the dead
  knob used, and a leading-zero run is a seed with leading zeros. The positive seeds come
  from a real 512-bit key this module generates, because a `lambda` canonical mod `n²`
  beside a `mu` canonical mod `n` for the same `n` is not a shape any draw produces.
  Measured: 16/17, 10/12 and 7/8 seeds carry a non-empty first field where 0 did; 10, 6 and
  5 accepted, of which **2** went through the explicit-`g` branch, **4** distinct `n`
  bit-widths came back out, and **3** ciphertexts were non-zero. The last number is pinned
  rather than `accepted` because `stripLeadingZeros("")` is `""` and `Fe.fromBytes` reads
  that as zero — the empty input this target ran for ever is *accepted*.

- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Value-exact vs `phe`
  (python-paillier) 1.5.0. Toy key p=11,q=17: n_sq/λ/g/µ and concrete (m,r)→c
  cross-checked (`root.zig:1000,1026`, NOTICE).
- **2026-07-14** — New module: Paillier additively-homomorphic PKE (P. Paillier,
  EUROCRYPT 1999) over `std.crypto.ff`.
