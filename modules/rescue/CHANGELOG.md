# rescue — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Portability fix (`check-portable`), test-only: "pow ladder agrees with
  repeated multiplication" looped `for (0..e)` where `e: u64` — a for-range bound must be
  `usize`, which fails to compile on a 32-bit target. `pow`'s real API keeps `e: u64`
  deliberately (a Goldilocks exponent can genuinely range up to the field modulus,
  ~2^64, e.g. inversion via `pow(a, P - 2)`); this test only ever exercises `e =
  rnd.int(u8)` (0..255) to cross-check against repeated multiplication, so narrowing just
  the loop bound is always in-range by construction. Compile-only, identical semantics —
  no new test. Verified: `zig build portable-rescue` and `zig build test-rescue
  --summary all` (46/46) both green.
- **2026-08-14** — Documentation, neither BREAKING nor BEHAVIOURAL.
  `params.zig` called itself "a line-by-line port" of the authors' sage
  reference while the same doc comment said everything in it is derived
  rather than remembered. It reimplements the algorithm and carries no
  number across, so "reimplementation" is what it says now. The wording is
  not cosmetic: that reference is Apache-2.0 with no MIT alternative, and
  "port" is the word that earns a module an attribution file here — it is
  what `minisign` was attributed for on the same day.

- **2026-08-14** — Licensing record. Not breaking and not behavioural — no code
  changed, and no digest this module produces is different. What changed is
  what the module admits to carrying: its constant tables and part of its
  known-answer vectors are numbers a script lifted out of two third parties'
  Rust source (facebook/winterfell's `rp64_256`, miden-crypto's
  `rescue`/`rpo`), which is reproduced DATA, not the black-box test-oracle
  relationship the module had been recorded under. A new
  `modules/rescue/NOTICE` reproduces both projects' MIT terms in full and is
  listed in root NOTICE §1. miden-crypto is dual-licensed `MIT OR Apache-2.0`
  and MIT is elected, so the only condition a consumer sees is still "keep the
  notice with the files" — the same shape as every other condition in this
  repository. Two things are recorded as NOT owed, with the argument rather
  than the verdict: the RPO report's own 38 published test vectors are
  specification material (cited in `SPEC.md`, not attributed), and the miden
  ARK tables reproduce from the published generator — all 168 values — so they
  are this module's own derived numbers rather than upstream's. The README's
  `Provenance:` line was corrected: it had pointed at `SPEC.md` as the place
  the tables were "attributed", and `SPEC.md` is the verification-methodology
  file, not an attribution location.

- **2026-08-06** — Security audit: three findings fixed, two documented as accepted (not
  defects) — part of the collection-wide audit. Verified: byte-exact against three
  independently-verified upstream vector sources (each pinned by commit hash and file
  SHA-256).
- **2026-07-29** — New module: Rescue-Prime Optimized (RPO) over Goldilocks
  `p = 2^64 - 2^32 + 1`, at both published instances (`m = 12`, `m = 16`),
  both sponge framings that exist upstream, and the paper's round order
  as a separate permutation. The sibling to `poseidon`: same motivation
  (cheap inside a circuit), opposite trade — Rescue alternates `x^α` with
  `x^(1/α)`, which is far more expensive in software and cheaper to
  prove. Measured here: the inverse S-box layer is **15x the forward one
  and 76% of the whole permutation**; hashing 512 bytes costs 61x
  SHA-256. The field lives inside the module (~240 lines, canonical,
  branch-free) rather than becoming a new general-purpose module.
  **The variant was chosen on anchoring, not deployment**: plain
  Rescue-Prime's reference implementation publishes **no** test vectors,
  while RPO publishes 38. Constants are derived (SHAKE256) and pinned
  element-by-element against miden-crypto's embedded values; `1/α` is
  computed and checked three ways, including replaying its 72-multiply
  addition chain symbolically over exponents. Three upstream divergences
  are documented rather than smoothed over: miden-crypto changed its
  state layout in a breaking PR so every digest changed (a single-value
  test tells the corpora apart); the two RPO sponges disagree on padding,
  capacity placement and the empty input, so both ship with a test
  asserting they never collide; and **Winterfell's Rescue-XLIX round
  constants could not be re-derived** from the generator its own comment
  cites, so that one table is an honestly-labelled embedded blob pinned
  by file digest plus the published KAT — while the same generator
  reproduces miden's RPO tables exactly. Constant-time throughout (the
  inverse S-box is a fixed addition chain, not a ladder), not
  disassembly-verified. Byte-level hashing is grade-2 anchored: no
  upstream byte KAT exists anywhere in miden-crypto.
