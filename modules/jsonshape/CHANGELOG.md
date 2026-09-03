# jsonshape — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit (710 lines since the last one, i.e. most of the
  module). ⚠ **BREAKING:** `Error` gained `TooManyMatches` and `ShapeSpec` gained
  `max_matches`.
  - An out-of-range JSON number reached a bare `@intFromFloat`. A remote `1e300`
    into an `.int` column was undefined behaviour: SIGABRT in Debug **and**
    ReleaseSafe, silent i64-minimum in ReleaseFast — three modes, three answers,
    none of them SPEC.md's "a shape mismatch never panics or propagates as an
    error". Now degrades to `.null` like every other mismatch.
  - The `.decimal` column had the same defect one module over, with the guard on
    the **wrong value**: `dataset`'s `Value.cast` checked `isFinite(f)` and then
    converted `f * 1e12`, so a finite `1e30` reached `@intFromFloat` as `1e42`,
    which does not fit `i128`. `dataset.Value.asInt` had a bare `@intFromFloat`
    on its own public API. Both fixed there, via a new `Value.floatToInt`.
  - **`MAX_PATH_DEPTH` was advertised as the DoS control and is not one.** It
    bounds depth; `..name` visits every value at every level, so matches grow
    with the document's *branching*. Measured with a fixed, operator-written
    6-byte path (`..a..a`) where only the document is hostile: 163,831 B →
    393,220 rows, peak RSS 65 MiB (~417x), superlinear. New `MAX_MATCHES`
    (65,536, overridable) bounds matched nodes **and** the items they flatten
    into — bounding matches alone is the same mistake one level down, since one
    match that is a large array becomes that many rows.
  - Three guarantees had no gate at all, each verified by mutation: raising
    `MAX_PATH_DEPTH` to 4,000,000 left the suite green (and segfaulted a 1.2 MB
    document); deleting the `.index` bounds check left it green with an
    out-of-bounds read; and the test named "back-compat — legacy dot-path
    resolves identically" stayed green with `isLegacyPath` forced to always
    return false, because both engines agree on its fixture. All three now have
    tests, each seen red under exactly that one-line mutation.
  - Docs: README claimed `..name` "finds every `name` field anywhere under the
    current node" (it stops at depth 64, silently) and understated the error set.
    This entry also covers `51a369c3`, which added the entire JSONPath dialect —
    a second path language with no changelog entry at all.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on jq (C) (design
  reference, not a test anchor).
- **2026-07-09** — New module: JSON → `dataset` reshaping — dot-path descent + typed
  column projection (jq-style minimal subset).
