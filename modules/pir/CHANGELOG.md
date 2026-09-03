# pir — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit. `PirWith`/`VerifiedWith` are now **exported
  from `root.zig`**: they existed since 2026-08-07 and `SPEC.md`
  "Constant-time PRG selection" and `README.md` both instruct a caller on a
  soft-AES target to use them, but neither was reachable through
  `@import("pir")` — the escape hatch for a named cache-timing channel on the
  client's own key generation was unreachable by every consumer, and the
  tests that exercised it live inside the module, where a missing re-export
  is invisible. `example/main.zig` now instantiates both, so a compile gate
  outside the module holds them. **`Pir(b, L).Verified(S)` silently dropped
  the chosen PRG** and re-applied `fss.prg.default` to both channels; it now
  forwards it, and the threading test covers `.Verified(S)` and `.Multi(k)`
  as well as `.Dpf`. `privacy_test.zig` gained a calibration control that
  pins `reject_gap` from both sides (a 30 % leak must be rejected, a 10 %
  leak must not) — the two existing negative controls both produce a gap of
  exactly 1.0, so the threshold could be moved anywhere in (0.10, 1.0] with
  the suite green. `answerSlicesRange` no longer rescans the whole slice for
  raggedness on every shard call. `src/bench.zig` prints its build mode.
- **2026-09-02** — Range sharding and an explicit PRG parameter, added over
  2026-08-31…09-02 and recorded here late — the entries below stopped at
  2026-08-07 while the module gained ~900 lines:
  - **BREAKING** — `answerBytesLen` and `tagBytesLen` changed from
    `usize` to `Error!usize` (they now report the geometry overflow they
    previously computed past).
  - New: `PirWith(Prg, b, L)` / `VerifiedWith(Prg, b, L, S)`, taking the
    `fss` PRG explicitly and mirroring `fss.DpfWith`/`fss.MpfWith`;
    `Pir`/`Verified` are these applied to `fss.prg.default`, unchanged for
    every existing caller.
  - New: `answerRange` / `answerSlicesRange` / `accumulate` and
    `error.InvalidRange` — server-side range sharding over `[lo, hi)`, with
    the whole database as the degenerate one-shard case. See `SPEC.md`
    "Range sharding".
  - New: `Query.wipe` / `Secret.wipe`, and
    `selective_failure_advantage_log2`.
- **2026-08-07** — Security audit: seven findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit.
- **2026-07-29** — Malicious-server detection (`Verified(...)`). The module's model was
  honest-but-curious: a server learned nothing about the index but was
  assumed to answer honestly, so a doctored share made the client
  silently reconstruct a wrong record. It now runs a second DPF for the
  same index whose payload is a **client-secret odd scalar `m`**, so the
  tag answer is `m·word` by the protocol's own linearity, checked in a
  widened ring (SPDZ2k-style) together with a presence word. No new
  dependency: the tag key is one more DPF key under the same hiding.
  The security statement, stated exactly because over-claiming here
  would be worse than not building it: **detection, not robustness** —
  the client aborts with `error.AnswerRejected`, does not recover the
  record and cannot say which server lied. Any record-changing deviation
  by ONE server (or by both, if they do not pool keys) is caught except
  with probability `≤ 2^(1-8S) + Adv_PRG`, a function of
  `tag_slack_bytes` alone (2^-63 at the default). **Colluding servers
  forge undetectably** — the same full-domain scan that recovers the
  index recovers `m` — and **two servers holding the same wrong database
  are accepted**, since the MAC binds to the servers' common data rather
  than to a published digest. Both are asserted as `ATTACK NOT CAUGHT`
  tests, not left implicit. Privacy is unchanged. ⚠ **The sentence that
  stood here — that the abort verdict is index-independent, so the check
  adds no selective-failure oracle — was corrected on 2026-09-01**: it holds
  at the recommended `S = 8`, but not uniformly down to the permitted floor
  `S = 1`, where `tag_slack_bytes` is a privacy parameter and not only an
  integrity one. `SPEC.md` "The exact security statement" carries the scoped
  claim; this entry is left in place with the correction attached rather
  than rewritten.
  `S = 0` is a `@compileError`: in the un-widened ring
  `m·2^(8L-1) = 2^(8L-1)` for every odd `m`, so a top-bit forgery would
  pass with probability 1. Under `Verified`, querying past the database
  **rejects** rather than reconstructing to zero as the unverified base
  layer still does, because an honest all-zero answer is indistinguishable
  from the coordinated-zeroing forgery the presence word exists to stop.
  Authenticated PIR against a published digest (Colombo et al.) is the
  composable upgrade and is named as such;
  cross-checking by repetition was rejected outright, since a server
  adding the same constant every time produces identical wrong
  reconstructions.

- **2026-07-29** — Keyword lookup — `keywordIndex` / `queryKeyword`, also under
  `Verified`. `queryKeyword` is literally `query(keywordIndex(kw), …)`,
  and that is the point: the map is total, deterministic and
  unconditional (`LE64(SHA-256(kw)[0..8])` masked to the domain — a mask,
  not a modulo, so no reduction bias, since domains are powers of two),
  so **a query for a missing keyword is byte- and shape-identical to one
  for a present keyword**. Presence never enters the computation, so it
  cannot leave it. That guarantee carries a caller obligation stated in
  the README and at the call site, not buried in SPEC: **one lookup, one
  query, whatever comes back**. A client that consults a local set and
  skips the query, or retries on a mismatch, puts the presence bit back
  on the wire — a test demonstrates exactly that wrapper's leak.
  Collisions are a **correctness** cost, never a privacy one: two
  keywords may share a slot and the loser becomes a false negative
  discovered locally, with the provisioning rule
  `domain_bits >= 2·log2(N) + log2(1/eps) - 1` given for sizing. Under
  `Verified`, a keyword whose slot lies past the database **rejects**, so
  "absent" and "the server lied" are indistinguishable there — a
  deployment wanting verifiable absence must materialise every slot. A
  published key→index map was rejected because it needs the same
  always-query discipline *plus* a distribution and freshness pipeline
  this no-I/O module cannot provide; cuckoo/batch codes stay rejected,
  and would compose above this layer rather than replace it.
