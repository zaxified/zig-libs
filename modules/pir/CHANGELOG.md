# pir — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- Malicious-server detection (`Verified(...)`). The module's model was
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
  tests, not left implicit. Privacy is unchanged, and the abort verdict
  is index-independent, so the check adds no selective-failure oracle.
  `S = 0` is a `@compileError`: in the un-widened ring
  `m·2^(8L-1) = 2^(8L-1)` for every odd `m`, so a top-bit forgery would
  pass with probability 1. Querying past the database now **rejects**
  rather than reconstructing to zero, because an honest all-zero answer
  is indistinguishable from the coordinated-zeroing forgery the presence
  word exists to stop. Authenticated PIR against a published digest
  (Colombo et al.) is the composable upgrade and is named as such;
  cross-checking by repetition was rejected outright, since a server
  adding the same constant every time produces identical wrong
  reconstructions.

- Keyword lookup — `keywordIndex` / `queryKeyword`, also under
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
