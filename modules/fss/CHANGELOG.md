# fss — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- `Mpf.evalEachFullWith` / `evalFullWith` / `evalFull` — the multi-point
  counterpart, and the interleaved walk the `Dpf.evalFull` entry below
  recorded as the right answer for `Multi(k)`. ONE descent of the domain
  prefix carries all `k` tree states side by side and emits every
  instance's share at each index, instead of `k` per-point evaluations
  (`k·N·n` PRG calls) or `k` separate prefix walks (which would have
  turned one pass over the consumer's data into `k`). Cost per index
  drops from `k·n` PRG calls to `~k`: measured **495 ms → 52 ms** (~9.5x)
  for a full 2^14 domain at `k=4`, and **43.1 ms → 3.0 ms** (~14x) for a
  500-point prefix of a 2^20 domain at `k=8`. Same construction, same
  keys, same outputs — a traversal-order change only, with the
  sum-of-`k`-DPFs construction and its `k·N` evaluation count untouched
  (the cuckoo/batch-code alternative stays scoped out). `evalEach` stays
  naive as the differential oracle, and the walk's index-range-only
  pruning keeps the emission sequence a function of the prefix length
  alone.

- `Dpf.evalFull` / `evalFullWith` — one tree traversal that emits every
  leaf, instead of re-walking the tree from the root per point. Cost
  drops from `O(N log N)` PRG calls to `O(N)`: measured **570 ms → 52
  ms** (~10.9x) for a full 2^16 domain, matching the `(2n+1)/3`
  prediction. It fills a **prefix**, not only a whole domain — the
  sibling `pir` module's server evaluates `x < database.count()` and
  domains are routinely provisioned far larger than the current record
  count, so a full-domain-only evaluator would have been a regression for
  the common case. Subtrees past the requested prefix are pruned
  **before** the PRG call, so an oversized domain costs nothing: a
  500-point prefix of a 2^20 domain is **5.1 ms → 0.36 ms**. The
  streaming form exists because `pir` has no allocator and no
  runtime-sized scratch — it lets the server fold each value into its
  accumulator as the walk produces it, leaving `answer`/`answerSlices`
  signatures untouched. `evalAll` is deliberately left naive, as a
  structurally independent differential oracle. Both `pir`'s value
  channel and `Verified`'s tag channel are wired to it.

- **BREAKING — the default PRG is now fixed-key AES-128, which changes
  the key bytes.** `Dpf`/`Mpf` were SHA-256; they are now
  `prg.Aes128Mmo`, fixed-key AES in the Matyas-Meyer-Oseas shape with the
  Guo-Kolesnikov-Rosulek-Roy σ pre-mix (`H_j(x) = AES_k(σ(x ⊕ j)) ⊕
  σ(x ⊕ j)`, public fixed key, control bit = the child block's low bit).
  Measured on the same host, in the same binary: raw expansion **2.00
  M/s → 71.8 M/s (36x)**, `Gen` **75.4 k → 1.86 M keys/s (25x)**,
  full-domain `evalFull` **1.21 M → 30.3 M evals/s (25x)** — more than
  the "~10x" it was scoped out with, because AES also halves the
  primitive calls per node (one 128-bit block per child rather than a
  256-bit hash for 17 bytes) and the two children pipeline through one
  `encryptWide`. σ rather than plain MMO because the construction feeds
  the PRG XOR-correlated inputs by design, which is the setting GKRRR
  introduced σ for.

  **What it did NOT buy: interop.** Fixed-key AES removes the primitive
  as an obstacle to matching Google's DPF vectors, but not that
  library's own fixed keys, tweak convention, value-correction scheme or
  protobuf key layout, and there is no published vector file to match —
  so the module stays self-defined, and the claim that this swap yields
  byte-exact external agreement is **wrong** and is corrected in
  `SPEC.md`.

  **The anchor survived, deliberately.** `Sha256Prg` was kept, not
  deleted: `DpfWith` is one body of correction-word code shared by both
  instantiations, so the recorded independent-re-derivation KAT vectors —
  stated over SHA-256 — still pin that code byte-exact. No vector was
  regenerated or self-generated. New, and genuinely external as far as it
  goes: the MMO step is pinned against FIPS-197 Appendix B's AES-128
  example, which anchors the AES call and explicitly nothing above it.

  **Key format.** Both PRGs give keys of the *same length* and different
  contents, so an old key decodes silently and evaluates to garbage.
  `Dpf`/`Mpf` gained `DpfWith`/`MpfWith` (PRG chosen explicitly),
  `Key.key_format` (`"fss.dpf/aes128-mmo/v1"`), and a tagged STORAGE
  codec `Key.toBytesTagged`/`fromBytesTagged` that rejects the other
  PRG's key with `error.UnsupportedKeyFormat`. The wire codec
  `toBytes`/`fromBytes` is unchanged and stays header-free — `pir`
  asserts a query share carries no structurally-constant bytes, so a tag
  byte belongs in storage, not on the wire, and on the wire the PRG is
  out-of-band geometry like `n`, `L`, `k`. Removed: the free
  `prg.prg`/`prg.convert` functions (now `prg.Aes128Mmo`/`prg.Sha256Prg`
  methods) — a compile error rather than a silent change of function.

  **Constant time**, closing the other scoped-out item: `Gen` and every
  evaluator now drive the α path bit and the running control bit through
  XOR-masked selects instead of branches. Remaining caveat, in the PRG
  and not the tree — on targets without hardware AES std falls back to a
  mitigated but not constant-time T-table; `prg.Aes128Mmo.constant_time`
  reports it and `DpfWith(prg.Sha256Prg, …)` is the constant-time-
  everywhere choice.
