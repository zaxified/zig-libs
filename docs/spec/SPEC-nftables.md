# SPEC — `nftables`

**Purpose** — Let a program manage the Linux firewall from typed Zig instead of assembling `nft`
command strings by hand: build tables/chains/rules/sets with a typed API and serialize them to the
documented libnftables JSON that `nft -j -f -` applies (or `nft -c -j -f -` checks). The module
produces portable JSON data — it is a codec, not a firewall.

**Model after / Seed** — clean-room from the documented libnftables JSON schema
(libnftables-json(5) man page + the nftables wiki "JSON representation"). Greenfield — no seed. No
libnftables (or any other nftables) source consulted or copied; libnftables itself is GPL and is
referenced solely as the specification of its JSON interchange format (an interface, not code). See
`NOTICE`.

**Design & invariants**
- **std.json is the whole serializer.** Every vocabulary enum whose tag names equal the schema
  tokens verbatim relies on default `@tagName` serialization; the handful whose tokens are not Zig
  identifiers (`==`, `fully-random`, `tcp reset`, `queue-threshold`, `auto-merge`, …) carry a custom
  `jsonStringify`. Output is minified and, by construction, byte-stable.
- **Typed model mirrors the schema tree:** `Expr` (match RHS / set elements / NAT args — payload
  fields, raw payload, `meta`, `ct`, prefixes, ranges, anonymous & `@named` sets, concat), `Stmt`
  (verdicts, counter, log, limit, reject, masquerade/redirect/snat/dnat), and `Object`/`Cmd`
  (`add`/`create`/`delete`/`flush` over table/chain/rule/set + `flush ruleset`). A fluent
  `RuleBuilder` (`.tcpDport().accept().apply()`) is sugar over the same `Stmt` slices.
- **Allocation model:** `Ruleset` owns an arena; borrowed strings and expression slices must outlive
  it, but statement arrays passed to `addRule` / accumulated by `RuleBuilder` are copied into the
  arena, so rules may be built in temporary storage. `RuleBuilder` latches OOM and reports it from
  `apply()`, keeping the chain ergonomic. Reentrant; no globals.

**Threat model / out of scope** — **This module only emits JSON; it never touches netlink and never
applies anything** — applying requires the Linux `nft` binary (which needs CAP_NET_ADMIN), and the
module itself is `platform: any`. It is a builder, not a validator: it does not verify that a
referenced chain/set exists, that a payload field name is real, or that a ruleset is semantically
sound — that is `nft`'s job (`nft -c` catches it). String fields are properly JSON-escaped
(including `@set` references), so a hostile name cannot break out of the JSON, but the module makes
no claim about what a caller-supplied name *means* to `nft`. Coverage is the ruleset-building subset
of the schema; stateful/introspection commands (`list`, `reset`, `monitor`), maps, flowtables and
the full expression zoo are out of scope.

**Verification** — Offline golden-JSON known-answer tests: byte-exact serialization of full
rulesets (inet filter with default-drop input chain; ip nat masquerade postrouting; named port set
used in a rule), every non-identifier enum token, expression/statement shapes, delete+flush command
shapes, JSON-escaping of set-ref names, and equivalence of the fluent builder vs a hand-written
`Stmt` slice — each also parsed back with `std.json` to prove well-formedness. When an `nft` binary
is present, the suite additionally pipes a generated ruleset through `nft -c -j -f -` (check mode,
never applied; tolerates the unprivileged netlink-cache EPERM as long as the parser accepted the
JSON) and confirms `nft -c` rejects a deliberately schema-invalid ruleset.

**Status** — `gap · any · codec · reentrant` · deps: none (std only).
