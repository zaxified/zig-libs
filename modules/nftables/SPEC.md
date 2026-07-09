# nftables — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
`std.json` is the whole serializer. Every vocabulary enum whose tag names equal the schema tokens
verbatim relies on default `@tagName` serialization; the handful whose tokens are not Zig
identifiers (`==`, `fully-random`, `tcp reset`, `queue-threshold`, `auto-merge`, ...) carry a
custom `jsonStringify`. Output is minified and, by construction, byte-stable. Typed model mirrors
the schema tree: `Expr` (match RHS / set elements / NAT args — payload fields, raw payload, `meta`,
`ct`, prefixes, ranges, anonymous & `@named` sets, concat), `Stmt` (verdicts, counter, log, limit,
reject, masquerade/redirect/snat/dnat), `Object`/`Cmd` (`add`/`create`/`delete`/`flush` over
table/chain/rule/set + `flush ruleset`). A fluent `RuleBuilder`
(`.tcpDport().accept().apply()`) is sugar over the same `Stmt` slices. Allocation model: `Ruleset`
owns an arena; borrowed strings and expression slices must outlive it, but statement arrays passed
to `addRule`/accumulated by `RuleBuilder` are copied into the arena, so rules may be built in
temporary storage. `RuleBuilder` latches OOM and reports it from `apply()`. Reentrant; no globals.
Clean-room from the documented libnftables JSON schema (libnftables-json(5) + the nftables wiki
"JSON representation"); libnftables itself is GPL and referenced solely as the specification of its
JSON interchange format (an interface, not code) — see NOTICE.

## Threat model / out of scope
This module only emits JSON; it never touches netlink and never applies anything — applying
requires the Linux `nft` binary (needs CAP_NET_ADMIN), and the module itself is `platform: any`.
It is a builder, not a validator: it does not verify that a referenced chain/set exists, that a
payload field name is real, or that a ruleset is semantically sound — that is `nft`'s job (`nft -c`
catches it). String fields are properly JSON-escaped (including `@set` references), so a hostile
name cannot break out of the JSON, but the module makes no claim about what a caller-supplied name
*means* to `nft`. Coverage is the ruleset-building subset of the schema; stateful/introspection
commands (`list`, `reset`, `monitor`), maps, flowtables and the full expression zoo are out of
scope.

## Verification
Offline golden-JSON known-answer tests: byte-exact serialization of full rulesets (inet filter with
default-drop input chain; ip nat masquerade postrouting; named port set used in a rule), every
non-identifier enum token, expression/statement shapes, delete+flush command shapes, JSON-escaping
of set-ref names, and equivalence of the fluent builder vs a hand-written `Stmt` slice — each also
parsed back with `std.json` to prove well-formedness. When an `nft` binary is present, the suite
additionally pipes a generated ruleset through `nft -c -j -f -` (check mode, never applied;
tolerates the unprivileged netlink-cache EPERM as long as the parser accepted the JSON) and
confirms `nft -c` rejects a deliberately schema-invalid ruleset. Run: `zig build test-nftables`.

## Backlog / deferred
Maps, flowtables, and the introspection commands (`list`/`reset`/`monitor`) are explicitly out of
scope for this builder (the schema's stateful/read-back half, not a ruleset-construction concern).
No open PLAN.md backlog item beyond this documented coverage boundary.

## Status
`gap · any · codec · reentrant` + deps: none (std only) — canonical source is `pub const meta` in
src/root.zig.
