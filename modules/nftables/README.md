# nftables

Typed Zig builder for the **libnftables JSON ruleset format** — construct
tables/chains/rules/sets with a typed API, serialize to the documented JSON
representation, and feed the bytes to `nft -j -f -` (or `nft -c -j -f -` to
check without applying). Lets a program manage the Linux firewall natively
instead of assembling `nft` command strings by hand.

- No pure-Zig nftables library exists.
- **Platform:** any (the JSON is portable data; *applying* it needs the Linux
  `nft` binary). We deliberately do not reimplement netlink or libnftables —
  the documented `nft -j` JSON schema is the stable interface.
- **Model after:** libnftables JSON (`nft -j`) schema.
- **Scope:** `add`/`create`/`delete`/`flush` over table/chain/rule/set plus
  `flush ruleset`; base and regular chains (type/hook/prio/policy); match
  expressions (payload fields, raw payload, `meta`, `ct`, prefixes/CIDR,
  ranges, anonymous sets, `@set` references, concat); statements
  `accept`/`drop`/`reject`/`return`/`continue`/`jump`/`goto`/`counter`/
  `log`/`limit`/`masquerade`/`redirect`/`snat`/`dnat`; named sets with
  flags/elements/timeout/size/auto-merge.

```zig
const nft = @import("nftables");

var rs = nft.Ruleset.init(gpa);
defer rs.deinit();
try rs.flushRuleset();
try rs.addTable(.inet, "filter");
try rs.addChain(nft.Chain.base(.inet, "filter", "input", .filter, .input, 0, .drop));
var r = rs.rule(.inet, "filter", "input");
try r.ctState(&.{ "established", "related" }).accept().apply();
var r2 = rs.rule(.inet, "filter", "input");
try r2.tcpDport(nft.num(22)).accept().apply();
const json = try rs.toJson(gpa); // pipe to: nft -c -j -f -   (check)
defer gpa.free(json);            //          nft -j -f -      (apply)
```

Tests are offline golden-JSON known-answer tests (byte-exact against the
documented schema, parsed back with `std.json`); when an `nft` binary is
present, the suite additionally pipes generated rulesets through
`nft -c -j -f -` (check mode only — nothing is ever applied).

Provenance: clean-room from the documented libnftables JSON schema
(libnftables-json(5) man page / nftables wiki "JSON representation"); no
libnftables source consulted or copied — we emit the documented `nft -j`
interchange format only. libnftables itself is GPL: it is referenced here
solely as the specification of its JSON input/output format (an interface,
not code).
