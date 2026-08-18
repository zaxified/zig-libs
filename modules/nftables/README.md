# nftables

Manage the Linux firewall from Zig, two ways:

1. **JSON builder — the portable path.** Construct tables/chains/rules/sets with
   a typed API, serialize to the documented libnftables JSON representation, and
   feed the bytes to `nft -j -f -` (or `nft -c -j -f -` to check without
   applying). Portable data: no privileges, no Linux, no kernel needed to *build*
   it.
2. **Native nfnetlink backend — the privileged path.** Talk `NETLINK_NETFILTER` /
   `NFNL_SUBSYS_NFTABLES` straight to the kernel: transactional batches,
   `NFT_MSG_*` object messages, the rule-expression vocabulary, and dumps decoded
   back into typed structs. No `nft` binary anywhere in the loop.

> An earlier version of this README said we deliberately do not reimplement
> netlink. That is no longer true for the *applying* path — the native backend
> below is exactly that reimplementation. It remains true that we do not
> reimplement libnftables' parser or its JSON layer: the JSON builder emits the
> documented interchange format, and the native backend speaks the kernel's UAPI.

## Which path to use

| | JSON builder | native backend |
|---|---|---|
| needs `nft` installed | yes, to apply | no |
| needs Linux + `CAP_NET_ADMIN` | only to apply | yes |
| testable unprivileged | fully | build + decode only |
| error reporting | `nft`'s stderr | per-command, with the kernel's extended ACK |
| atomicity | `nft -f` is one batch | one `sendmsg`, all-or-nothing |
| read the ruleset back | via `nft -j list` | native dumps, typed |

Use the **JSON builder** for config generation, tests, dry runs, cross-platform
tooling, or wherever shelling out to `nft` is acceptable. Use the **native
backend** in a daemon that owns the firewall: no external binary, no output
parsing, a real transaction, and a failure that names the exact command the
kernel refused.

Both speak the same vocabulary enums (`Family`, `ChainType`, `Hook`, `Policy`,
`SetDataType`, …), so a ruleset can be described once and emitted either way.

- **Platform:** `any` — the JSON builder and the whole wire layer are portable;
  only `Socket` is Linux-gated (behind `builtin.os.tag`, so the module still
  builds everywhere).
- **Model after:** libnftables JSON (`nft -j`) schema + kernel UAPI
  `linux/netfilter/nf_tables.h`.
- **Scope (JSON):** `add`/`create`/`delete`/`flush` over table/chain/rule/set
  plus `flush ruleset`; base and regular chains; match expressions (payload
  fields, raw payload, `meta`, `ct`, prefixes/CIDR, ranges, anonymous sets,
  `@set` references, concat); statements
  `accept`/`drop`/`reject`/`return`/`continue`/`jump`/`goto`/`counter`/`log`/
  `limit`/`masquerade`/`redirect`/`snat`/`dnat`; named sets with
  flags/elements/timeout/size/auto-merge.
- **Scope (native):** table/chain/rule/set/set-element objects
  (`NEW*`/`DEL*`/`GET*`), transactional batches with per-command error
  attribution, `NLM_F_ACK` + extended ACKs, dumps decoded into typed structs, and
  the `payload`/`cmp`/`meta`/`ct`/`bitwise`/`lookup`/`counter`/`immediate`/
  `limit`/`log`/`nat`/`masq` expressions with an explicit register model.

## JSON builder

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

## Native nfnetlink backend

```zig
const nft = @import("nftables");

var sock = try nft.Socket.open(gpa);
defer sock.close();

// One rule's expressions. The register discipline is applied for you.
var p = nft.Program.init(gpa, .inet);
defer p.deinit();
_ = p.tcpDport(22).counter().accept();

var batch = try sock.beginBatch(.{});
defer batch.deinit();
try batch.addTable(.{ .family = .inet, .name = "filter" });
try batch.addChain(.{ .family = .inet, .table = "filter", .name = "input",
                      .chain_type = .filter, .hook = .input, .prio = 0,
                      .policy = .drop });
try batch.addRule(.{ .family = .inet, .table = "filter", .chain = "input",
                     .exprs = try p.finish() });

// All of it, or none of it.
sock.commit(&batch) catch |err| {
    const f = sock.lastFailure().?;
    std.log.err("{s} (command #{?d}) failed: {s}", .{ f.command, f.index, f.message });
    return err;
};

// Read it back, typed.
var rules = try sock.listRules(.inet, "filter", "input");
defer rules.deinit();
for (rules.items) |rule| {
    var it = rule.exprIterator();
    while (try it.next()) |e| std.log.info("expr {s}", .{e.name});
}

// Or the whole ruleset in one round trip per object kind — pass `null`
// instead of a family to sweep every family at once, the same framing
// `nft list ruleset` uses.
var all_tables = try sock.listTables(null);
defer all_tables.deinit();
for (all_tables.items) |t| {
    // t.family is the raw NFPROTO_* byte; recover the typed enum:
    std.log.info("table {s} in {?s}", .{ t.name, if (nft.Family.fromNfproto(t.family)) |f| @tagName(f) else null });
}
```

The socket itself is the sibling `netlink` module's: `Socket` wraps a
`netlink.Socket` opened with `openProtocol(gpa, NETLINK.NETFILTER)`, so bind,
port-id capture, `NETLINK_EXT_ACK`, sequence allocation, the
`MSG_PEEK|MSG_TRUNC` receive-sizing loop and `SO_RCVTIMEO` are shared code, not
a private copy. What is nftables-specific and stays here: the batch framing, the
batch ACK/attribution engine and the decoders.

### Batching is the point

nftables commits are transactions. `Batch` frames
`NFNL_MSG_BATCH_BEGIN` … commands … `NFNL_MSG_BATCH_END` into one buffer sent
with a single `sendmsg`; the kernel stages every command and applies the lot only
if all of them are accepted. If one fails, nothing is applied — and because every
command carries its own sequence number, the returned `Failure` says *which*
command (index + `NFT_MSG_*` name), with the kernel's extended-ACK reason string
where the kernel provides one.

### Registers

A rule is a little machine over a register file: `payload`/`meta`/`ct` load into
a destination register, `cmp`/`lookup`/`bitwise`/`nat` read a source register. A
rule that compares a register nothing wrote is accepted by the kernel and then
never matches, silently. `Program` applies the same discipline a stock `nft`
does — reset to `NFT_REG_1` at the start of every match sequence, allocate
sequentially only where two values must be live at once (NAT address + port) —
and `expr.zig`'s header documents the model in full. `Program.push` is the escape
hatch for hand-built expressions and deliberately does not touch the allocator.

## Tests

- **Offline golden-JSON** known-answer tests for the JSON builder (byte-exact,
  parsed back with `std.json`).
- **Byte-exact netlink goldens** for the native backend: the complete `sendmsg`
  payloads a stock `nft` put on the wire, captured with
  `unshare -rn strace -f -e trace=sendmsg -e write=all -xx -s 8192 -e abbrev=none nft …`.
  Each golden names the exact command it came from.
- **Live tests** under `unshare -rn`: a native create/list/delete round-trip, a
  deliberately bad batch proving the kernel rolled the whole transaction back,
  and an unspec-family dump (`listTables(null)`) proving a single request
  returns objects from more than one family.
- **JSON ↔ native consistency**: the native batch is applied in a netns, then
  `nft -j list ruleset` decompiles it and the result is compared against what the
  JSON builder emits for the same ruleset.
- Hostile/truncated decode tests and fuzzing of every walker.

```sh
zig build test-nftables              # offline; live parts SKIP and pass
unshare -rn zig build test-nftables  # everything, including the live parts
```

Provenance: the JSON path is clean-room from the documented libnftables JSON
schema (libnftables-json(5) man page / nftables wiki "JSON representation"). The
native path is clean-room from the kernel UAPI headers
(`linux/netfilter/nfnetlink.h`, `linux/netfilter/nf_tables.h`,
`linux/netfilter.h`) plus byte-exact captures of a stock `nft` binary's netlink
traffic. No libnftables, libnftnl, libmnl or nftables source was consulted or
copied; `nft` is used only as a capture subject and a test oracle. libnftables
itself is GPL-2.0: it is referenced solely as the specification of its JSON
input/output format (an interface, not code).