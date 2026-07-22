# nftables — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

The module has two backends over one shared vocabulary: the portable **JSON builder** and the
**native nfnetlink** path. `src/types.zig` holds the enums both speak (`Family`, `ChainType`,
`Hook`, `Policy`, `Op`, `MetaKey`, `PayloadBase`, `LimitPer`/`LimitUnit`, `SetFlag`,
`SetDataType`, …); `src/root.zig` re-exports them unchanged, so the JSON builder's public surface
is exactly what it always was. Files: `types.zig` (vocabulary + kernel mappings), `nl.zig`
(thin alias layer over `netlink.codec`), `wire.zig` (nfnetlink framing/objects/batch/decoders), `expr.zig` (rule
expressions + register model), `socket.zig` (transport, Linux-only), `goldens.zig` (captured
`nft` traffic), `consistency.zig` (JSON↔native proof), `root.zig` (JSON builder + facade).

## Design & invariants — JSON builder
`std.json` is the whole serializer. Every vocabulary enum whose tag names equal the schema tokens
verbatim relies on default `@tagName` serialization; the handful whose tokens are not Zig
identifiers (`==`, `fully-random`, `tcp reset`, `queue-threshold`, `auto-merge`, ...) carry a
custom `jsonStringify`. Output is minified and, by construction, byte-stable. Typed model mirrors
the schema tree: `Expr` (match RHS / set elements / NAT args), `Stmt` (verdicts, counter, log,
limit, reject, masquerade/redirect/snat/dnat), `Object`/`Cmd` (`add`/`create`/`delete`/`flush`
over table/chain/rule/set + `flush ruleset`). A fluent `RuleBuilder`
(`.tcpDport().accept().apply()`) is sugar over the same `Stmt` slices. Allocation model: `Ruleset`
owns an arena; borrowed strings and expression slices must outlive it, but statement arrays passed
to `addRule`/accumulated by `RuleBuilder` are copied into the arena. `RuleBuilder` latches OOM and
reports it from `apply()`. Reentrant; no globals.

## Design & invariants — native nfnetlink backend
**Framing.** `nlmsg_type = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_*`, then a 4-byte `nfgenmsg`
(`nfgen_family` = the table's `NFPROTO_*`, `version` = 0, `res_id` = 0 for commands and
`NFNL_SUBSYS_NFTABLES` for the batch control messages), then `NFTA_*` TLVs.

**Byte order.** netlink itself is host-endian, but every nftables *integer* attribute — and
`nfgenmsg.res_id` — is big-endian on the wire and the kernel does **not** set
`NLA_F_NET_BYTEORDER`. The backend therefore uses `netlink.codec`'s big-endian accessors
(`Attr.asBe16/32/64`, `appendAttrBe16/32/64`) and the host-endian twins are deliberately unused
for payload values. The exception is
the contents of a **register**: `NFTA_DATA_VALUE` is raw bytes, so a port is network order because
that is how it sits in the packet, while `ct state`/`meta mark` are host order because that is how
the kernel put them in the register (`expr.regU32` vs `expr.portBytes`).

**Batch = transaction.** `Batch.init` writes `NFNL_MSG_BATCH_BEGIN` (seq `S`), each command gets
`S+1, S+2, …`, `finish()` appends `NFNL_MSG_BATCH_END`; the whole buffer goes out in one
`sendmsg`. The kernel stages every command and commits only when `BATCH_END` arrives with no
failure — one bad command aborts the transaction and *nothing* is applied. `finish()` is
idempotent. `bytes()` before `finish()` is deliberately not a valid batch.

**Error attribution.** Per-command failures come back as `NLMSG_ERROR` carrying that command's
sequence number; a failure of the commit stage is reported against the `BATCH_BEGIN` sequence.
`Batch.entryForSeq`/`stageForSeq` map a sequence number back to `{index, NFT_MSG_* name}` or to
`.commit`, and `Socket.lastFailure()` returns `{stage, seq, index, command, code, message}` with
the kernel's `NLMSGERR_ATTR_MSG` string when extended ACKs are available. `BatchOptions.ack`
defaults to **on** (`NLM_F_ACK` per command) so success is positive rather than inferred from
silence; `nft` itself leaves it off, so the goldens do too.

**Register model.** Loads (`payload`, `meta`, `ct`) write a destination register; consumers
(`cmp`, `lookup`, `bitwise`, `nat`) read a source register. A `cmp` on a register nothing wrote is
accepted by the kernel and then never matches — the failure mode this model exists to prevent.
`Program` allocates only the four 16-byte registers `NFT_REG_1`…`NFT_REG_4`, **resets to
`NFT_REG_1` at the start of every match sequence** (load → optional bitwise → cmp/lookup, after
which the value is dead), and allocates sequentially without a reset only in `nat()`, where the
address and the port must be live at once. That is byte-for-byte what `nft` does. `Program.push`
is the raw escape hatch and does not touch the allocator; `Program.regs.reset()` is public so a
caller mixing the two can re-establish the invariant. `Program` also carries the *table's* family
so that a layer-3 match emits the `meta nfproto` dependency in an `inet` table and omits it in
`ip`/`ip6` — again matching `nft`.

**Widths.** `Program.metaCmp`/`payloadCmp` reject a comparison value whose width does not match
the load (`error.ValueWidthMismatch`) — e.g. a 2-byte value against a 4-byte payload load, or a
bare `"lo"` against the `IFNAMSIZ`-padded `meta iifname` (use `ifnameCmp`). `bitwise` rejects a
mask/xor that disagrees with its `len`. `Op.in` is rejected by `cmp` builders
(`error.UnsupportedOperator`) — set membership is a `lookup`, not a comparison.

**Prefix matching.** A byte-aligned CIDR prefix shortens the payload load to the covered bytes and
needs no `bitwise`; a non-aligned prefix loads the whole field and emits `bitwise` mask/xor. Both
shapes are byte-exact against captured `nft` traffic (`/8` and `/12`).

**Allocation.** `Batch` owns one growable buffer plus the entry table; `Program` owns an arena and
copies every byte slice handed to a high-level helper, so temporaries are safe (`push` borrows).
`Socket.list*` return an owned arena plus decoded items, so nothing borrows the receive buffer.
Errors in `Program` are latched and surface from `finish()`.

**Socket.** Blocking `NETLINK_NETFILTER`, one instance per thread, `SOCK_CLOEXEC`, kernel-assigned
port id matched on every reply, `NETLINK_EXT_ACK` requested best-effort, `MSG_PEEK|MSG_TRUNC`
buffer-growth probe so no datagram is ever truncated, datagrams from a non-kernel sender dropped,
`NLM_F_DUMP_INTR` restarts a dump up to 4 times before `error.InconsistentDump`.

## Threat model / out of scope
The JSON builder never touches netlink and never applies anything. The native backend does apply
things and needs `CAP_NET_ADMIN` in the network namespace; it is the caller's job to decide what
goes into a batch. Neither backend is a validator: they do not verify that a referenced chain/set
exists, that a payload field name is real, or that a ruleset is semantically sound — `nft -c`
does that for the JSON path, and the kernel rejects the batch for the native path (with
attribution). JSON string fields are properly escaped (including `@set` references); netlink
strings are length-prefixed TLVs, so a hostile name cannot break framing either — but neither
module makes a claim about what a caller-supplied name *means*.

Every decoder is bounds-checked before any slice is formed: a truncated, hostile or bit-flipped
reply yields `error.Truncated`/`error.BadLength`, never a panic or an out-of-bounds read, and
every walker advances by at least 4 bytes so no input can loop forever. Unknown attributes are
skipped rather than rejected — the kernel gains `NFTA_*` types over time and a dump must not break
on one — while malformed *lengths* are always rejected.

Out of scope: maps, flowtables, named objects (`NFT_MSG_NEWOBJ`), `monitor`/event subscription,
and the introspection half of the JSON schema (`list`/`reset`).

## Verification
**JSON builder.** Offline golden-JSON known-answer tests: byte-exact serialization of full
rulesets (inet filter with default-drop input chain; ip nat masquerade postrouting; named port set
used in a rule), every non-identifier enum token, expression/statement shapes, delete+flush command
shapes, JSON-escaping of set-ref names, and equivalence of the fluent builder vs a hand-written
`Stmt` slice — each also parsed back with `std.json`. When an `nft` binary is present the suite
pipes a generated ruleset through `nft -c -j -f -` (check mode, never applied) and confirms `nft -c`
rejects a deliberately schema-invalid ruleset.

**Native backend — byte-exact goldens.** Every golden in `src/goldens.zig` is the complete
`sendmsg` payload a stock `nft` (v1.1.6, Linux 7.0, x86-64) put on the wire, captured with

```sh
unshare -rn strace -f -e trace=sendmsg -e write=all -xx -s 8192 -e abbrev=none nft <command…>
```

`-e write=all` prints the buffer verbatim, so there is no re-encoding step between the
kernel-bound bytes and the hex in the file. Each golden carries the exact command above it.
Captured commands: `add table inet filter` · `delete table inet filter` ·
`add chain inet filter input '{ type filter hook input priority 0; policy drop; }'` ·
`add chain ip nat post '{ type nat hook postrouting priority 100; }'` ·
`add rule inet filter input tcp dport 22 counter accept` ·
`add rule inet filter input ip saddr 10.0.0.0/8 drop` ·
`add rule inet filter input ip saddr 10.0.0.0/12 drop` (the bitwise case) ·
`add rule inet filter input ip saddr @blocked drop` ·
`add rule inet filter input ct state established,related accept` ·
`add rule inet filter input limit rate 10/second burst 5 packets accept` ·
`add rule inet filter input log prefix "ssh: " level info` ·
`add rule inet filter input iifname "lo" accept` ·
`add rule ip nat post oifname "eth0" masquerade` ·
`add rule ip nat post ip saddr 10.0.0.0/8 snat to 192.0.2.1` ·
`add rule ip nat post tcp dport 80 dnat to 10.0.0.5:8080` ·
`add set inet filter blocked '{ type ipv4_addr; flags interval; }'` ·
`add element inet filter blocked '{ 10.0.0.1 }'` ·
`delete rule inet filter input handle 4` · and a three-command `nft -f` run
(`add table` + `add chain` + `add rule`) that is **one** batch — the framing proof.

Two things make byte-exactness possible. `nft` seeds its batch sequence at 0
(`BATCH_BEGIN` = 0, commands 1…n, `BATCH_END` = n+1), so the goldens build with `first_seq = 0`
and `.{ .ack = false }` (`nft` does not set `NLM_F_ACK`). And `nft` stamps a private versioned TLV
into `NFTA_TABLE_USERDATA`/`NFTA_SET_USERDATA`; that blob is opaque to the kernel, so
`TableSpec.userdata`/`SetSpec.userdata` pass bytes straight through and the goldens hand the module
the exact bytes `nft` sent. Nothing interprets them.

Two capture-derived facts are recorded as tests rather than byte goldens: the **set datatype ids**
(`NFTA_SET_KEY_TYPE` is a userspace number the kernel stores untouched — `ipv4_addr` = 7,
`ipv6_addr` = 8, `ether_addr` = 9, `inet_proto` = 12, `inet_service` = 13, `mark` = 19,
`ifname` = 41, one `nft add set` capture each), and the size/timeout set shape
(`NFTA_SET_DESC{SIZE}` + `NFTA_SET_TIMEOUT` in **milliseconds**, asserted by value and by attribute
order because the captured message also carried the userdata stamp).

**Live tests** (`unshare -rn zig build test-nftables`; they print `SKIPPED:` and pass otherwise):

- *Round-trip.* One batch creates a table, a base chain, a set with two elements and two rules;
  `listTables`/`listChains`/`listSets`/`listSetElems`/`listRules` read every one of them back and
  check the decoded fields (hook number, priority, policy, key length, expression names, the
  `bitwise` the `/12` prefix forces); one rule is deleted by the handle the kernel reported, the
  other survives; the table is dropped and confirmed gone.
- *Atomic rollback.* A two-command batch whose second command references a non-existent chain.
  `commit` returns `error.NotFound`, `lastFailure()` reports `stage = .message`, `index = 1`,
  `command = "NEWRULE"`, `code = -2`, and the table created by command #0 is **not** in the
  ruleset — the transaction was rolled back whole.
- *JSON ↔ native consistency.* One ruleset (a `/12` prefix + counter + drop, a `tcp dport 22`
  accept, an `iifname "lo"` accept, under a default-drop base chain) is described twice: once
  through the JSON builder, once through `Batch`/`Program`. The **native** batch is applied over
  netlink, then `nft -j list ruleset` decompiles the kernel's own view and it is compared against
  the JSON builder's output: table and chain fields (`family`/`table`/`name`/`type`/`hook`/
  `prio`/`policy`) exactly, and each rule's statement array position by position — `match`
  statements deeply (operator, left, right must be JSON-identical), other statements by name
  (`nft` renders a fresh counter as `{"counter":{"packets":0,"bytes":0}}` where the builder emits
  `{"counter":null}`). Statement *counts* must agree too, which additionally checks that the
  protocol dependencies the native path emits explicitly (`meta l4proto tcp`, `meta nfproto ipv4`)
  land exactly where `nft` folds them back. The check was negative-controlled: changing the native
  prefix to `/13` while leaving the JSON at `/12` fails the test with `match statement differs`.

**Hostile input.** Truncated/over-long/zero-length TLVs, an `NFTA_TABLE_FLAGS` of the wrong width,
a payload shorter than `nfgenmsg`, and expression nests whose declared length runs past the buffer
are all rejected with `Truncated`/`BadLength`. Three fuzz targets (`std.testing.fuzz`) drive the
expression walker, the object decoders and the netlink walkers with arbitrary bytes and assert a
step bound so no input can loop.

Run: `zig build test-nftables` (and `--release=fast`), `unshare -rn zig build test-nftables`.

## Backlog / deferred
- ~~**Dependency inversion (one line in the root `build.zig`).**~~ **Done.** The `nftables` entry
  declares `.deps = &.{"netlink"}`, and `nl.zig` is now a thin alias layer over `netlink.codec`
  with no codec code of its own — including the eight big-endian accessors, which moved into
  `netlink.codec` (`conntrack` had written them independently too). `socket.zig`'s dump loop is
  `netlink.classifyDumpMessage`. What is still a fourth copy is `socket.zig`'s **transport**
  (`open`/`close`/`send`/`recvDatagram`/`setRecvTimeout` + the `MSG_PEEK|MSG_TRUNC` growth
  loop): `netlink.Socket.open` hardcodes `linux.NETLINK.ROUTE`, so lifting that needs a
  protocol-parameterised `netlink.Transport`, which is the remaining item.
- **Objects, maps, flowtables.** `NFT_MSG_NEWOBJ`/`GETOBJ`/`DELOBJ` (named counters, quotas,
  ct helpers/timeouts), verdict/data maps (`NFT_SET_MAP` + `NFTA_SET_ELEM_DATA` semantics beyond
  the raw byte pass-through that already exists), and flowtables are not modelled.
- **Expressions not modelled.** `reject`, `queue`, `redir`, `dup`, `fwd`, `quota`, `numgen`,
  `hash`, `xfrm`, `synproxy`, `tproxy`, `objref`, `flow_offload`, `range`, `dynset`, the
  `NFT_BITWISE_*` shift ops, and the inner/tunnel payload bases. `Expr.raw` is the escape hatch:
  a caller can hand a pre-encoded `NFTA_EXPR_DATA` payload under any name without forking the
  module. The JSON builder still covers `reject`/`redirect` on its side.
- **Interval sets.** Elements are modelled at the wire level (`flags`, `KEY_END`), and the
  captured three-element encoding of `{ 10.0.0.1 }` in an interval set is a golden, but there is no
  helper that turns a range into the start/end element pair. Callers of interval sets must emit the
  markers themselves.
- **`meta ibridgename`/`obridgename`.** `MetaKey.key()` returns null for these two; neither the
  UAPI header nor a capture grounded their `enum nft_meta_keys` value, and guessing would silently
  produce a rule matching on the wrong key. The encoder rejects them with
  `error.UnsupportedMetaKey`.
- **`NF_INET_INGRESS`.** `Hook.ingress` is only mapped for the netdev family. The inet/ip/ip6
  ingress hook (=5 on modern kernels) is rejected with `error.UnsupportedHook` rather than guessed.
- **IPv6 prefix helpers.** `ipv4MaskBytes`/`ipSaddrPrefix` cover IPv4; an IPv6 `/n` must be built
  through `payloadMaskedCmp` with a caller-supplied 16-byte mask.
- **Event monitoring.** `NFNLGRP_NFTABLES` multicast (`nft monitor`) is not wired up; the socket
  binds no groups. `conntrack`'s event seam is the shape to copy.
- **Non-x86 goldens.** The captures are little-endian; every golden test skips on a big-endian
  host (netlink's host-endian header fields would differ). The wire layer itself is
  endian-explicit and would need a big-endian capture to be pinned.

## Status
`gap · any · codec · reentrant` + deps: none (std only) — canonical source is `pub const meta` in
src/root.zig. `Socket` is Linux-only and `single_owner`.
