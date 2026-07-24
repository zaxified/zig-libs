# tc

Linux traffic control over rtnetlink — **qdiscs, classes, filters and actions**, in pure
Zig with no `tc` binary shell-out and no libc.

- **qdiscs** (`RTM_NEWQDISC`/`DELQDISC`/`GETQDISC`) — `netem` (delay/jitter, loss,
  duplication, reordering, corruption, rate), `htb`, `tbf`, `fq_codel`, `mq` (the
  option-less multiqueue root whose per-queue child classes the kernel auto-creates), and
  `cake` (the CAKE AQM/shaper: bandwidth, RTT/target, DiffServ/flow modes, NAT, wash,
  ACK-filter, overhead/MPU/ATM, memory, split-GSO, fwmark, ingress), plus a `raw`
  escape hatch that takes a kind string and a pre-encoded `TCA_OPTIONS` payload.
- **classes** (`RTM_NEWTCLASS`/`DELTCLASS`/`GETTCLASS`) — htb rate/ceil token buckets
  including the psched **rate tables** and the 64-bit `TCA_HTB_RATE64`/`CEIL64`
  attributes for rates above 4.29 GB/s.
- **filters** (`RTM_NEWTFILTER`/`DELTFILTER`/`GETTFILTER`) — `u32` (masked 32-bit matches
  at fixed offsets) and `flower` (structured L2–L4 keys: ethertype, ip_proto, IPv4/IPv6
  prefixes, TCP/UDP/SCTP ports, classid).
- **actions** (`TCA_U32_ACT`/`TCA_FLOWER_ACT`, and the standalone
  `RTM_NEWACTION`/`DELACTION`/`GETACTION` table) — `gact` (pass/drop/continue/reclassify/
  trap, incl. the probabilistic `tc_gact_p`), `mirred` (egress/ingress × redirect/mirror),
  `police` (rate/burst/mtu/peakrate on the same psched rate tables, incl. `RATE64`),
  `skbedit` (priority/mark/queue_mapping/ptype), `vlan` (push/pop/modify), plus a `raw`
  escape hatch. Multi-action lists chain through the `TC_ACT_PIPE` verdict.
- **handles** — a typed `Handle` for `major:minor` with `TC_H_ROOT`/`TC_H_INGRESS`/
  `TC_H_UNSPEC`, hexadecimal `parse`/`format` (`"1:10"` is minor **16**, exactly as `tc`
  reads and prints it).

Transport is shared with the sibling `netlink` module: `tc` runs no socket, receive
buffer, sequence counter, errno table or extended-ACK handling of its own — it drives
`netlink.Socket` through the public
`nextSeq`/`send`/`recvDatagram`/`requestAck`/`lastErrorMessage` seam and builds its own
tc messages on `netlink.codec`. The multi-part **dump** loops triage their replies with
the shared `netlink.classifyDumpMessage` too; what is local is only tc policy — which
request, which reply type, which parser, and the client-side `ifindex`/`parent` filter.

Consumers: fleet-simulation network impairment (per-link delay/loss/reorder), bandwidth
partitioning for test rigs and multi-tenant hosts, and anywhere you would otherwise shell
out to `tc qdisc|class|filter|actions …`.

## Import

```zig
const tc = @import("tc");
```

## Usage

```zig
var sock = try tc.Socket.open(gpa);
defer sock.close();

const one: tc.Handle = .init(1, 0);        // "1:"
const leaf: tc.Handle = .init(1, 0x10);    // "1:10"

// An htb root qdisc, one shaped class under it, one filter steering into it.
try sock.qdiscAdd(.{ .ifindex = ifi, .handle = one, .parent = .root },
                  .{ .htb = .{ .defcls = 0x10 } });
try sock.classAdd(.{ .ifindex = ifi, .handle = leaf, .parent = one },
                  .{ .htb = .{ .rate = 125_000, .ceil = 250_000 } }); // bytes/s
try sock.filterAdd(.{ .ifindex = ifi, .parent = one, .prio = 1, .eth_type = tc.ETH_P.IP },
                   .{ .u32 = .{ .classid = leaf,
                                .keys = &.{ .ipv4Dst(.{ 10, 0, 0, 1 }, 32) } } });

// Or run an action list on a match: mark the packet, then police it. The list is
// walked in order for as long as each action returns TC_ACT_PIPE.
try sock.filterAdd(.{ .ifindex = ifi, .parent = one, .prio = 2, .eth_type = tc.ETH_P.IP },
                   .{ .u32 = .{ .keys = &.{ .ipv4Src(.{ 10, 0, 0, 2 }, 32) },
                                .actions = &.{
                                    .{ .skbedit = .{ .mark = 7 } },      // verdict: pipe
                                    .{ .police = .{ .rate = 125_000,     // bytes/s
                                                    .burst = 10 * 1024,  // bytes
                                                    .exceed = .shot } },
                                } } });

// Read the actions back off a dumped filter.
const fs = try sock.filters(ifi, one);
defer gpa.free(fs);
for (fs) |f| for (f.actions()) |a|
    std.debug.print("{d}: {s} verdict={d}\n", .{ a.order, a.kind(), a.gen.action.raw() });

// Read back (no privilege needed).
const cs = try sock.classes(ifi, one);
defer gpa.free(cs);
for (cs) |c| std.debug.print("{f} rate={d}\n", .{ c.handle, c.htb.?.rate64 });

try sock.qdiscDel(.{ .ifindex = ifi, .parent = .root });
```

The v1 netem shortcuts are unchanged:

```zig
try sock.add(ifi, .{ .delay_ns = 100 * std.time.ns_per_ms, .loss_pct = 1.0 });
const q = (try sock.show(ifi)).?;
if (q.netem) |nw| std.debug.print("delay_ns={d} loss={d}\n", .{ nw.delay_ns, nw.loss });
try sock.change(ifi, .{ .delay_ns = 20 * std.time.ns_per_ms, .duplicate_pct = 5.0 });
try sock.del(ifi);
```

`ifi` is a kernel interface index (`netlink.Socket.links()` resolves a name to one).

## API

### Socket

| Call | Meaning |
|---|---|
| `Socket.open(gpa)` / `.close()` | one `NETLINK_ROUTE` socket per thread/loop; reads `/proc/net/psched` for the rate arithmetic |
| `Socket.openWithPsched(gpa, ps)` | same, with an explicit `Psched` calibration |
| `.qdiscAdd/.qdiscReplace/.qdiscChange(QdiscTarget, QdiscSpec)` | `tc qdisc add` / `replace` / `change` |
| `.qdiscDel(QdiscTarget)` | `tc qdisc del` |
| `.qdiscs(ifindex) ![]Qdisc` | `RTM_GETQDISC` dump, scoped to the interface |
| `.classAdd/.classReplace/.classChange(ClassTarget, ClassSpec)` | `tc class add` / `replace` / `change` |
| `.classDel(ClassTarget)` | `tc class del` (`parent` may stay `.unspec`) |
| `.classes(ifindex, ?Handle) ![]Class` | `RTM_GETTCLASS` dump, optionally scoped (see below) |
| `.filterAdd/.filterReplace/.filterChange(FilterTarget, FilterSpec)` | `tc filter add` / `replace` / `change` |
| `.filterDel(FilterTarget, ?kind)` | `tc filter del`; `kind` is normally `null` |
| `.filters(ifindex, ?Handle) ![]Filter` | `RTM_GETTFILTER` dump, optionally scoped |
| `.actionAdd/.actionReplace/.actionChange([]const ActionSpec)` | `tc actions add` / `replace` / `change` — the shared action table |
| `.actionDel([]const ActionRef)` | `tc actions del action KIND index N` |
| `.actions(kind) ![]Action` | `tc actions ls action KIND` — an `RTM_GETACTION` dump |
| `.actionGet(ActionRef) !?Action` | `tc actions get action KIND index N` (single reply, not a dump) |
| `.lastErrorMessage()` | the kernel's extended-ACK reason for the last failed write |
| `.add/.change/.del/.show(ifindex, …)` | the v1 netem shortcuts (root qdisc, handle `1:0`) |

Dump scoping is client-side, because the kernel dumps everything for an ifindex:
`classes(ifi, qdisc_handle)` keeps classes whose **class id major** matches (the rule
`tc class show … parent 1:` uses — a classful qdisc reports `TC_H_ROOT` as the parent of
its top-level classes, not the qdisc handle), `classes(ifi, class_handle)` keeps that
class's direct children, and `filters(ifi, parent)` matches the attach point exactly.

### Types

- `Handle` — `init(major, minor)`, `.root`/`.ingress`/`.clsact`/`.unspec`, `major()`,
  `minor()`, `qdisc()`, `isClass()`, `parse("1:10")`, `{f}` formatting. **Hexadecimal**,
  like `tc`.
- `QdiscSpec` = `.netem` | `.htb` | `.tbf` | `.fq_codel` | `.mq` | `.cake` | `.raw`;
  `ClassSpec` = `.htb` | `.raw`; `FilterSpec` = `.u32` | `.flower` | `.raw`;
  `ActionSpec` = `.gact` | `.mirred` | `.police` | `.skbedit` | `.vlan` | `.raw`.
- `Verdict` — the `TC_ACT_*` return codes (`.ok`, `.shot`, `.pipe`, `.stolen`,
  `.reclassify`, `.trap`, `.unspec` = `tc`'s `continue`). `.pipe` is the one that
  **chains** into the next action of the list; everything else ends it. Non-exhaustive,
  so a verdict this module predates (or a `TC_ACT_GOTO_CHAIN` composite) still decodes —
  use `.raw()` rather than `@tagName` on a decoded one.
- `Gen` — the shared `tc_gen` prologue (`index`, `capab`, `action`, `refcnt`, `bindcnt`)
  every action kind's options struct starts with, and which `Action.gen` always exposes
  (police's differently-shaped `tc_police` is reassembled into it).
- `Action` — one decoded action: `order` (its 1-based place in the list), `kind()`,
  `gen`, `cookie()`, an optional per-kind wire struct (`a.gact`/`a.mirred`/`a.police`/
  `a.skbedit`/`a.vlan`), plus `stats` and `tm` when the kernel sent them.
  `Filter.actions()` returns the list attached to a dumped filter.
- `Netem`, `Htb`, `HtbClass`, `Tbf`, `FqCodel`, `Mq`, `Cake` (+ `CakeDiffservMode`/
  `CakeFlowMode`/`CakeAtmMode`/`CakeAckFilter`), `U32` + `U32Key`, `Flower` + `Prefix4`/
  `Prefix6` — the ergonomic input structs; every field is doc-commented in
  `src/qdisc.zig` / `src/filter.zig`. Rates are **bytes per second** (`1mbit` = 125000).
- `Qdisc`, `Class`, `Filter` — dump results, each with a `kind()` plus an optional
  decoded-options field per modelled kind (`q.netem`, `q.htb`, `q.tbf`, `q.fq_codel`,
  `q.cake`, `c.htb`, `f.u32_sel`, `f.flower`, `f.classid()`).
- `Psched`, `RateSpec`, `LinkLayer` and the rate-table helpers in `tc.ratespec`.
- `tc.message` — the pure request builders (`buildQdiscSet`, `buildClassSet`,
  `buildFilterSet`, `buildDump`, …) if you want the bytes without a socket.

Errors: `WriteError` (build + transport + mapped kernel errno, e.g. `error.Exists`,
`error.NotFound`, `error.AccessDenied`, `error.InvalidRequest`) and `DumpError`
(`WriteError`-style transport plus `error.InconsistentDump`). Both come from
`netlink.RequestError`, so a `tc` error and a `netlink` error are the same value.

## Verify

```sh
zig build test-tc                 # unit/golden/fuzz; the live tests print SKIPPED and pass
unshare -rn zig build test-tc     # + the live netns round-trip (qdisc→class→filter→dump→del)
```

Every write op needs `CAP_NET_ADMIN`; the `RTM_GET*` dumps do not. The encoders are
checked against **byte-exact requests captured from a real `iproute2` `tc`** under
`strace` (50 goldens, each with the exact command in a comment) — see SPEC.md for the
full verification story and the deferred list.

One asymmetry worth knowing: qdiscs, classes and filters are namespaced, so
`unshare -rn` is enough to exercise them; the **shared action table** is guarded by
`CAP_NET_ADMIN` in the *initial* user namespace (the kernel uses `netlink_capable`, not
`netlink_net_capable`, in `act_api.c`), so `tc actions add/del` needs real root. The
`RTM_GETACTION` dump needs no privilege at all, and the live test for the write half
prints `SKIPPED: …` and passes without it.

Provenance: kernel UAPI headers (`linux/rtnetlink.h`, `linux/pkt_sched.h`,
`linux/pkt_cls.h`) plus iproute2 consulted as a *behaviour* reference for the rate-table
arithmetic and attribute ordering — see `/NOTICE`.
