# tc

Linux traffic control over rtnetlink — **qdiscs, classes and filters**, in pure Zig with
no `tc` binary shell-out and no libc.

- **qdiscs** (`RTM_NEWQDISC`/`DELQDISC`/`GETQDISC`) — `netem` (delay/jitter, loss,
  duplication, reordering, corruption, rate), `htb`, `tbf`, `fq_codel`, plus a `raw`
  escape hatch that takes a kind string and a pre-encoded `TCA_OPTIONS` payload.
- **classes** (`RTM_NEWTCLASS`/`DELTCLASS`/`GETTCLASS`) — htb rate/ceil token buckets
  including the psched **rate tables** and the 64-bit `TCA_HTB_RATE64`/`CEIL64`
  attributes for rates above 4.29 GB/s.
- **filters** (`RTM_NEWTFILTER`/`DELTFILTER`/`GETTFILTER`) — `u32` (masked 32-bit matches
  at fixed offsets) and `flower` (structured L2–L4 keys: ethertype, ip_proto, IPv4/IPv6
  prefixes, TCP/UDP/SCTP ports, classid).
- **handles** — a typed `Handle` for `major:minor` with `TC_H_ROOT`/`TC_H_INGRESS`/
  `TC_H_UNSPEC`, hexadecimal `parse`/`format` (`"1:10"` is minor **16**, exactly as `tc`
  reads and prints it).

Transport is shared with the sibling `netlink` module: `tc` no longer runs its own
`NETLINK_ROUTE` socket, sequence counter, errno table or extended-ACK handling — it
drives `netlink.Socket` through the public `nextSeq`/`requestAck`/`lastErrorMessage`
seam and builds its own tc messages on `netlink.codec`. Only the multi-part **dump**
receive loop is still local, because `netlink`'s dump engine is private and generic over
its own parsers (a `DRY candidate:` note marks the spot).

Consumers: fleet-simulation network impairment (per-link delay/loss/reorder), bandwidth
partitioning for test rigs and multi-tenant hosts, and anywhere you would otherwise shell
out to `tc qdisc|class|filter …`.

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
- `QdiscSpec` = `.netem` | `.htb` | `.tbf` | `.fq_codel` | `.raw`;
  `ClassSpec` = `.htb` | `.raw`; `FilterSpec` = `.u32` | `.flower` | `.raw`.
- `Netem`, `Htb`, `HtbClass`, `Tbf`, `FqCodel`, `U32` + `U32Key`, `Flower` + `Prefix4`/
  `Prefix6` — the ergonomic input structs; every field is doc-commented in
  `src/qdisc.zig` / `src/filter.zig`. Rates are **bytes per second** (`1mbit` = 125000).
- `Qdisc`, `Class`, `Filter` — dump results, each with a `kind()` plus an optional
  decoded-options field per modelled kind (`q.netem`, `q.htb`, `q.tbf`, `q.fq_codel`,
  `c.htb`, `f.u32_sel`, `f.flower`, `f.classid()`).
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
`strace` (19 goldens, each with the exact command in a comment) — see SPEC.md for the
full verification story and the deferred list.

Provenance: kernel UAPI headers (`linux/rtnetlink.h`, `linux/pkt_sched.h`,
`linux/pkt_cls.h`) plus iproute2 consulted as a *behaviour* reference for the rate-table
arithmetic and attribute ordering — see `/NOTICE`.
