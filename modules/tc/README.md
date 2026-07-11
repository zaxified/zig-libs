# tc

Linux traffic control (`RTM_NEWQDISC`/`RTM_DELQDISC`/`RTM_GETQDISC` over rtnetlink) — v1
scoped to the **netem** qdisc: delay/jitter, loss, duplication, reordering, corruption and
rate limiting, attached as an interface's root qdisc. This is the write side the sibling
`netlink` module deliberately omits ("read/dump only") — `tc` builds its own
`NETLINK_ROUTE` socket and adds the `NLM_F_CREATE`/`NLM_F_EXCL`/`NLM_F_REPLACE` request
construction plus `NLMSG_ERROR` ACK parsing on top of `netlink`'s wire codec. No `tc`
binary shell-out, no libc — pure Zig raw syscalls.

The primary consumer is fleet-simulation network impairment (inject realistic
delay/loss/reorder per simulated link) and general-purpose traffic shaping for testing;
anywhere you'd otherwise reach for `tc qdisc add dev eth0 root netem …`.

## Import

```zig
const tc = @import("tc");
```

## Usage

```zig
var sock = try tc.Socket.open(gpa);
defer sock.close();

// Attach netem as the root qdisc (fails error.Exists if one is already there).
try sock.add(ifindex, .{
    .delay_ns = 100 * std.time.ns_per_ms,
    .jitter_ns = 10 * std.time.ns_per_ms,
    .loss_pct = 1.0,
});

// Read it back (works for any qdisc kind, not just netem; no privilege needed).
const q = (try sock.show(ifindex)).?;
std.debug.print("{s}\n", .{q.kind()}); // "netem"
if (q.netem) |nw| std.debug.print("delay_ns={d} loss={d}\n", .{ nw.delay_ns, nw.loss });

// Create-or-replace with a different config (idempotent, unlike add).
try sock.change(ifindex, .{ .delay_ns = 20 * std.time.ns_per_ms, .duplicate_pct = 5.0 });

// Remove — the interface reverts to its default qdisc.
try sock.del(ifindex);
```

`ifindex` is a kernel interface index (`netlink.Socket.links()` resolves a name to one).

## API

- `Socket.open(gpa)` / `.close()` — one `NETLINK_ROUTE` socket per thread/loop.
- `Socket.add(ifindex, Netem) SetError!void` — `NLM_F_CREATE|NLM_F_EXCL`; `error.Exists`
  if a root qdisc is already attached.
- `Socket.change(ifindex, Netem) SetError!void` — `NLM_F_CREATE|NLM_F_REPLACE`;
  create-or-replace, idempotent.
- `Socket.del(ifindex) DelError!void` — remove the root qdisc.
- `Socket.show(ifindex) GetError!?Qdisc` — `RTM_GETQDISC` dump, filtered to `ifindex`;
  needs no privilege. Returns the qdisc regardless of kind (`"noqueue"`, `"netem"`, …);
  `Qdisc.netem` is populated only when `Qdisc.kind()` is `"netem"`.
- `Netem` — the typed input options struct (nanoseconds + percent-based fields; see
  doc-comments in `src/root.zig` for every field). `add`/`change` return
  `error.InvalidPercent` for any `*_pct` field outside `[0, 100]`.
- `NetemWire` (inside `Qdisc.netem`) — the raw wire-scaled read-back (kernel `u32`
  probabilities, not reconstructed percentages — see SPEC.md for why).

## Verify

```sh
zig build test-tc                              # unit/golden/fuzz tests; live tests skip
unshare -rn zig build test-tc                  # + live netns round-trip (add/change/del)
```

Both write ops need `CAP_NET_ADMIN`; `show` does not. See SPEC.md for the full
verification story (golden bytes, encode/decode round-trip, live-netns proof).

Provenance: clean-room from the kernel UAPI headers (`linux/rtnetlink.h`,
`linux/pkt_sched.h`) — see `/NOTICE`.
