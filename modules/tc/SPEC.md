# tc — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see
/NOTICE.

## Design & invariants

`tc` adds the write half of rtnetlink's traffic-control API on top of the sibling
`netlink` module's wire codec (`codec.Message`/`Attr`/`AttrIterator`/`appendHeader`/
`appendAttr*`). `netlink` is scoped read/dump-only by design, so this module opens its
**own** `NETLINK_ROUTE` socket (same raw-syscall shape as `netlink.Socket.open`, kept
independent rather than reaching into `netlink`'s private fields) and adds the pieces a
write path needs that a pure dumper doesn't: `NLM_F_CREATE`/`NLM_F_EXCL`/`NLM_F_REPLACE`
flag constants (linux/netlink.h; not in `netlink.codec`, whose scope never needed them)
and an ACK-await loop (send, then block for the matching `NLMSG_ERROR`, errno 0 = success).

v1 is deliberately narrow: attach **netem** as an interface's **root** qdisc only
(`tcm_parent = TC_H_ROOT = 0xFFFFFFFF`, `tcm_handle = 0x00010000` i.e. `1:0`, fixed —
never caller-supplied). `Netem` is the ergonomic input (nanoseconds, `f64` percent
`[0, 100]`); the module encodes it into the kernel wire form. `Socket.show` (RTM_GETQDISC,
no privilege needed) reads back a `Qdisc{ifindex, handle, parent, kind, netem: ?NetemWire}`
— `netem` is populated only when the qdisc's `TCA_KIND` is `"netem"`, so `show` also works
(returning `netem: null`) on an untouched interface's default qdisc
(`noqueue`/`pfifo_fast`/…), which is how the offline/live tests establish a known "before"
state without assuming one.

`NetemWire` (the read-back type) deliberately stores raw kernel-scaled values (`u32`
probabilities, not reconstructed percentages) rather than mirroring `Netem`'s ergonomic
shape: `percent -> u32` is a lossy one-way scale (`round(percent/100 * UINT32_MAX)`), so
comparing reconstructed percentages after a round-trip would need an epsilon: comparing
raw scaled integers is instead exact and is what the tests do
(`nw.loss == try percentToU32(1.0)`).

### The tcmsg / tc_netem_qopt / attribute layout

All three of the following are transcribed directly from the kernel UAPI headers
(`/usr/include/linux/rtnetlink.h`, `/usr/include/linux/pkt_sched.h` — a recent kernel's
headers were read directly for this module; no third-party source was consulted for any
of it, see Provenance below).

```text
struct tcmsg (20 B, linux/rtnetlink.h):
  u8  tcm_family      (AF_UNSPEC = 0 — qdiscs aren't address-family-specific)
  u8  tcm__pad1
  u16 tcm__pad2
  i32 tcm_ifindex
  u32 tcm_handle      (this module always writes 0x00010000 = "1:0" on add/change/del)
  u32 tcm_parent      (this module always writes TC_H_ROOT = 0xFFFFFFFF)
  u32 tcm_info

Attributes on the tcmsg (TCA_*, linux/rtnetlink.h):
  TCA_KIND    = 1   -> NUL-terminated string, "netem\0"
  TCA_OPTIONS = 2   -> nested (NLA_F_NESTED); payload = qopt ++ extended attrs (below)

struct tc_netem_qopt (24 B, linux/pkt_sched.h) — the fixed prefix of TCA_OPTIONS:
  u32 latency     (this module always writes 0 — see "psched-tick decision" below)
  u32 limit       (packet FIFO limit; Netem.limit, default 1000)
  u32 loss        (percentToU32(Netem.loss_pct))
  u32 gap         (Netem.reorder_gap)
  u32 duplicate   (percentToU32(Netem.duplicate_pct))
  u32 jitter      (this module always writes 0 — ditto)

Extended TCA_NETEM_* attributes, siblings after the qopt bytes inside TCA_OPTIONS
(each only emitted when its Netem inputs are nonzero):
  TCA_NETEM_CORR (=1)      -> struct tc_netem_corr (12 B): u32 delay_corr, loss_corr, dup_corr
  TCA_NETEM_REORDER (=3)   -> struct tc_netem_reorder (8 B): u32 probability, correlation
  TCA_NETEM_CORRUPT (=4)   -> struct tc_netem_corrupt (8 B): u32 probability, correlation
  TCA_NETEM_RATE (=6)      -> struct tc_netem_rate (16 B): u32 rate, i32 packet_overhead,
                              u32 cell_size, i32 cell_overhead (this module only ever
                              sets `rate`; the overhead/cell-size knobs are out of scope)
  TCA_NETEM_LATENCY64 (=10) -> i64, nanoseconds (Netem.delay_ns)
  TCA_NETEM_JITTER64 (=11)  -> i64, nanoseconds (Netem.jitter_ns)
```

All `*_pct` fields (loss, duplicate, delay/loss/duplicate correlation, reorder
probability + correlation, corrupt probability + correlation) scale identically:
`u32 = round(percent / 100 * UINT32_MAX)` — this is the kernel's own probability scale
for netem (0 = never, `UINT32_MAX` = always), not specific to any one field.

### The psched-tick decision

The legacy `tc_netem_qopt.latency`/`.jitter` fields are documented in the kernel header
as microseconds but are historically **PSCHED ticks** internally (the scale a kernel
reports via `/proc/net/psched`, traditionally requiring `tc`'s own tick<->time conversion
using that file's numerator/denominator). This module avoids that conversion entirely:
it always writes `0` into the legacy `latency`/`jitter` qopt fields and instead sets the
exact nanosecond values via the 64-bit extended attributes `TCA_NETEM_LATENCY64` /
`TCA_NETEM_JITTER64` (added to the kernel specifically so callers don't have to do
psched-tick math) — this is the same approach modern `tc` itself takes when the running
kernel supports these attributes (present since Linux 4.14, 2017; universal today).
Trade-off accepted: a caller talking to a pre-4.14 kernel would see no delay/jitter
applied (the legacy fields are left at 0) — out of scope for this v1, and worth revisiting
only if a consumer ever needs such an old kernel.

On dump (`Socket.show`), a real kernel's `tc_netem_qopt.latency`/`.jitter` legacy fields
may come back **nonzero** even though this module never set them — the kernel populates
that legacy pair from its internally stored nanosecond value for old-tool compatibility.
`NetemWire.legacy_latency`/`.legacy_jitter` capture this (informational only, not
asserted against in the offline tests, which only exercise this module's own request
encoding); `NetemWire.delay_ns`/`.jitter_ns` (from the 64-bit attrs) are the values to
trust, and the live test confirms them exactly against both the module's own read-back
and the `tc qdisc show` oracle.

## Threat / permission model

`add`/`change`/`del` all need **CAP_NET_ADMIN** (RTM_NEW*/RTM_DEL* qdisc are privileged
rtnetlink operations); a non-privileged caller gets `error.AccessDenied` (mapped from
`NLMSG_ERROR`'s `-EPERM`/`-EACCES`). `show` (RTM_GETQDISC dump) needs no privilege —
matches `netlink`'s own RTM_GET* calls. Untrusted input is the kernel's reply, walked
through `netlink.codec`'s bounds-checked `AttrIterator`/`MessageIterator` (fuzzed there
already); this module's own `parseQdisc`/`parseNetemOptions` never panic or over-read on
a malformed/truncated payload (`error.Truncated`/`error.BadLength`), and are themselves
fuzz-tested. `percentToU32` rejects any `*_pct` outside `[0, 100]` (including NaN) before
any allocation happens, so a bad caller input can't build a half-formed request.

## Out of scope (v1)

- **Classful qdiscs** (htb, hfsc, cbq, prio, …) and their class hierarchy (`RTM_NEWTCLASS`
  family) — netem is a leaf qdisc; this module never builds a class tree.
- **Filters** (`RTM_NEWTFILTER` — u32/bpf/flower/…) — no filter attachment at all.
- **Other leaf qdiscs** (tbf, fq_codel, sfq, pfifo/bfifo, cake, …) — only `TCA_KIND =
  "netem"` is ever built or expected on read-back.
- **Non-root qdiscs** (attaching netem under a class, `tcm_parent != TC_H_ROOT`) — v1
  always targets the root.
- **netem's GI/GE loss models** (`TCA_NETEM_LOSS`, Gilbert-Elliot / 4-state) — only the
  flat i.i.d. `qopt.loss` probability is supported; `TCA_NETEM_DELAY_DIST` (empirical
  delay distribution) and `TCA_NETEM_SLOT`/`SLOT_DIST` (slotted delivery) likewise.
- **TCA_NETEM_RATE64 / ECN** — rates needing more than 32 bits, and the ECN-marking
  option, are not built.
- **The multicast rtnetlink event group** — no notification/monitoring, matching
  `netlink`'s own scope decision.

## Verification

- **Golden bytes** (primary regression guard): hand-derived, byte-exact `RTM_NEWQDISC`
  add request (delay 100ms/jitter 10ms/loss 1%), `RTM_DELQDISC`, and `RTM_GETQDISC` dump
  request encodings — any drift in the tcmsg/qopt/attribute layout fails these first.
- **Encode/decode round-trip**: build a request with every optional attribute populated
  (correlations, reorder+gap, corrupt, rate, both 64-bit time attrs), feed the built bytes
  back through `parseQdisc`/`parseNetemOptions` (simulating what a kernel dump reply looks
  like), assert every field survives exactly.
- **Zero-config encode**: `Netem{}` omits every optional attribute (byte-length assertion)
  and round-trips to all-default `NetemWire` fields.
- **`percentToU32`**: exact values at 0/50/100, and out-of-range/NaN rejection.
- **`errnoToError`**: every mapped errno (EPERM/EACCES/EEXIST/ENOENT/ENODEV/EINVAL/
  EOPNOTSUPP/ENOBUFS/ENOMEM) plus the degenerate-value guards (0, `INT_MIN`, unmapped).
- **Fuzz**: `parseQdisc` over arbitrary bytes (`std.testing.fuzz`) — never panics or
  over-reads.
- **Live (env-gated, `error.SkipZigTest` when unprivileged/non-Linux)**: an unprivileged
  `show()` on `lo` (asserts *some* qdisc kind comes back, no capability needed), and a
  CAP_NET_ADMIN-gated `add` → `show` → `change` → `show` → `del` → `show` round-trip on
  `lo`, each `show()` asserting the exact fields just written. Run privileged via:

  ```sh
  unshare -rn zig build test-tc
  ```

  This was run in the development environment (`unshare -rn` grants CAP_NET_ADMIN in a
  throwaway user+net namespace — no host state touched) — all tests passed, including the
  live round-trip. It was cross-checked against the real `tc` binary as an independent
  oracle at every step (`tc qdisc show dev lo`): after `add` (delay 100ms/10ms jitter,
  loss 1%) `tc` reported `qdisc netem 1: root refcnt 2 limit 1000 delay 100ms 10ms loss
  1%`; a repeat `add` failed `EEXIST` (`error.Exists`), matching `NLM_F_EXCL`; after
  `change` (delay 20ms, duplicate 5%) `tc` reported `qdisc netem 1: root refcnt 2 limit
  1000 delay 20ms duplicate 5%`; after `del`, both this module's own `show()` and `tc`
  reported the interface back on its default `noqueue` qdisc.

## Provenance

Clean-room from the kernel UAPI headers (`linux/rtnetlink.h` — struct tcmsg, TCA_*;
`linux/pkt_sched.h` — struct tc_netem_qopt and friends, TCA_NETEM_*), both GPL-2.0 WITH
Linux-syscall-note. No GPL header source is copied — only the uncopyrightable ABI facts
they document are used (struct layouts, numeric attribute/flag constants); the
Linux-syscall-note exception is what keeps this module cleanly MIT despite citing those
headers, exactly as already established for the `netlink` and `wireguard` modules. No
third-party *implementation* (iproute2 or otherwise) was consulted as a design reference
for this module — the kernel headers were sufficient, and rtnetlink attribute parsing is
order-independent by construction (`nla_parse`-style type lookup), so this module's own
choice of attribute-emission order carries no compatibility requirement. See `/NOTICE`.

## Status

`gap · linux · client · reentrant` + deps: `netlink` — canonical source is `pub const
meta` in `src/root.zig`.
