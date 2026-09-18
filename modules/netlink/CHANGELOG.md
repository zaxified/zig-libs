# netlink — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `recvDatagramStrict`'s
  "only the kernel is a verified sender" guard was fail-OPEN on an
  undersized `msg_namelen` (accepted the datagram instead of rejecting it);
  now fail-closed. Not observable on today's ABI (`sockaddr_nl` is a fixed
  12 bytes) — it only changes behaviour if that struct ever grows.
  `Socket.neighborFlush` also no longer aborts a bulk flush the first time it
  meets an `AF_BRIDGE` VXLAN FDB entry (`error.MixedFamilies`): that entry is
  now counted in a new `FlushResult.skipped` field and the flush continues
  over the regular entries after it, matching the `dst_len == 0` precedent
  SPEC.md already documents. `scripts/checks/check-uapi-consts.py`'s `netlink`
  entry now also scans `root.zig` (~90 constants), not just `bridge.zig`.

- **2026-09-08** — **NO CONSUMER-VISIBLE CHANGE:** `bridge.fuzzBuilders` draws
  **31 knobs behind its two byte draws**, the longest such tail in the
  repository, and its corpus carried no octets past the name and the MAC. So
  every one of those knobs was its own minimum — `eos` returns `true` on an
  exhausted input, so every option was PRESENT with the value 0. `vlan_id_min`
  is 1 and both `buildFdbRequest` and `buildVlanRequest` open with `checkVid`,
  so those two builders answered `error.InvalidVlanId` on **every seed in the
  corpus** and had never once returned a request. Measured per builder:
  3/0/0/5/5 before, 3/2/3/4/5 after (13 of 25 accepted before, 17 of 25 after)
  — the previously pinned total of 13 could not show the two zeros, which is
  why the guard now pins the five builders separately.

  A seed is now written as the VALUES its 31 draws read, in a struct of the
  same type the harness records what it drew into, so the corpus guard compares
  the whole schedule with one `expectEqualDeep` — a draw inserted, removed or
  reordered fails there instead of silently shifting every later knob onto the
  wrong word. The seeds cover the VID range refusals (`vid_end` below `vid`, a
  VID above `vlan_id_max`, `self` and `master` together, a PVID with a range),
  a bridge request with no IFLA_INFO_DATA nest and a brport request with
  nothing to change.

  `root.fuzzBuilders`'s guard now pins its four builders separately too
  (3/3/4/5) and checks all six of its knobs, not just `prefix` and `ifindex`.

- **2026-09-07** — **The netns bridge integration test failed on any host with
  the tunnel modules loaded, and the module was fine.** `upAllButLoopback`
  identified the kernel-named veth peer positionally, resting on an assumption it
  stated in prose: *"a fresh netns holds exactly `lo`, the bridge, the port and
  the peer"*. It does not. The kernel auto-creates `sit0`, `gre0`, `gretap0` and
  `erspan0` in EVERY new namespace when those modules are loaded — measured on a
  7.0 kernel: `unshare -rn ip link show` lists **five** devices, not one. So the
  walk found four candidates, its own `TestAmbiguousVethPeer` guard fired, and the
  suite went red over the host's module list. ⭐ The guard was right to exist and
  right to fire; the assumption behind it was the defect. Two of the four
  auto-created devices are `ARPHRD_ETHER` with an all-zero MAC, so no property of
  a single link tells them from a veth end — what separates them is *when* they
  appeared, so the namespace is now snapshotted before anything is created and
  the peer is the one new device that is neither bridge nor port. Confirmed
  causal: emptying the snapshot reproduces the old failure exactly. Test-only.

- **2026-09-07** — **the five fuzz harnesses fetched their input and threw it away.** Each
  opened `smith.bytes(&buf)` and then sliced the buffer to
  `smith.valueRangeAtMost(u16, 0, buf.len)`. A `Smith` ranged draw reads eight input octets as
  a little-endian u64 and returns the range MINIMUM unless that u64 already lies inside the
  range, so the length was 0 for every seed and every decoder, walker and builder here ran on
  an empty slice with the seed sitting unread in the buffer. All five now draw with one
  `smith.slice(&buf)` call, and all five have a corpus — the walkers' and the typed parsers'
  built at run time by `codec`'s own encoders (netlink lengths and scalars are HOST byte
  order, so a hex corpus would be a little-endian one), the bridge parsers' quoted from the
  captures in the value tests. Measured, per harness, over its own corpus: `codec.fuzzWalkers`
  0 → 12 of 12 seeds non-empty and 0 → 9 messages / 12 attributes walked; `root.fuzzParsers`
  0 → 9 of 9 and 0 → 10 of 36 (seed, parser) pairs parsed; `root.fuzzBuilders` 1 → 5 of 5 and
  1 → 15 of 20 builds accepted; `bridge.fuzzParsers` 0 → 14 of 14 and 0 → 11 records;
  `bridge.fuzzBuilders` 0 → 5 of 5 and 5 → 13 of 25 builds accepted. Each harness now carries
  a corpus guard that pins those numbers.
- **2026-09-07** — two defects the collapse was hiding, both found by writing the guard.
  `codec.fuzzWalkers` drew its fixed-header skip with `valueRangeAtMost(u16, 0, 32)`, i.e.
  **always 0** — and every rtnetlink payload opens with an ifinfomsg/ifaddrmsg/rtmsg/ndmsg
  before its TLVs, so `Message.attrs(0)` stopped on that header's leading zero octets with
  `error.BadLength` and the attribute walker saw **0 attributes across the whole corpus** even
  after the buffer draw was fixed; the skip now comes from a full-width `smith.value(u64)` and
  is carried in each seed. `bridge.fuzzBuilders` gated every optional field on
  `smith.value(bool)`, a 1-bit draw that is likewise always its minimum — `false` — so `.mac`,
  `.dst` and every optional knob were null on every replayed seed and the mac buffer could not
  have reached `buildBridgeAddRequest` even with a perfect corpus; they are drawn with
  `smith.eos()` now, which reads one octet per decision.

- **2026-09-02** — **BREAKING: `codec.nestEnd` returns `error{AttrTooLong}!void`** (audit,
  drift campaign). It used to return `void` and close a nest with a bare
  `@intCast(list.items.len - off)` into the `nlattr`'s `u16` length — so a nest grown past
  65535 bytes was **silently truncated to its low sixteen bits** in ReleaseFast (a panic in
  Debug), the caller sent a message whose nest header covered a fraction of its payload, the
  kernel installed that fraction, and the send reported SUCCESS. Measured through `nftables`:
  6000 set elements asked for, batch committed, **1904 landed**, `lastFailure()` null. Its two
  siblings `appendAttr`/`appendAttrString` have always returned `AttrTooLong` for exactly this
  condition; the asymmetry was the defect, and a `void` return is what made it unreportable.
  Callers now `try` it (mechanical: 178 call sites across nine modules; `netlink`'s own
  `BuildError` and `bridge.BuildError` gained `AttrTooLong`, and `ethtool`/`nl80211`/`tc` map it
  onto their existing "request too large" errors the way they already map `appendAttr`'s).
  Splitting an over-large nest across several messages — what `nft(8)` does — is a caller's
  decision, so this layer refuses instead of guessing.

- **2026-08-18** — `Socket.neighborFlush(NeighborFlushFilter)`: the dump-then-delete loop
  behind `ip neigh flush`, which iproute2 has no single message for. Default state mask
  `NEIGHBOR_FLUSH_DEFAULT_STATE` (pinned by a unit test) reproduces iproute2's
  `filter.state = ~(NUD_PERMANENT|NUD_NOARP)` baseline (`ip/ipneigh.c`
  `do_show_or_flush()`), so `NUD.PERMANENT`/`NUD.NOARP` entries are exempt by default —
  `NeighborFlushFilter.state_mask` overrides this on purpose (`ip neigh flush`'s `nud`
  selector does the same). An entry vanishing between the dump and the delete
  (`error.NotFound`) is counted in `FlushResult.raced`, not raised. Security audit,
  same day: any other delete failure (e.g. `error.AccessDenied` if `CAP_NET_ADMIN` is
  lost mid-flush) used to abort and propagate, discarding `FlushResult` — a destructive
  bulk operation that could not say how far it got. Fixed to match `traceroute`'s
  `Trace.transport_err` precedent instead: `FlushError` now covers only failures with
  nothing yet deleted (the initial dump), and a mid-loop delete failure stops the loop
  and is recorded in the new `FlushResult.stopped` field alongside the real
  `deleted`/`raced` counts already accumulated, returned as a normal result rather than
  raised. See SPEC.md "Neighbour flush" for the two points where this deliberately does
  not replicate iproute2 (both in the safer direction), and for the full reasoning
  behind `stopped`.
- **2026-08-11** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on `libmnl` /
  `libnl` (framing + `mnl_nlmsg_ok`/`mnl_attr_ok`) (design reference, not a test
  anchor).
- **2026-07-22** — rtnetlink **writes**: `RTM_NEW*`/`RTM_DEL*` requests sent with
  `NLM_F_ACK` — `addressAdd`/`addressDel`, `routeAdd`/`routeDel`,
  `linkSet`/`linkUp`/`linkDown`/`linkAdd`/`linkDel`, `neighborAdd`/`neighborDel` — with
  `Create{ exclusive, replace, append }` mapping onto `NLM_F_CREATE`/`EXCL`/`REPLACE`/
  `APPEND`. The reply is matched on (portid, seq) and a non-zero errno becomes a typed
  error; `NETLINK_EXT_ACK` is set at `open` and the kernel's `NLMSGERR_ATTR_MSG` string is
  surfaced through `lastErrorMessage()`. `linkSet` keeps the `ifi_change` mask discipline
  — only the `IFF_*` bits the caller asked for are touched, and a change with nothing in it
  is `error.NothingToChange` rather than a silent no-op. The write engine itself is public
  (`nextSeq` + `requestAck`) so sibling modules can build their own requests on it, and
  `codec` gained `nestBegin`/`nestEnd` plus the `NLM_F_*` write modifiers.
- **2026-07-04** — New module: rtnetlink **dumps** — links / addresses / routes /
  neighbors over a pure-Zig netlink transport (sequence numbers, ACK/`NLMSG_ERROR` errno
  decoding, multi-part assembly) and a bounds-checked NLA/rtattr TLV codec. Read-only at
  this point: the module documented write ops (`RTM_NEW*`/`RTM_DEL*`) and multicast event
  monitoring as deliberately out of scope.
