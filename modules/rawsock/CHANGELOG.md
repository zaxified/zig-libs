# rawsock — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-16** — **NO CONSUMER-VISIBLE CHANGE:** A1/rawsock.md F12's last surviving
  mutant (m33, `setPromisc(false)` never actually issuing `DROP_MEMBERSHIP`) gets a
  permanent regression test. The prior measurement attempt checked the wrong kernel
  observable (`IFF_PROMISC` via `SIOCGIFFLAGS`, which `dev_get_flags()` derives from
  `dev->gflags` and which a `PACKET_MR_PROMISC` membership never touches, on any kernel,
  in any namespace — not a privilege gap). The right one, `dev->promiscuity`
  (`IFLA_PROMISCUITY` via `RTM_GETLINK`), moves under the standard `unshare -rn`-style
  recipe this campaign already uses, no VM required. New test-only `ifacePromiscuity()`
  helper (hand-rolled `RTM_GETLINK` query, same no-external-dependency style as the rest of
  the module); `scripts/vm/run.sh` gets a `rawsock` `guest_setup` entry creating a `dummy`
  device (`rstest0`) so the VM lane exercises a real netdevice, not just `lo`. F12 closed.
- **2026-09-11** — **NO CONSUMER-VISIBLE CHANGE:** A1/rawsock.md F12's two-gate mutation
  runner (`A1/repro/rawsock/mut/mutate.py`, host `zig test` lane + `unshare -rn` netns lane,
  36 mutations) ported into `modules/rawsock/tools/mutate.py` per CONVENTIONS.md #9 (a
  foreign-toolchain instrument belongs beside the module it checks, not in the audit tree).
  Mutation table and classification logic byte-identical to the original; 3 of 36 patterns
  had drifted from source changes since the audit (F13's `setRcvTimeout` error-checking, a
  variable rename, F4's filter-ordering change) and were updated to the current shape with
  the same mutation intent, then re-verified against the tree (36/36 patterns match, no
  accidental no-ops). Not executed this session (raw `zig test`/`unshare` calls are outside
  this campaign's modtest-only gate) -- F12 itself stays open until someone runs it and adds
  permanent tests for the surviving mutations.
- **2026-09-10** — A1 fix campaign, second-pass fix queue (no consumers in-repo, P1
  applies): three more of the audit's sixteen findings closed (fourteen of sixteen total).
  **New, additive:** `Socket.open`'s `Options.filter` — a classic-BPF program attached as
  the very first thing done to the socket, before `bind`/`SO_RCVBUF`/`SO_RCVTIMEO`, closing
  the window where a `setFilter` call made after `open` returns can leave frames the filter
  would reject already queued and delivered anyway (measured: the pre-existing pattern —
  `open`, then `setFilter` — still leaks a frame sent in between; `Options.filter` does not,
  in three repeated runs) (F4). `recv` now uses `recvmsg` instead of `recvfrom`, requesting
  `PACKET_AUXDATA`, and `Frame` gained `vlan_tci: ?u16` — the 802.1Q tag the kernel strips
  before this module ever sees a frame (`EthHeader.ethertype`'s doc) is no longer simply
  gone: the byte-stripping and ethertype-rewrite this module already exhibited are now a
  permanent regression test (previously undocumented as *behavior*, only as prose), and the
  new `PACKET_AUXDATA` parser is unit-tested against a real captured kernel control message.
  ⚠ Live population of the tag value itself (`TP_STATUS_VLAN_VALID`) was never observed set
  by this kernel for a manually-injected loopback frame in an unprivileged netns — `vlan_tci`
  reads `null` in that live test, an environment limit disclosed in `A1/rawsock.md` F3, not a
  code defect (part of F3 — the doc-comment half was already fixed in the prior pass).
  **Bug fix, internal only (no behavior change):** `formatHwaddr` replaced `std.fmt.bufPrint`
  with a hand-rolled hex table — byte-identical output (pinned by the existing round-trip
  test plus a new 256-sample comparison against the old implementation), measured 69.78 ns
  to 2.74 ns per call in `ReleaseFast` (25.5x) (F11).
  Open, deferred: F10 (the `socket()`→`bind()` window — needs a second real interface to
  reproduce, `lo` alone doesn't give it one) and F12 as a whole (the remaining socket-path
  mutation survivors need the audit's own two-gate `mutate.py` harness, out of scope for a
  single slot). scripts/modtest rawsock: 28/35 (7 privileged skip without CAP_NET_RAW);
  under `unshare --user --map-root-user --net`: 35/35, Debug and ReleaseFast alike.

- **2026-09-10** — A1 fix campaign, first pass (no consumers in-repo, P1 applies): ten of the audit's
  sixteen findings closed. **New, additive:** `Frame.wire_len` via `MSG_TRUNC` — a frame
  longer than the caller's buffer used to be indistinguishable from one that fit exactly
  (F1); `Socket.stats()` (`PACKET_STATISTICS`) — a socket that silently dropped 98.9% of a
  burst returned the same `error.WouldBlock` as a quiet wire, with no way to tell them apart
  (F5); `Options.recv_buf_bytes` (`SO_RCVBUF`) — the only knob on the queue size that
  directly bounds F5's loss (F14); `arp.Reply.sender_is_eth_src` — the Ethernet source vs.
  ARP sender MAC comparison `arpwatch`-style spoof detection depends on, surfaced rather
  than decided for the caller (part of F2). **Input hardening** (P1, no consumer to break):
  `arp.parseReply` now validates RFC 826's `ar$hrd`/`ar$pro`/`ar$hln`/`ar$pln` — before this,
  a frame declaring `ar$pro = 0x86dd` (IPv6) with `ar$pln = 16` decoded the first four bytes
  of a 16-byte address as a bogus IPv4 one; live on a real segment, 16 of 23 forged replies
  like this were accepted (F2). `hwaddr()` now checks the interface's hardware-address
  family and returns `error.NotEthernet` for anything that isn't `ARPHRD_ETHER` — a `sit`
  tunnel's own 4-byte remote address used to come back dressed as a MAC, and `lo`/`gre0`
  came back as an all-zero MAC indistinguishable from a real one (F6). **Bug fixes:**
  `LinkAddr.halen` now reports the bytes actually copied (`<= hwaddr_len`), not the kernel's
  raw `sll_halen` verbatim — the doc's own suggested `la.hwaddr[0..la.halen]` panicked in
  Debug/ReleaseSafe and was UB in ReleaseFast on an oversized `sll_halen` (F7);
  `setRcvTimeout`'s `setsockopt` failure is no longer discarded — `Options.recv_timeout_ms`
  can now fail `open` with `error.TimeoutFailed` instead of silently leaving a socket that
  blocks forever (F13). **Test-only, no production change:** the interface-name length guard
  (`ifaceIndexOn`) and `ifaceName`'s NUL-termination are now exercised directly in the
  privilege-free part of the test gate, not only by the example in Debug mode (F16); a
  17-character hwaddr with a uniformly wrong separator closes the one missing vector for an
  already-working check (F15); `arp.parseReply` gained a length-boundary ladder and a full
  `oper` enumeration (0..15) narrowing two of the audit's un-killed mutation survivors (part
  of F12, not closed as a whole — the socket-path survivors are untested by a unit test and
  would need the audit's own two-gate mutation run). **Docs only:** `EthHeader.ethertype`'s
  and `etherTypeFilter`'s comments no longer claim Linux preserves an 802.1Q tag before
  delivery — measured against a real veth pair and `tcpdump` on the same wire, it doesn't
  (F3, doc half only — the tag stays invisible to this module); `Options.recv_timeout_ms`'s
  doc now says explicitly that it bounds one `recvfrom` call, not a caller's whole wait loop
  — measured 200 ms requested, 19.2 SECONDS actually waited against a flooding peer without
  an attached filter (F8, closed — the module's own answer, an in-kernel filter, was already
  correct; only the documentation gap remained).
  Open, deferred: F3's code half (`PACKET_AUXDATA`/`recvmsg`, a new `Frame.vlan_tci`), F4
  (the `setFilter` open→bind window), F10 (the `socket()`→`bind()` window), F11
  (`formatHwaddr` perf, WONTFIX-shaped), F12 as a whole (see above). Measured RED→GREEN for
  every closed item (mutation or a genuine live-socket run under `unshare --net`), and
  `-Doptimize=ReleaseFast` in both a plain and a network-namespaced lane, not just Debug.
  scripts/modtest rawsock: 27/32 (5 privileged skip without CAP_NET_RAW); under
  `unshare --user --map-root-user --net`: 32/32, Debug and ReleaseFast alike.

- **2026-09-07** — Test-only, no production change: two of the three fuzz targets had an
  entire arm that had never executed. `fuzzParseHwaddr` and `fuzzArpParseReply` both open
  with `smith.value(bool)` and neither had a corpus, so outside `--fuzz` the input was
  already exhausted and the draw returned FALSE every round. In `parseHwaddr` that meant
  only the "structurally-correct skeleton" arm ran - and inside it every `smith.index` was
  0 too, so the text built was always the same `"00:00:00:00:00:00"`; the raw-bytes arm,
  the length/separator gate, had never run at all. In `arp.parseReply` it was the other way
  round: only the raw-bytes arm ran and its own length draw was 0, so the single call the
  target ever made was `parseReply("")`, and the arm that starts from a REAL ARP reply and
  mutates it - the one that gets past the ethertype/oper checks so the sender IP/MAC
  extraction runs on hostile data - had never executed once. `fuzzEthHeaderParse` was the
  plain case: `bytes` plus a ranged length, so `parse` returned null off its
  `frame.len < 14` check every round. All three now draw bytes first, the two shape
  harnesses reading their choices out of that draw through `testkit.fuzz.Cursor`. Seeded
  from the module's own captured frames. Measured by the three new `corpus:` guards -
  Ethernet: 4 non-empty seeds, 3 parsed, **3 rewriting back to their own fourteen octets**;
  hwaddr: **7 raw-arm and 5 skeleton-arm runs**, 5 accepted, **4 distinct addresses**
  (1 at best before, and the raw arm 0); ARP: 4 raw-arm and **5 mutate-arm** runs, **8
  mutations applied**, 5 frames parsed - all of which were 0 before.

- **2026-08-18** — New: `ipv4Addr` / `ipv4Netmask` (`SIOCGIFADDR` / `SIOCGIFNETMASK`),
  following the exact `ifreq`-ioctl shape of `hwaddr`/`ifaceName`. Closes the last raw
  syscall a consumer had to hand-roll to learn its own subnet for an ARP sweep — the
  module previously stopped at the link layer (`SIOCGIFHWADDR`). Purely additive; no
  existing behavior changed.
- **2026-07-19** — Security audit: no findings. Modeled on `libpcap` (minimal AF_PACKET
  path) (design reference, not a test anchor).
- **2026-07-09** — New module: Linux AF_PACKET raw-frame capture + inject — BPF filter,
  promiscuous mode, typed frame decode.
