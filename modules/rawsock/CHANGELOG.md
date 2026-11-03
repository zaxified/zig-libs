# rawsock — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-03** — Card: scope `core`, measured and mutation dates corrected to 2026-11-03, the mutant schema described under the Audit line.

- **2026-11-03** — **BEHAVIOURAL, not breaking; CONSUMER-VISIBLE:** fourth round. `filter.validate` now follows the kernel's scratch-memory pass exactly (a read after a `ret`, or reached by a jump that skipped the store, is `Uninitialised`; checked against the real kernel on 210 programs): programs `validate` accepted before may be refused now. `compile`: `net A mask M` takes any mask (libpcap does), TCP-flag and ICMP-type names are numbers wherever a number goes (`port tcp-syn`, `icmp[icmptype] = tcp-syn`), `net 10 mask M` is `Syntax` (libpcap), a negative link shift is `UnsupportedExpression` instead of a cast panic. `ring`: **BREAKING for round-3 callers of `ring`:** `Ring.release` returns `ReleaseError!void` (`Closed`, `NotHeld`, `WrongBlock`; a double or out-of-order release moves nothing), `next` after `deinit` is `Closed` and while a block is held `BlockHeld`, `deinit` is idempotent, `Packet.vlan_tpid`, `Ring.fromMap` (a ring over caller memory, for tests); a bad PACKET header is returned by `Block.nextPacket` and does NOT fail the ring (only a bad block header does; the round-3 entry said otherwise). `bench-rawsock -- ring` measures live delivery (see SPEC).

- **2026-11-03** — **CONSUMER-VISIBLE (additive):** new opt-in `rawsock.ring`: a `TPACKET_V3` receive ring (`Ring.init(sock, opts)`, `next`, `release`, `stats`, `deinit`; typed `InitError`: `BadSize`, `AccessDenied`, `RingUnsupported`, `OutOfMemory`; the kernel's packet/drop/freeze counters accumulated; block and packet headers read from the shared map are checked as hostile input, `BadBlock` is terminal). Sizes are bounded (block 4 KiB..16 MiB, 2..1024 blocks, 256 MiB total, checked in 64 bits). A program that does not name `ring` is byte-identical (axp probe, ReleaseSmall mips32: unchanged). Bench: a gopacket/pcapgo + x/net/bpf Go candidate (`tools/go_bench`); `filter_run` rows against Go's BPF VM.

- **2026-11-03** — **BEHAVIOURAL, not breaking; CONSUMER-VISIBLE:** third round. `vlan and ip`, `vlan 5 and tcp port 80` etc. now compile with libpcap's shift (every primitive after a `vlan` looks inside the tag; `vlan and vlan 5` the second tag); `vlan and ip` was `UnsupportedExpression`. New `filter.Options.link` (`.ethernet`, `.linux_sll`, `.raw`) and `filter.Link` for `tcpdump -i any` and raw-IP savefiles; `filter.compileOpts` takes it. The ancillary vlan form stays alone-only. Oracle: 169 tcpdump rows on a 32-frame corpus (QinQ and tagged-SYN frames added) plus 20 rows each for SLL and raw savefiles from `tcpdump -y`.

- **2026-11-03** — **BEHAVIOURAL, not breaking; CONSUMER-VISIBLE:** fix round on the grade-2 pass. (1) `filter.compile`: `and` and `or` now have EQUAL precedence, left to right, as pcap-filter(7) says (`tcp or udp and port 53` is `(tcp or udp) and port 53`; it used to bind `and` tighter, silently accepting every TCP frame): anyone with a mixed `and`/`or` filter without parentheses gets a different program. (2) Jumps over 255 instructions are widened through `ja` (a list of 33 `ip host` terms, 14 `tcp port` or 5 `port` terms used to be `FilterTooComplex`; now up to the kernel's 4096 instructions). (3) `filter.run` follows the kernel where it was probed on Linux 7.0: `X + k` wraps in 32 bits, a register shift count is masked to 5 bits, a constant shift of 32 or more drops; new `filter.validate` (the kernel's attach-time checks, `ValidateError`), `filter.usesAncillary`, `filter.ancillary_base`; negative or ancillary load offsets drop in `run` and work in the kernel. (4) New in `compile`: `vlan` / `vlan N` as the whole expression (`compileOpts` with `Options.vlan_ancillary` for a live socket), `icmp6`, `proto N`, `ip|ip6 proto \tcp`, `ether proto \ip`, `net 10`, `net A mask M`, `host a or b` shorthand, `tcp[tcpflags]`, `tcp-syn`... and `icmp-echo`... constants, spaces inside brackets, octal numbers; numbers now follow libpcap (`1_000` and `+5` are `Syntax`, as in libpcap; Zig's parser took them). Host and network names, `ip multicast`/`broadcast`, `protochain` are `UnsupportedExpression` (some were `Syntax`). `pcapng.Reader`: reads the obsolete Packet Block, refuses a Simple Packet Block longer than its block and an `if_tsresol` that is not one byte (as libpcap does), and an error is terminal (the same error again from every later `next`). No error set changed. Tests: 151-expression tcpdump oracle (mixed and/or, long lists, vlan, shorthand), 160-program differential of `run` against libpcap, fuzz harness for `run`, live attach of a ja-widened filter, BE-correct seed corpora (the two red s390x/MIPS seed tests now pass), host-order pcapng writer test.

- **2026-11-03** — **CONSUMER-VISIBLE (additive; one stricter behaviour):** grade-2 pass. `filter.compile` gains IPv6 `host`/`net`, bare `host`/`net`, `arp`/`rarp host`, `portrange`, `less`/`greater`/`len`, `broadcast`/`multicast` and offset expressions `ether|ip|ip6|arp|rarp|tcp|udp|icmp|sctp[off:size] & mask RELOP n` (previously `UnsupportedExpression`; no error set changed). New `rawsock.pcapng` (reader and writer). `filter.run` is rewritten as one switch over the opcode (2.2x to 1.05x libpcap's interpreter): it now drops a frame on an opcode the kernel would refuse at attach time (`ret` with the X source, `ldx` from the packet, `ld` size with `imm`, ...) where it used to execute a lenient reading; a scratch slot nothing stored to still reads 0. Tests: 100-expression tcpdump oracle on a 30-frame corpus, pcapng fixtures from `editcap`, fuzz harnesses for filter/pcap/pcapng, sweep tests; tools: `bench.zig` + `c_bench.c` (vs libpcap), `gen_filter_oracle.py`, `gen_pcapng_fixtures.py`; `interop-rawsock` also checks the interface lookups against `ip`.

- **2026-10-30** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the § GS sweep: 32/36 + 4 eq; 3 new killing tests (gen depth cap exactly 512/513 on every edge kind, parser leaf cap 4096/4097, an exact-fit auxdata cmsg record).
- **2026-10-30** — **CONSUMER-VISIBLE (fixes only):** no-panic sweep + blind review (§ GS). `filter.compile` no longer overflows the stack on a long `a and a and …` chain (parser leaf cap at `max_insns` and a code-generator depth cap of 512 → `FilterTooComplex`; a too-long input with a later syntax error now reports `FilterTooComplex`); `filter.run` jump arithmetic saturates (32-bit); cmsg scanners total on a huge `cmsg_len`; `pcap.Reader.next` total on a hand-set `pos`; an interface name containing NUL is `NoSuchInterface`. Docs: `Reader.next` does not check `orig_len >= incl_len`; a persistent `RecvFailed` must not be retried in a tight loop. Tests: `src/sweep_test.zig`.
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — Ported to Zig 0.17.0. ifreq union-bytes `@bitCast` of `[N]u8` <-> int replaced by `std.mem.toBytes`/`bytesToValue` (native memory order, as the kernel ABI). Also: comptime `strRepeat` helper quota raised.
- **2026-10-09** — tests: deterministic fuzz driver `RAWSOCK_FUZZ` over the existing harnesses (Ethernet header,
  hardware address, ARP reply).

- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** `tools/interop.zig` (`unshare -rn zig build interop-rawsock`)
  asks the Linux kernel "who-has" over a veth pair through this module's own socket and ARP builder, and
  the kernel answers; the request and reply are frozen (`src/testdata/kernel_arp.zig`) and replayed without
  privileges: `arp.buildRequest` must build the request the kernel answered, `arp.parseReply` must read
  the kernel's reply. No defect.

- **2026-10-04** — mvp → core (survey 2026-09-30 backlog items 1–4 except the ring). ADDED
  `rawsock.filter`: `compile` (a pcap-filter(7) subset — `ip`/`ip6`/`arp`/`icmp`/`tcp`/`udp`/
  `sctp`, `ether src|dst|host|proto`, `ip [src|dst] host|net`, `ip proto`, `[tcp|udp|sctp]
  [src|dst] port`, `and`/`or`/`not`/parentheses — with libpcap's meaning, verified frame by frame
  against `tcpdump -r` on a 20-frame corpus for 35 expressions) and `run` (a classic-BPF
  interpreter with kernel semantics, itself checked against libpcap's own `tcpdump -dd`
  programs). `rawsock.pcap`: savefile writer/reader (µs/ns, either byte order) that reproduces
  `tcpdump -w` files byte for byte. `Options.timestamps` → `Frame.timestamp_ns`
  (`SO_TIMESTAMPNS`). `Socket.joinFanout` (`PACKET_FANOUT`, `FanoutMode`, defrag/rollover).
  `Frame.timestamp_ns` is a defaulted field and `Options.timestamps` is best-effort like
  `PACKET_AUXDATA` (null when the kernel refuses), so no error set changed — source-compatible. Mutation: 41 mutants, 35
  killed at once, 4 killed by new tests, 2 equivalent (removed: a dead step guard in `run`, a
  redundant empty-octet check in the IPv4 parser).

- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** A1/rawsock.md F12's last surviving
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
