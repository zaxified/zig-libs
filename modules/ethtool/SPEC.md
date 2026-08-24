# ethtool — design, verification and threat model

What this module is and how to use it: see [README.md](README.md).
Metadata (platform/role/concurrency/deps): `pub const meta` in
`src/root.zig`. Provenance and licences: the repo-root `NOTICE`.

This document answers the other question — how it was built, what it is
asserted against, and what could go wrong.

## 1. Verification story

### 1.1 Two capture environments

| environment | what it produced |
|---|---|
| ordinary unprivileged user, real NICs (`enp0s31f6`, an Intel `e1000e`; `wlp2s0`, `iwlwifi`) | every request golden, and the GET-reply and error goldens |
| unprivileged user+net namespace (`unshare -rn`) with a `veth` pair | the two compact `FEATURES_SET_REPLY` goldens and the `FEATURES_NTF` notification golden — all three need CAP_NET_ADMIN to provoke |
| `unshare -rn` + a raw `AF_NETLINK` socket (Python `socket.AF_NETLINK`, no library beyond stdlib) instead of the real `ethtool` binary | `reply_features_set_honoured_verbose` (wave-2 F1) — the real `ethtool` CLI always requests a *compact* reply, so the *verbose* reply shape this module's own `setFeaturesByName` actually receives had no capture route through `ethtool` itself; sending the request by hand (same verbose `WANTED` bitset, `compact_bitsets` omitted) was the only way to provoke it |

The namespace harness is the one `CONVENTIONS.md` §7 prescribes for netlink
modules. It is worth stressing that SET *requests* did **not** need it: the
kernel refuses an unprivileged SET only after `ethtool` has already handed the
bytes to `sendto`, so an unprivileged `strace` still pins them byte for byte.

### 1.2 Request goldens — captured from a real `ethtool`, byte for byte

```sh
strace -f -e trace=%network -e write=all -e read=all -xx -s 16384 \
    -e abbrev=none ethtool <args>
```

`-e trace=%network`, not `sendmsg`: **`ethtool` sends with `sendto`**, so the
`-e trace=sendmsg` recipe the sibling `nl80211` goldens use captures the
kernel's replies and none of the requests. That cost an hour and is recorded
at the top of `src/goldens.zig` so it costs nobody else one.

Twenty-one request goldens are committed, one per command line:

| command | pins |
|---|---|
| `ethtool enp0s31f6` | `LINKMODES_GET` (no flags), `LINKINFO_GET`, `LINKSTATE_GET` |
| `ethtool -g / -c / -a / -l / -k` | `RINGS_GET`, `COALESCE_GET`, `PAUSE_GET`, `CHANNELS_GET`, `FEATURES_GET` |
| `ethtool -a` (2nd request) | `LINKMODES_GET` **with** `ETHTOOL_FLAG_COMPACT_BITSETS` — the same command as the first golden, differing in exactly the 8 bytes of the flag attribute |
| `ethtool -k`, `ethtool -S … --groups` | two `STRSET_GET`s with an **empty header nest** (a device-independent string table) |
| `ethtool -S enp0s31f6 --groups eth-mac eth-ctrl rmon` | `STATS_GET` + the verbose name-keyed group bitset + the one command whose header nest is attribute **2**, not 1 |
| `ethtool -G … rx 512`, `-A … autoneg off`, `-K … tso off`, `-s … speed 100 duplex full autoneg on` | the four SET request shapes |
| `ethtool -m enp0s31f6` | `MODULE_EEPROM_GET` |
| `unshare -rn` + `ethtool -K veth0 tso on` | the 5-name masked verbose `FEATURES_SET` bitset |
| `unshare -rn` + `ethtool -L veth0 combined 1` / `-C veth0 adaptive-rx on` / `-s veth0 port tp` / `--set-module veth0 power-mode-policy high` | `CHANNELS_SET`, `COALESCE_SET`, `LINKINFO_SET`, `MODULE_SET` (wave-2 F6 — these four had **no** golden at all, self round-trip only, until this pass) |

Only `nlmsg_seq` is treated as a runtime value (each test builds with the
sequence the capture used). `nlmsg_pid` needs no special handling — `ethtool`,
like this module, writes 0 and lets the kernel fill it in. Everything else,
including attribute order and padding, is a plain byte compare.

Each of those tests drives this module's own public request encoder (§2.1a) —
the same `buildX` the client method calls — so the capture is compared against
what an `Ethtool` actually puts on the wire, not against a re-spelling of it
in the test. `FEATURES_SET` is the exception, for the reason §2.1a gives.
Encoder shapes `ethtool` never sends (a SET keyed by bit index, a *device's*
string sets, `PAUSE_GET` with `ETHTOOL_FLAG_STATS`, `MODULE_GET`) have no
capture to compare against and are decoded back with this module's own
primitives instead, asserting the optional attributes that must be **absent**
as well as those present.

One encoder was reordered to keep that compare plain: `appendLinkModesSet`
emits speed → duplex → autoneg, which is the order `ethtool -s` uses. Netlink
attaches no meaning to attribute order; matching the reference tool turns a
set comparison into a byte comparison, which is strictly stronger.

### 1.3 What could **not** be captured from `ethtool`

- **Compact bitsets in a request.** `ethtool` always keys the bitsets it
  *sends* by name, because userspace does not want to hardcode kernel bit
  numbers. `bitset.appendCompact` and `bitset.appendIndexedValues` are
  therefore UAPI-derived and covered by round-trip + hostile-input tests.
- **A verbose `FEATURES_GET` reply.** `ethtool` always sets
  `ETHTOOL_FLAG_COMPACT_BITSETS` for features. That reply was fetched instead
  with a 30-line raw `AF_NETLINK` client — the oracle there is the kernel
  itself, not `ethtool`. It earns its place: it is the only golden that pins
  the `NOMASK`-verbose rule in §2.2.
- **The `monitor` notification.** `ethtool --monitor` only prints, so the
  group was joined by a small raw reader in the namespace while `ethtool -K`
  ran. The committed message is the kernel's, byte for byte.
- **Non-empty statistics groups.** No NIC available implements the
  standardised `eth-mac`/`eth-ctrl`/`rmon` counters, so the real `STATS_GET`
  reply has three groups and no counters in them — which is itself the case
  worth pinning (empty ≠ error). Counter and histogram decoding, including the
  open-ended last RMON bucket, is covered by constructed replies in
  `stats.zig` and is honestly labelled UAPI-derived.
- **Module EEPROM data.** No pluggable transceiver was available; only the
  request is pinned. `moduleinfo.parseEeprom` is covered by constructed
  replies.

### 1.4 Decoder goldens — real kernel replies

Sixteen reply goldens are decoded back through the module. The ones that carry
their weight:

- **The same link-mode bitset in both encodings** (`ethtool <dev>` verbose vs
  `ethtool -a <dev>` compact, seconds apart on the same NIC). A dedicated test
  walks all 125 bits and requires `supports`/`advertises` to agree — so the two
  decoders check each other rather than both being checked against my reading
  of the header.
- **The same feature bitsets in both encodings**, likewise cross-checked over
  all 64 bits for active/supported/fixed.
- **`FEATURES_GET` + `STRSET_GET` together**, exercising the name → index →
  bit round trip that compact bitsets force on a caller. This is what caught
  the fact that four of the 64 feature bits are named with an **empty string**
  — a decoder that skipped empty names would have silently shifted every index
  after them.
- **Two `FEATURES_SET_REPLY`s**, one fully honoured and one where the kernel
  refused four of five requested bits. These are what established the actual
  diff semantics (§2.3). Both are **compact** — the format the real `ethtool`
  CLI asks for (it always sets `compact_bitsets`, per `bitset.zig`'s file
  header). This module's own `setFeaturesByName`/`setFeaturesByIndex` never
  set that flag (`client.zig`'s `setFeaturesImpl`), so the reply shape the
  shipped code path actually receives was, until wave-2 F1, unanchored —
  the two committed goldens exercised a request shape our own API doesn't
  send. Closed by a **third** `FEATURES_SET_REPLY` golden,
  `reply_features_set_honoured_verbose`, captured live (`unshare -rn`, a raw
  `AF_NETLINK` socket carrying the exact same verbose `WANTED` bitset
  `ethtool -K veth0 tso on` sends, header's `compact_bitsets` omitted) — the
  first byte-exact evidence for what the kernel actually replies with on the
  path this module's own by-name API drives. (Considered and rejected: just
  making `setFeaturesImpl` set `compact_bitsets` to match the two existing
  goldens instead — that would silently break `SetResult.honouredByName`,
  which only has names to report when the reply is verbose, for every
  caller of `setFeaturesByName`.)
- **A real `FEATURES_NTF`** off the `monitor` group, decoded with the ordinary
  `features.parse` to demonstrate that a notification's payload is a GET
  reply's payload.
- **Three error replies**: `-EPERM` (`WOL_GET` unprivileged), `-EOPNOTSUPP`
  with no extended ACK (`CHANNELS_GET` on `e1000e`), and `-EOPNOTSUPP` **with**
  `NLMSGERR_ATTR_MSG` = "failed to retrieve link settings" (`LINKMODES_GET` on
  Wi-Fi). The last one is why the socket enables `NETLINK_EXT_ACK`, and it also
  pins the uncapped-echo layout: the kernel echoes the *whole* request when it
  attaches a message, so the ext-ACK walk must skip `nlmsg_len` bytes, not 16.
- **The nlctrl `CTRL_CMD_NEWFAMILY` reply**, asserting family id 23 and
  `monitor` group id 8 — and that 23 > `GENL_ID_CTRL`, i.e. that it really is
  dynamically assigned.

### 1.5 Anonymisation

One **length-preserving** substitution was applied to every committed reply:
`nlmsg_pid` was zeroed. That field is the capturing process's netlink port id,
which the kernel derives from its pid; it identifies a session on the capture
machine and nothing about the protocol, and nothing in these tests reads it
(the goldens are decoded, not matched against a socket).

Nothing else was touched. There is nothing else to touch: **the ethtool
netlink family carries no MAC addresses, serial numbers or bus IDs at all.**
The one command that would (`ethtool -i` — driver, firmware version, bus id)
has no netlink message and never left the ioctl path. The `MODULE_EEPROM` data
attribute *could* carry a transceiver serial number, but no module was present
and no EEPROM bytes were captured.

Interface names (`enp0s31f6`, `wlp2s0`, `veth0`) were deliberately kept: they
are udev bus-path names or names this harness created, they carry no identity,
and keeping them makes the capture commands in the comments reproducible.

### 1.6 Hostile-input tests

Every decoder is fed truncated TLVs, wrong-width scalars and contradictory
attributes, and must answer with `error.Truncated` / `error.BadLength` rather
than a panic or an over-read. Specifically rejected:

- a compact bitset whose `VALUE`/`MASK` word count contradicts its `SIZE`;
- a `VALUE` payload that is not a whole number of `u32` words;
- a bitset carrying **both** encodings, or `NOMASK` **and** a `MASK`;
- a `SIZE` or `COUNT` of `0xffffffff` — bounded (`bitset.max_bits`,
  `stats.max_strings`) *before* any allocation;
- a bit index at or beyond `max_bits`;
- duplicate `VALUE`/`OURS`/`HW`/`ACTIVE`/… attributes (a leak vector, since the
  second parse would orphan the first allocation);
- a string-set entry with no index or no value (it would put every later index
  out of step);
- an `ETHTOOL_A_MODULE_EEPROM_DATA` longer than the kernel's own 128-byte
  ceiling;
- a statistics counter that is not exactly 8 bytes.

Four `std.testing.fuzz` harnesses (bitsets, parameters, statistics/string
sets, notifications) additionally require no crash, no leak and no unbounded
loop on arbitrary bytes.

### 1.7 Live tests

Eleven tests run against the real kernel. They pick a target with the sibling
`netlink` module's `RTM_GETLINK` dump (not `/sys` — same no-libc discipline,
and it yields `ARPHRD_ETHER` so a loopback or tunnel is not mistaken for a
NIC), and every one of them prints `SKIPPED: …` and passes when a driver does
not implement the operation. `EOPNOTSUPP` is the *normal* answer for most of
this family on most drivers; a suite that failed on it would be useless.

The strongest one asks the same kernel for the same link modes twice, once
verbose and once compact, and requires every bit to agree — a decoder bug in
either encoding fails on any machine with an Ethernet NIC.

Two tests need CAP_NET_ADMIN (`RINGS_SET` writing the current value back, and
`FEATURES_SET` re-requesting a feature's current state) and skip without it.
Both were run for real inside `unshare -rn` against a `veth` pair; the
features one exercises the full SET → `SetResult` path.

## 2. Design invariants

### 2.1 Nothing the kernel assigns is hardcoded

The family id was 23 on the development machine; it is whatever nlctrl hands
out on the next boot, and is resolved at open. So is the `monitor` group id (8
here). `genetlink` deliberately stops before multicast-group resolution, so
the `CTRL_ATTR_MCAST_GROUPS` walk lives here as a pure function
(`client.findMcastGroupId`) — the same extension point `nl80211` documents. If
a third family needs it, that is the code to promote.

### 2.1a One encoder per operation, and it is public

Building a request and performing it are separate steps, and only the second
needs a socket. Each request-performing `Ethtool` method has a matching
`buildX` function in the topic module next to the attribute appenders it uses
(`link.buildLinkModes`, `params.buildSetRings`, `stats.buildStringSet`, …),
re-exported flat from the root. It takes the family id and sequence number —
the two runtime facts the socket owns — and returns the complete datagram, so
a caller with its own transport gets exactly the bytes this module would send.

The *invariant* is the point: the client method **calls** that encoder and
sends what it returns. There is no second spelling of any operation's message,
and the `nlmsghdr`+`genlmsghdr` frame they share is written once, in
`header.beginRequest`/`header.finishRequest`. `client.zig` carries a test that
asserts against its own source text that the frame has not been re-inlined
there — a re-inlined copy would compile and would pass every byte test, since
the encoders would still be correct, so no value-level assertion can catch it.

One request shape differs from what the `ethtool` binary sends, deliberately
and unchanged here: `FEATURES_SET` goes out with no header flags, where
`ethtool -K` sets `ETHTOOL_FLAG_COMPACT_BITSETS`. Both are valid; this module
reads the verbose `FEATURES_SET_REPLY`. `goldens.zig` pins the difference.

### 2.2 Bitsets: three rules, all learned from bytes

1. **Encoding follows the request.** A reply's bitsets are compact iff the
   request's `ETHTOOL_A_HEADER_FLAGS` carried `ETHTOOL_FLAG_COMPACT_BITSETS`.
   Nothing else influences it.
2. **`isSet` ≠ "supported".** A masked bitset is a (value, mask) pair, and a
   clear bit outside the mask means *unsupported*, not *off*. `inMask` is the
   other half; `LinkModes.supports` / `.advertises` are the named forms.
3. **`NOMASK` changes what an entry means.** In a `NOMASK` verbose bitset the
   kernel emits only the set bits and attaches **no `VALUE` flag at all** —
   presence is the value. The committed verbose `FEATURES_GET` reply shows both
   shapes in one message: its masked `hw` bitset lists all 64 bits with `VALUE`
   on the capable ones, while its `NOMASK` `active` bitset lists only the nine
   that are on, none of them carrying `VALUE`. A decoder that read `Bit.value`
   there would report every feature as off. `Bit.value` is deliberately left as
   the raw wire flag; `isSet`/`isSetByName` apply the rule.

The word count of a compact bitset is `ceil(size/32)` exactly, enforced in both
directions — a reply that disagrees is malformed, not something to guess at.

### 2.3 A SET's ACK is not proof, and the *mask* is the signal

`FEATURES_SET` always ACKs. The `FEATURES_SET_REPLY`'s two bitsets are diffs:

| attribute | mask means | value means |
|---|---|---|
| `WANTED` | this bit's result differs from what was requested | what was requested |
| `ACTIVE` | this bit's active state actually changed | its new state |

Both captured replies confirm it. In the refused one the request asked for
five TSO bits on; `WANTED` came back with mask = the four that stayed off and
value = those same four (i.e. "you asked for these on"), while `ACTIVE` came
back with mask = value = the single bit that did turn on. In the honoured one
`WANTED` was empty and `ACTIVE`'s mask was all five with a zero value ("all
five moved, to off").

The consequence for the API: `fullyHonoured` counts **mask** bits, via
`Bitset.maskCount`, not set value bits. Counting values would call a feature
that was requested *off* and refused a success, because its value bit is 0.

`SetResult` is a different type from `Features` on purpose: the attribute
numbers are the same but the meanings are not, and reusing `Features` would
invite reading `active` as "what is on now".

### 2.4 Absent is not zero

Every reply field is an optional and nothing is defaulted. `ethtool -g` prints
`n/a` for exactly the attributes the kernel omitted, and a consumer that
turned those into 0 would report a device with no TX ring. Symmetrically, an
absent field in a `*Set` struct means "leave it alone": a SET carries only what
changes, and sending an empty one is a legal no-op rather than a wipe.

### 2.5 The blocking seam

`EventSocket` has exactly one blocking call, `waitForNotification`, doing one
`recvmsg` when its buffer is drained. `fd()` is exposed so a caller can poll
with its own deadline. There is no timer thread, no deadline parameter and no
event loop in this module — the same discipline as `nl80211.EventSocket`,
`netconf.Client.pumpOnce` and `ebpf`'s ring-buffer consumer.

The event socket is separate from the command socket because multicast
membership is per-socket: subscribing the command socket would make every
request have to filter unsolicited notifications out of its own reply stream.

### 2.6 Lifetimes

Anything with a heap allocation (`LinkModes`, `Features`, `SetResult`, `Stats`,
`StringSets`, `Eeprom`, `Notification`, `Bitset`) owns it and has `deinit`.
Everything else is a plain value type whose strings live in fixed inline
buffers (`header.Device`), so it can be returned by value and outlive the
receive buffer. Every allocating parser has `errdefer` on the partially-built
result, and duplicate-attribute checks exist partly to make that airtight.

## 3. Threat model

The peer is the local kernel, so this is not an adversarial channel in the way
`nl80211`'s over-the-air information elements are. What is still defended
against:

- **A corrupt or truncated datagram.** Every length is validated by the
  `netlink` codec before a slice is formed; iteration advances ≥ 4 bytes per
  step, so a walk over N bytes terminates in ≤ N/4 steps.
- **An allocation driven by an attacker-controlled length.** `SIZE`, `COUNT`,
  bit indices and EEPROM lengths are all bounded before `alloc` is called.
- **A future kernel.** Every enum is `_`-open, unknown attributes are skipped,
  and unknown message types reach the caller as raw numbers rather than being
  rejected. The one hardcoded table (`stats.group_names`) is asserted against
  the kernel's own `ETH_SS_STATS_STD` reply, in both a golden and a live test,
  so a kernel that reorders or renames a group breaks a test instead of
  silently mislabelling data.
- **Privilege confusion.** The module never guesses at capabilities: EPERM and
  EACCES map to `error.AccessDenied` and are reported, never retried or
  worked around.

What is explicitly **not** defended against: a caller passing a device name it
did not validate. Names are length- and NUL-checked (so they cannot overflow
`IFNAMSIZ` or smuggle an embedded terminator), but a name is otherwise passed
through to the kernel, which is the correct place to resolve it.

## 4. Deferred

Reachable through `Ethtool.raw`, not modelled:

| command family | why deferred |
|---|---|
| `WOL_GET`/`SET` | needs CAP_NET_ADMIN even to read, and its `SOPASS` is a secret that deserves its own handling |
| `EEE_GET`/`SET`, `FEC_GET`/`SET` | more bitsets, no new decoding problem; add on demand |
| `PRIVFLAGS`, `DEBUG` | driver-private string-keyed flag sets; the `STRSET` half is already here |
| `TSINFO`/`TSCONFIG`, `PHC_VCLOCKS` | PTP timestamping — a coherent sub-domain of its own |
| `CABLE_TEST_ACT` / `_TDR_ACT` | asynchronous: the result arrives as a notification, so it needs a request/notification correlation design this v1 does not have |
| `RSS_GET`/`SET`, `PLCA`, `MM`, `PSE`, `PHY`, `TUNNEL_INFO`, `MODULE_FW_FLASH` | newer and narrower; several are still churning |
| the all-devices **dump** form (`NLM_F_DUMP` with an empty header nest) | the typed API is per-device; `raw(.{ .dump = true })` reaches it |

Not deferred but **permanently out of scope**: the legacy `SIOCETHTOOL` ioctl
API, and with it `ethtool -i` (drvinfo) and plain `ethtool -S` (the driver's
private counter array). Neither has a netlink message; implementing them would
mean a second, unrelated transport inside a module whose whole premise is the
netlink one. A consumer that needs drvinfo should read
`/sys/class/net/<dev>/device/{vendor,device}` and the driver link, or shell out.

Also deliberately absent: **SFF-8472 / SFF-8636 / CMIS decoding.**
`moduleEeprom` returns raw bytes and stops there; turning them into vendor
strings, wavelengths and DOM readings is a separate spec family and would be
its own module.

## 5. Provenance

Clean-room from the kernel UAPI headers `linux/ethtool_netlink_generated.h`
and `linux/ethtool.h` (GPL-2.0 WITH Linux-syscall-note). Constants,
attribute numbers and message layouts are the kernel's OS ABI — the interface,
not an implementation — and are reproduced here as such.

The `ethtool` binary (v6.19) was used **only as a black-box oracle**: run under
`strace`, its `sendto` payloads compared against this module's encoders. No
`ethtool` source was read or ported, and no `ethtool` behaviour beyond the wire
bytes was copied. Per `CONVENTIONS.md` §5 a black-box oracle is neither
required attribution nor a design reference; the `NOTICE` entry this module
does need is for the **kernel UAPI headers**, on the same Linux-syscall-note
basis as `netlink`/`genetlink`/`nl80211` — see `NOTICE`.

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** real ethtool binary as capture oracle under strace, goldens.zig
