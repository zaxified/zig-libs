# ethtool

Native **Ethernet device control** over the kernel's modern `ethtool`
generic-netlink family: link settings and state, ring / coalesce / pause /
channel parameters, netdev feature flags, the standardised statistics groups,
the kernel's own string tables and pluggable-module (SFP/QSFP) access — no
`ethtool` shell-out, no `SIOCETHTOOL` ioctl, no libc.

- No maintained pure-Zig ethtool-netlink client exists.
- **Model after:** the kernel UAPI (`linux/ethtool_netlink_generated.h`,
  `linux/ethtool.h`). The `ethtool` binary was used **only as a black-box
  capture oracle** under `strace` — its requests are the byte-exact goldens
  this module is asserted against — no `ethtool` source was read or ported.
- **Platform:** linux (raw `std.os.linux` AF_NETLINK syscalls — a conscious
  ceiling). **Role:** client. **Concurrency:** reentrant (no globals; one
  `Ethtool` / `EventSocket` per thread/loop).
- **Deps:** `genetlink` — the generic-netlink layer (`genlmsghdr`, nlctrl
  family resolve, `NETLINK_GENERIC` socket), re-exported here as
  `ethtool.genl`; `netlink` — its bounds-checked wire codec, re-exported as
  `ethtool.codec`.
- **Privileges:** every GET in the typed API is **unprivileged**. Every SET
  needs **CAP_NET_ADMIN**. Joining the `monitor` multicast group needs none.

Provenance: original work of the zig-libs authors (MIT); clean-room from the
kernel UAPI `linux/ethtool_netlink_generated.h` and `linux/ethtool.h` (GPL-2.0
WITH Linux-syscall-note — the message/attribute/flag constants and the bitset
and nest layouts are the kernel's OS ABI, not copyrightable interface code),
relying on the same Linux-syscall-note exception as
`netlink`/`genetlink`/`nl80211`/`wireguard`. The `ethtool` binary (GPL-2.0) was
run ONLY as a black-box test oracle under `strace`, its request bytes diffed
against this module's — no `ethtool` source consulted, studied or ported.

## Scope

| | |
|---|---|
| **Implemented** | `LINKINFO_GET`/`SET`, `LINKMODES_GET`/`SET`, `LINKSTATE_GET`, `RINGS_GET`/`SET`, `COALESCE_GET`/`SET`, `PAUSE_GET`/`SET`, `CHANNELS_GET`/`SET`, `FEATURES_GET`/`SET`, `STATS_GET`, `STRSET_GET`, `MODULE_GET`/`SET`, `MODULE_EEPROM_GET`, the `monitor` multicast group |
| **Escape hatch** | `Ethtool.raw` — any command, caller-encoded attributes, replies handed back as attribute bytes |
| **Deferred** | WOL, EEE, FEC, PRIVFLAGS, DEBUG, TSINFO/TSCONFIG, cable test, RSS, PLCA, MM, PSE, PHY, tunnel info, module firmware flash, and the all-devices dump form — all reachable through `raw`; see `SPEC.md` |
| **Not here, permanently** | the legacy `SIOCETHTOOL` **ioctl** API. That is what `ethtool -i` (driver/firmware/bus info) and plain `ethtool -S` (the driver's private counter array) still use — there is no netlink message for either. See "What is not here" below. |

## API

```zig
const ethtool = @import("ethtool");

var et = try ethtool.Ethtool.open(gpa);    // resolves the family id — never hardcode it
defer et.close();
const dev = ethtool.Target.byName("eth0"); // or .byIndex(2)

// ── link ─────────────────────────────────────────────────────────────────
const st = try et.linkState(dev);          // link up/down, SQI, ext-state
const li = try et.linkInfo(dev);           // port, PHY address, MDI-X, transceiver

var modes = try et.linkModes(dev, .verbose);   // .verbose = bitsets carry names
defer modes.deinit(gpa);
_ = .{ modes.autoneg, modes.speedMbps(), modes.duplex };
_ = modes.supports(ethtool.uapi.LINK_MODE.@"1000baseT_Full");   // in the mask
_ = modes.advertises(ethtool.uapi.LINK_MODE.@"1000baseT_Full"); // in the value

try et.setLinkModes(dev, .{ .autoneg = false, .speed_mbps = 100, .duplex = .full });

// ── parameters (every field optional: absent = "n/a", never 0) ────────────
const r = try et.rings(dev);
_ = .{ r.rx, r.rx_max, r.tx, r.tx_max, r.tx_push };
try et.setRings(dev, .{ .rx = 512 });        // absent fields are left alone

const c = try et.coalesce(dev);
const p = try et.pauseParams(dev, true);     // true = ask for the stats nest
const ch = try et.channels(dev);
try et.setPause(dev, .{ .rx = true, .tx = true });
try et.setChannels(dev, .{ .combined_count = 4 });

// ── features ─────────────────────────────────────────────────────────────
var f = try et.features(dev, .verbose);
defer f.deinit(gpa);
_ = f.isActive("rx-gro");                    // ?bool — null = no names in this reply

var res = try et.setFeaturesByName(dev, &.{
    .{ .name = "tx-tcp-segmentation", .on = false },
});
defer res.deinit(gpa);
if (!res.fullyHonoured()) {                  // the ACK alone proves nothing
    _ = .{ res.unhonouredCount(), res.changedCount(), res.honouredByName("tx-tcp-segmentation") };
}

// ── statistics + the kernel's name tables ────────────────────────────────
var s = try et.stats(dev, &.{ "eth-mac", "eth-ctrl", "rmon" });
defer s.deinit(gpa);
if (s.group(.eth_mac)) |g| _ = .{ g.stats, g.hist_rx, g.value(0) };

var sets = try et.stringSet(null, &.{ .features, .stats_eth_mac });
defer sets.deinit(gpa);
_ = sets.byId(.features).?.get(16);          // bit 16's kernel name

// ── pluggable transceiver ────────────────────────────────────────────────
const mi = try et.moduleInfo(dev);           // EOPNOTSUPP on a fixed-PHY NIC
var page = try et.moduleEeprom(dev, .{ .offset = 0, .length = 128 });
defer page.deinit(gpa);

// ── anything not modelled above ──────────────────────────────────────────
var attrs: std.ArrayList(u8) = .empty;
defer attrs.deinit(gpa);
try ethtool.header.append(gpa, &attrs, 1, .{ .target = dev });
const replies = try et.raw(.{ .cmd = ethtool.uapi.MSG.TSINFO_GET, .attrs = attrs.items });
defer ethtool.Ethtool.freeRawReplies(gpa, replies);
```

Sub-namespaces, all `pub`: `uapi` (every constant and enum), `bitset`,
`header`, `link`, `params`, `features`, `stats`, `moduleinfo`, `client`, plus
`genl` and `codec` for driving `raw`. Every encoder and decoder is a pure
function over byte slices, so the wire format is testable without a socket.

### Request encoding is a public step

Every method above is a message plus a socket, and the message half is public
on its own. `ethtool.buildRings(gpa, family_id, seq, dev)` — and one `buildX`
per method, named after it — returns the **complete datagram**: the `nlmsghdr`
with its flags, the `genlmsghdr` with the command, and the attributes,
allocator-owned, ready to hand to a `sendto`. `family_id` and `seq` are
parameters because they are the socket's to know: the family id is whatever
nlctrl assigned this boot, and the sequence number is the client's counter.

```zig
const req = try ethtool.buildRings(gpa, et.family_id, et.sock.nextSeq(), dev);
defer gpa.free(req);
// …hand `req` to your own transport, or inspect it.
```

These are the same encoders the client uses: `Ethtool.rings` calls
`buildRings` and sends what it returns, so there is one encoder per operation
and no second copy to drift. The sibling `nl80211`
(`iface.buildGetInterface`) and `nftables` bindings expose their request
encoders the same way.

## Bitsets — read this before touching one

Half of this family's interesting attributes are *bitsets*, and the same
attribute arrives in two entirely different shapes depending on one flag in the
**request**:

| | compact | verbose |
|---|---|---|
| wire | `SIZE` + `VALUE`/`MASK` as `u32` arrays | a nest of `BIT { INDEX, NAME, VALUE }` |
| names | none — resolve via `stringSet` | carried inline |
| asked for by | `ETHTOOL_FLAG_COMPACT_BITSETS` in the header | the absence of that flag |

`Ethtool.linkModes` / `.features` take a `BitsetForm` parameter that sets it.

Two traps the accessors exist to keep you out of:

- **`isSet` is not "supported".** A masked bitset is a (value, mask) pair; a
  clear bit that is also outside the mask means *unsupported*, not *off*. That
  is `inMask` — and it is why `LinkModes` has both `advertises` (value) and
  `supports` (mask).
- **`NOMASK` changes what an entry means.** In a `NOMASK` ("list") verbose
  bitset the kernel emits *only the set bits* and attaches **no `VALUE` flag at
  all** — presence is the value. Reading `Bit.value` there reports every
  feature as off. `isSet` / `isSetByName` apply the rule; `Bit.value` is
  deliberately left as the raw wire flag.

## A SET's ACK is not proof

`FEATURES_SET` always ACKs, even when the stack silently refuses the change
(TSO requested while checksum offload is off, say). The truth is in the
`FEATURES_SET_REPLY`, whose two bitsets are *diffs* — and whose **mask** half
carries the meaning:

| reply attribute | mask means | value means |
|---|---|---|
| `WANTED` | this bit's result differs from what was requested | what was requested |
| `ACTIVE` | this bit's active state actually changed | its new state |

`setFeaturesByName` therefore returns a `SetResult`
(`fullyHonoured`, `unhonouredCount`, `changedCount`, `honouredAt`,
`newStateAt`, `honouredByName`) instead of `void`. Both a fully-honoured and a
four-of-five-refused reply are committed as real captured goldens.

## Waiting for notifications

The family publishes one multicast group, `monitor`, on which every `*_NTF`
message is emitted — including changes made by *other* processes, which is the
point: it is how an agent learns that someone ran `ethtool -K` behind its back.

`EventSocket` exposes **exactly one blocking call**, `waitForNotification`,
which does one `recvmsg` when its buffer is drained. There is no timer thread,
no deadline and no event loop in this module — a caller that needs a bounded
wait polls `events.fd()` itself:

```zig
var events = try ethtool.EventSocket.openWith(&et, &.{ethtool.mcast_group.monitor});
defer events.close();

var pfd = [_]std.os.linux.pollfd{.{ .fd = events.fd(), .events = 1, .revents = 0 }};
if (std.os.linux.poll(&pfd, 1, 5000) > 0) {
    var n = try events.waitForNotification(gpa);
    defer n.deinit(gpa);
    if (n.cmd == ethtool.uapi.REPLY.FEATURES_NTF) {
        var f = try ethtool.features.parse(gpa, n.attrs);  // same payload as a GET reply
        defer f.deinit(gpa);
    }
}
```

Same seam discipline as the sibling `nl80211`, `netconf` and `ebpf` modules:
threading policy belongs to the application.

## What is not here

This module speaks **ethtool netlink**, not the legacy ioctl. Two things a
user of the `ethtool` CLI expects are therefore absent, and no amount of
netlink will produce them:

- **`ethtool -i`** — driver name, firmware version, bus id. There is no
  `ETHTOOL_MSG_DRVINFO_GET`; the CLI still uses
  `SIOCETHTOOL`/`ETHTOOL_GDRVINFO` for it. (An `strace` of `ethtool -i` emits
  no netlink traffic at all — that is how it was confirmed.)
- **plain `ethtool -S`** — the driver's own free-form counter array, likewise
  ioctl-only. What `STATS_GET` returns is the newer *standardised* set
  (`eth-mac`, `eth-ctrl`, `rmon`, `eth-phy`), which is what
  `ethtool -S <dev> --groups …` asks for and what a monitoring consumer
  actually wants — the names are IEEE 802.3 / RFC 2819's rather than each
  driver's invention. Most drivers implement **none** of them and answer with
  groups that are present but empty; that is a normal reply, not an error.

## Design notes

- **The family id is resolved, never hardcoded** — it was 23 on the
  development machine and is whatever nlctrl assigns on the next boot. So is
  the `monitor` group id.
- **Absent means "n/a", not zero.** Every reply field is an optional and
  nothing is defaulted: `ethtool -g` prints `n/a` for exactly the attributes
  the kernel omits. Symmetrically, an absent field in a `*Set` struct means
  "leave it alone" — a SET carries only what changes.
- **Extended ACKs are on.** The socket sets `NETLINK_EXT_ACK`, so a refusal
  carries the kernel's own sentence ("failed to retrieve link settings" is what
  a Wi-Fi interface answers `LINKMODES_GET` with); `lastErrorMessage` returns
  it. `error.NotSupported` alone loses the interesting half.
- **`EOPNOTSUPP` is normal.** Most drivers implement a minority of this family.
  Every live test treats it as "skip", not "fail".
- **Malformed kernel replies → typed errors** (`error.Truncated` /
  `error.BadLength` from the fuzz-tested netlink codec), never a panic. Bitset
  sizes, string-set counts and EEPROM lengths are all bounded before anything
  is allocated.

## Verify

```sh
zig build test-ethtool                  # Debug
zig build test-ethtool --release=fast
```

Offline golden-byte, decoder, hostile-input and fuzz tests are the gate. The
live tests run real unprivileged gets against a network interface on the
machine and print `SKIPPED: …` and pass when a driver does not implement an
operation — a run on a machine with no Ethernet-type interface never fails.
The two privileged tests need CAP_NET_ADMIN and skip without it; to run them
(and the whole suite against a controlled device):

```sh
unshare -rn
ip link add veth0 type veth peer name veth1 && ip link set veth0 up
zig build test-ethtool
```

Capture commands, both capture environments, anonymisation and the full
deferred list are documented in `SPEC.md` and at the top of `src/goldens.zig`.
