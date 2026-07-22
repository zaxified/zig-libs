# nl80211

Native **Wi-Fi control** over the kernel's `nl80211` generic-netlink family:
radio and interface enumeration, scanning with information-element decoding,
station/link statistics, connect/disconnect and the regulatory domain — no `iw`
shell-outs, no `wpa_supplicant` linkage, no libc.

- No maintained pure-Zig nl80211 client exists.
- **Model after:** the kernel UAPI (`linux/nl80211.h`) and the IEEE 802.11
  information-element formats. `iw` was used **only as a black-box capture
  oracle** under `strace` — its requests are the byte-exact goldens this module
  is asserted against — no `iw` or `wpa_supplicant` source was read or ported.
- **Platform:** linux (raw `std.os.linux` AF_NETLINK syscalls — a conscious
  ceiling). **Role:** client. **Concurrency:** reentrant (no globals; one
  `Nl80211` / `EventSocket` per thread/loop).
- **Deps:** `genetlink` — the generic-netlink layer (`genlmsghdr`, nlctrl
  family resolve, `NETLINK_GENERIC` socket), re-exported here as
  `nl80211.genl`; `netlink` — its bounds-checked wire codec (nlmsghdr + nlattr
  TLV build/parse), re-exported as `nl80211.codec`.
- **Privileges:** the dumps (`wiphys`, `interfaces`, `stations`,
  `scanResults`, `regDomains`), family resolution and multicast subscription
  need **none**. `triggerScan`, `connect`, `disconnect` and `requestRegDomain`
  need **CAP_NET_ADMIN**.

Provenance: original work of the zig-libs authors (MIT); clean-room from the
kernel UAPI (`linux/nl80211.h`, GPL-2.0 WITH Linux-syscall-note — the
command/attribute constants and their layouts are the kernel's OS ABI, not
copyrightable interface code) and the IEEE 802.11 element formats. See
`NOTICE`.

## Scope

nl80211 has 100+ commands and 350+ attributes. This is a **v1 with a stated
ceiling**:

| | |
|---|---|
| **Implemented** | `GET_WIPHY` (split dump, merged), `GET_INTERFACE`, `TRIGGER_SCAN` + `GET_SCAN` + the `scan` multicast event, `GET_STATION`, `CONNECT`/`DISCONNECT`, `GET_REG`/`REQ_SET_REG` |
| **Escape hatch** | `Nl80211.raw` — any command, caller-encoded attributes, replies handed back as attribute bytes |
| **Deferred** | AP mode, mesh, IBSS, P2P, monitor config, survey, TDLS, WoWLAN, scheduled scan, key management, vendor commands, MLO — see `SPEC.md` |
| **Out of scope, permanently** | the supplicant (4-way handshake, EAP, SAE) — see "Connecting" below |

## API

```zig
const nl80211 = @import("nl80211");

var wifi = try nl80211.Nl80211.open(gpa);   // resolves the family id — never hardcode it
defer wifi.close();

// ── enumeration ──────────────────────────────────────────────────────────
const radios = try wifi.wiphys();
defer nl80211.wiphy.freeAll(gpa, radios);
for (radios) |r| _ = .{
    r.name(), r.channelCount(), r.max_num_scan_ssids,
    r.supportsIftype(.station), r.supportsCipher(nl80211.CIPHER.CCMP),
};

const ifaces = try wifi.interfaces();
defer gpa.free(ifaces);
const wlan = ifaces[0].ifindex.?;

// ── scan ─────────────────────────────────────────────────────────────────
// Subscribe BEFORE triggering: the completion event can fire in the gap.
var events = try nl80211.EventSocket.openWith(&wifi, &.{nl80211.mcast_group.scan});
defer events.close();

try wifi.triggerScan(.{                     // needs CAP_NET_ADMIN
    .ifindex = wlan,
    .ssids = nl80211.wildcard_ssids,        // active scan; &.{} = passive
    .freqs_mhz = &.{ 2412, 2437, 2462 },    // optional channel restriction
    .flags = nl80211.SCAN_FLAG.FLUSH,
    .max_num_ssids = radios[0].max_num_scan_ssids, // reject locally, not with EINVAL
});
while (!(try events.waitForEvent()).endsScan()) {}  // the ONE blocking call

const bsses = try wifi.scanResults(wlan);
defer nl80211.scan.freeAll(gpa, bsses);
for (bsses) |b| {
    const e = b.elements();                 // SSID, rates, DS channel, RSN, …
    _ = .{ b.bssid.?, b.signalDbm(), b.freq_mhz, e.ssid, e.security(b.capability) };
}

// ── link statistics ──────────────────────────────────────────────────────
const peers = try wifi.stations(wlan);
defer gpa.free(peers);
for (peers) |s| _ = .{
    s.mac.?,           s.signal_dbm, s.rx_bytes, s.tx_bytes, s.tx_failed,
    s.connected_time_s, (s.rx_bitrate orelse continue).kilobitsPerSecond(),
};

// ── regulatory ───────────────────────────────────────────────────────────
const doms = try wifi.regDomains();
defer nl80211.reg.freeAll(gpa, doms);
for (doms) |d| _ = .{ d.alpha2, d.dfs_region, d.ruleFor(5500) };
try wifi.requestRegDomain("DE");            // a hint; needs CAP_NET_ADMIN

// ── anything not modelled above ──────────────────────────────────────────
const replies = try wifi.raw(.{ .cmd = nl80211.uapi.CMD.GET_PROTOCOL_FEATURES });
defer nl80211.Nl80211.freeRawReplies(gpa, replies);
```

Sub-namespaces, all `pub`: `uapi` (every constant and enum), `ie`
(information-element parsing), `wiphy`, `iface`, `station`, `scan`, `connect`,
`reg`, `client`, plus `genl` and `codec` for driving `raw`. Every request
builder is a pure `(allocator, family_id, seq, params) → []u8` function, so the
wire format is testable without a socket.

## Waiting for events

`EventSocket` exposes **exactly one blocking call**, `waitForEvent`, which does
one `recvmsg` when its buffer is drained. There is no timer thread, no deadline
and no event loop in this module — a caller that needs a bounded wait polls
`events.fd()` itself and only calls `waitForEvent` once the fd is readable:

```zig
var pfd = [_]std.os.linux.pollfd{.{ .fd = events.fd(), .events = 1, .revents = 0 }};
if (std.os.linux.poll(&pfd, 1, 5000) > 0) {
    const ev = try events.waitForEvent();
    if (ev.isScanComplete()) { /* … */ }
}
```

Same seam discipline as the sibling `netconf` (`Client.pumpOnce`) and `ebpf`
(ring-buffer consumer) modules: threading policy belongs to the application.

## Connecting — read this before using `connect`

`NL80211_CMD_CONNECT` hands authentication, association **and the 4-way
handshake** to the driver's own SME. That works on hardware whose firmware has
one; most `mac80211`-based chips do **not**, and there the connect is refused
or stalls. Full supplicant behaviour (EAPOL, PMK/PTK/GTK derivation, PMKSA
caching, SAE, 802.1X/EAP) is **out of scope and will not be added** — half a
supplicant is worse than none.

So:

- **Open networks and the driver-SME path:** `connect` works.
- **WPA2/WPA3 on ordinary hardware:** run `wpa_supplicant`, and use this module
  for enumeration, scanning and statistics.

This module never derives a PMK from a passphrase — pass a 32-byte PMK
(`std.crypto.pwhash.pbkdf2` over the SSID), so no passphrase enters it.

```zig
try wifi.connect(.open(wlan, "GuestNet"));
try wifi.connect(.wpa2Psk(wlan, "SecureNet", &pmk));  // driver-SME path only
try wifi.disconnect(wlan, nl80211.connect.reason_deauth_leaving);
```

## Design notes

- **Both wire directions are pure functions** over byte slices, so the exact
  netlink + genlmsghdr + nested-attribute layout is golden-byte-tested offline;
  the socket only ferries buffers.
- **The family id is resolved, never hardcoded** — it was 41 on the development
  machine and is whatever nlctrl assigns on the next boot. So are the multicast
  group ids; `genetlink` deliberately stops before them, so the
  `CTRL_ATTR_MCAST_GROUPS` walk lives here (`client.findMcastGroupId`).
- **`GET_WIPHY` needs a merging parser.** With `SPLIT_WIPHY_DUMP` the kernel
  spreads one radio over many messages — 75 of them for a single radio in the
  committed golden, with the channel list dribbled out one channel per message.
  `wiphy.Parser` keys by wiphy index and merges; a non-split dump is just the
  degenerate case.
- **Information elements are the hostile-input surface.** Everything else on
  this wire comes from the local kernel; IEs are verbatim bytes off the air.
  `ie.zig` bounds-checks every step, always advances ≥ 2 bytes (so a walk over
  N bytes terminates in ≤ N/2 steps), never allocates, and `summarize` stops at
  the first malformed element instead of losing the whole BSS.
- **SSIDs are raw bytes, not strings** — any 0–32 bytes, possibly invalid
  UTF-8, possibly all zeroes (a hidden network). Never print one unescaped.
  Note the wire asymmetry the goldens pin: an SSID attribute is *not*
  NUL-terminated, while `REG_ALPHA2` *is*.
- **64-bit counters win over their 32-bit twins** regardless of arrival order,
  so a wrapped `RX_BYTES` never masks a good `RX_BYTES64`; likewise
  `RATE_INFO_BITRATE32` over the saturating u16.
- **`Wiphy.supportsCommand` means "advertised", not "possible"** —
  `NL80211_ATTR_SUPPORTED_COMMANDS` is a partial list and omits `TRIGGER_SCAN`
  even on radios that scan; infer scan capability from `max_num_scan_ssids`.
- **Malformed kernel replies → typed errors** (`error.Truncated` /
  `error.BadLength` from the fuzz-tested netlink codec), never a panic;
  `NLMSG_ERROR` errnos map onto `error.AccessDenied`, `error.NoSuchDevice`,
  `error.Busy`, `error.NotConnected`, ….

## Verify

```sh
zig build test-nl80211                  # Debug
zig build test-nl80211 --release=fast
```

Offline golden-byte, decoder and fuzz tests are the gate. The live tests run
real unprivileged dumps (`GET_WIPHY`, `GET_INTERFACE`, `GET_STATION`,
`GET_SCAN`, `GET_REG`, multicast subscribe, the `raw` escape hatch) when the
machine has a Wi-Fi device, and print `SKIPPED: …` and pass when it does not —
a run on a machine with no Wi-Fi never fails. The scan-trigger test
additionally needs CAP_NET_ADMIN and skips without it. Capture commands,
anonymisation and what could not be captured are documented in `SPEC.md` and at
the top of `src/goldens.zig`.
