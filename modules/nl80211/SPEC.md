# nl80211 — design, verification and threat model

Purpose and API: see [README.md](README.md). This document covers how the
module was built and verified, what it deliberately does not do, and what could
go wrong.

## 1. Verification story

### 1.1 Request goldens — captured from a real `iw`, byte for byte

Every request encoder is asserted against bytes a real `iw` 6.17 handed the
kernel on Linux 7.0, captured with:

```sh
strace -f -e trace=sendmsg -e write=all -xx -s 8192 -e abbrev=none <iw command>
```

`-e write=all` dumps the exact `sendmsg` payload with no re-encoding step in
between, so the golden *is* the wire. The command line sits in a comment next
to each golden in `src/goldens.zig`.

| golden | captured from |
|---|---|
| `CTRL_CMD_GETFAMILY("nl80211")` | every `iw` invocation's first message |
| `GET_WIPHY` + `SPLIT_WIPHY_DUMP` | `iw list` |
| `GET_INTERFACE` (dump) | `iw dev` |
| `GET_INTERFACE` (single, `IFINDEX`) | `iw dev <dev> info` |
| `GET_STATION` (dump) | `iw dev <dev> station dump` |
| `GET_STATION` (single, `IFINDEX` + `MAC`) | `iw dev <dev> link` |
| `GET_SCAN` (dump) | `iw dev <dev> scan dump` |
| `TRIGGER_SCAN` (wildcard SSID + `SCAN_FLAGS`) | `iw dev <dev> scan trigger` |
| `TRIGGER_SCAN` + frequency list | `iw dev <dev> scan trigger freq 2412 2437` |
| `TRIGGER_SCAN` + `FLUSH`/`LOW_PRIORITY` | `iw dev <dev> scan trigger flush lowpri` |
| `TRIGGER_SCAN` + named SSID | `iw dev <dev> scan trigger ssid TestNet` |
| `CONNECT` (open) | `iw dev <dev> connect TestNet` |
| `CONNECT` + `WIPHY_FREQ` | `iw dev <dev> connect TestNet 2412` |
| `CONNECT` + nested `ATTR_KEYS` (WEP) | `iw dev <dev> connect TestNet 2412 key 0:abcde` |
| `DISCONNECT` | `iw dev <dev> disconnect` |
| `GET_REG` (dump) | `iw reg get` |
| `REQ_SET_REG` | `iw reg set US` |

Two fields of a captured request are runtime values rather than encoding and
are excluded from the comparison: `nlmsg_pid` (the kernel-assigned port id;
this module always writes 0 and lets the kernel fill it in) and `nlmsg_seq`
(each test simply builds with the sequence number the capture used). Everything
else — length, message type, flags, `genlmsghdr`, and every attribute's type,
length, order and padding — is compared byte for byte.

Things the goldens caught or pinned that would otherwise have been guesses:

- **`SCAN_SSIDS` / `SCAN_FREQUENCIES` nest entries are indexed from 1**, not 0.
- **Neither of those nests carries `NLA_F_NESTED`** on the wire, while the
  `ATTR_KEYS` container *and* each key inside it **do**. Only a capture
  distinguishes these.
- **An SSID attribute is not NUL-terminated** (`nla_len` 11 for "TestNet": 4 +
  7, with one alignment pad byte), while **`REG_ALPHA2` is** (`nla_len` 7 for
  "US": 4 + 3). Getting the first one wrong sends an 8-byte SSID that matches
  nothing.
- `iw` **omits `SCAN_FLAGS` entirely** once a frequency list restricts the
  scan, and defaults to `COLOCATED_6GHZ` otherwise.
- `NL80211_KEY_IDX` is a `u8` (`nla_len` 5, padded to 8), not a `u32`.

### 1.2 What could **not** be captured from `iw`

`iw connect` supports only open and **WEP** networks — it has no WPA mode,
because on ordinary mac80211 hardware WPA needs a userspace supplicant. So
these `CONNECT` attributes have **no `iw` golden**:

`NL80211_ATTR_WPA_VERSIONS`, `CIPHER_SUITES_PAIRWISE`, `CIPHER_SUITE_GROUP`,
`AKM_SUITES`, `PMK`, `USE_MFP`, `WANT_1X_4WAY_HS`, `SOCKET_OWNER`,
`PREV_BSSID`.

**ANCHORED for five of the nine, 2026-08-08 (wave-2 F7).** `wpa_supplicant`
2.11 was made to associate WPA2-PSK, for real, to a real `hostapd` AP over the
kernel's own `mac80211_hwsim` radios inside the repo's privileged VM lane
(`scripts/vm/run.sh`'s guest — no host radio, no host privilege), and its
`NL80211_CMD_CONNECT` was captured with the same `strace` recipe as every
other golden here. The 320 bytes are frozen in `src/goldens.zig`
(`wpa2_connect_capture`) and compared attribute-by-attribute against what
`buildConnect` emits for the same association. That anchors **`WPA_VERSIONS`,
`CIPHER_SUITES_PAIRWISE`, `CIPHER_SUITE_GROUP`, `AKM_SUITES` and
`SOCKET_OWNER`** — number, length, payload width and value — and with them the
suite selectors `CIPHER.CCMP` (00-0F-AC:4) and `AKM.PSK` (00-0F-AC:2), neither
of which any header on the capture host declares. The encoders agreed with the
supplicant on the first comparison; nothing was adjusted to fit.

Two differences were found and are pinned rather than removed: this module's
message-wide attribute order follows `iw`'s, not the supplicant's (netlink does
not care, and the *relative* order of the four security attributes is the same
in both), and the supplicant emits `SOCKET_OWNER` twice where this module emits
it once.

**Still unanchored:** `PMK`, `USE_MFP`, `WANT_1X_4WAY_HS` and `PREV_BSSID`. A
PSK association through cfg80211's own SME sends none of them — the capture is
asserted to contain none — so they stay round-trip-only. Reaching them needs
4-way-handshake offload (`PMK`), an MFP-required BSS, an 802.1X network and a
roam respectively; `mac80211_hwsim` offers no handshake offload, so the first is
out of reach of this lane entirely. Their attribute *numbers* are
standing-checked by `scripts/check-uapi-consts.py nl80211` on every run.

Everything else — every decoder, and every other request encoder — is backed by
real bytes.

### 1.3 Decoder goldens — real kernel replies

Captured with the read side of the same harness:

```sh
strace -f -e trace=recvmsg -e read=all -xx -s 16384 -e abbrev=none <iw command>
```

with the duplicate `MSG_PEEK` read dropped. Committed replies:

| golden | size | what it proves |
|---|---|---|
| nlctrl `GETFAMILY` reply | 2556 B | family id + all six multicast groups resolve |
| `GET_INTERFACE` dump | 328 B | two interfaces: a P2P device (wdev, no ifindex, no name) and an associated station |
| `GET_STATION` dump | 2500 B | u64 counters beating their u32 twins, `s8` signal, doubly-nested VHT `RATE_INFO`, a 2100-byte `TID_STATS` nest skipped cleanly |
| `GET_SCAN` reply | 1044 B | a full BSS + **484 bytes of real information elements off the air** |
| `GET_REG` dump | 2296 B | the world domain (9 rules) followed by a per-wiphy country domain (28 rules), kHz units |
| `GET_WIPHY` split dump | 13204 B | **one radio spread over 75 messages**, reassembled into 2 bands / 51 channels |

The `GET_STATION` golden is the one that justifies the 64-bit-counter rule: its
`RX_BYTES` (u32) had already wrapped four times when `RX_BYTES64` said
33 915 461 682.

### 1.4 Anonymisation

The captures came from a machine with a real Wi-Fi link. Before being
committed, every reply had these **length-preserving** substitutions applied
(so all lengths, offsets and padding are unchanged and the decode assertions
stay meaningful):

| captured | replaced with |
|---|---|
| the AP's BSSID | `02:00:00:aa:bb:cc` |
| the radio's four local MACs | `02:00:00:11:22:33` … `:36` |
| the 18-byte SSID | `ZIGLIBS-TEST-AP-01` |
| the regulatory alpha2, in both the `GET_REG` reply and the beacon's Country IE | `DE` |

Every replacement MAC is locally administered (bit 1 of the first octet set),
so it cannot collide with a real vendor address. The substitution list was
re-run against the committed bytes to confirm no original identifier survives
anywhere, including across the 64-character line wrapping.

### 1.5 Hostile-input tests

- **Truncation sweep over real data:** every one of the 485 prefixes of the
  captured 484-byte IE stream is walked; each must decode or return a typed
  error, and the walk's step count is asserted against the ≥ 2-byte advance
  bound.
- **Single-byte corruption sweep** over the same stream.
- **Lying length fields:** an element claiming 200 body bytes with 2 present; a
  dangling header byte; an RSN element declaring 0xffff pairwise suites or
  0xffff PMKIDs; a suite list longer than the fixed capacity (clipped, with
  `declared` reporting the claim).
- **Malformed netlink** at every level: truncated TLVs, wrong-width `IFINDEX` /
  `WDEV` / `MAC` / `RX_BYTES64`, an SSID over the 802.11 ceiling, repeated
  `INFORMATION_ELEMENTS` / `REG_RULES` attributes (which would otherwise leak
  the first copy — each is `error.BadLength` instead).
- **Fuzz (`std.testing.fuzz`)** on the IE walk + `summarize` + `parseRsn`, the
  interface parser, the station parser, the BSS parser, the wiphy parser and
  the event parser. The allocating ones run under the testing allocator, so a
  leak on an error path fails the run.

### 1.6 Live tests

With a Wi-Fi device present these run for real and unprivileged: `GET_WIPHY`
(split), `GET_INTERFACE` (dump + single), `GET_STATION`, `GET_SCAN`, `GET_REG`,
`scan`/`mlme` multicast group resolution + join, and the `raw` escape hatch
against `GET_PROTOCOL_FEATURES`. Nothing there mutates system state.

`triggerScan` + `waitForEvent` + `scanResults` needs CAP_NET_ADMIN and skips
without it.

Every live test prints `SKIPPED: …` and passes when there is no radio, no
cfg80211, or no privilege, so a run on a machine without Wi-Fi never fails.

## 2. Design invariants

### 2.1 Nothing is hardcoded that the kernel assigns

The nl80211 family id and every multicast group id are dynamic. The family id
was 41 on the development machine; the goldens pass 41 in explicitly and the
live test asserts only that the resolved value is above nlctrl's fixed `0x10`.

`genetlink`'s README lists `CTRL_ATTR_MCAST_GROUPS` as an explicit extension
point it does not cover, and it is read-only for this work, so the group walk
lives here as a pure function (`client.findMcastGroupId`) plus a thin socket
wrapper. If a second genetlink family ever needs groups, that is the code to
promote upward.

### 2.2 The split-dump merge

`wiphy.Parser` keys accumulating state by wiphy index and merges:

- scalars are last-writer-wins (the kernel repeats identical values);
- bands are keyed by their nested attribute index;
- frequencies are keyed by their index *inside* the band, so a channel seen
  twice is updated rather than duplicated;
- whole-list attributes (ciphers, iftypes, supported commands) replace.

A message with no `NL80211_ATTR_WIPHY` is **dropped**, never merged into
whichever radio happens to be last — misattributing capabilities across radios
is worse than losing a fragment.

### 2.3 The blocking seam

`EventSocket.waitForEvent` is the only blocking call in the event path and does
exactly one `recvmsg`, and only when its buffer is drained. No timer thread, no
deadline, no event loop: a bounded wait is the caller's `poll()` on
`EventSocket.fd()`. This is the same discipline as `netconf`'s
`Client.pumpOnce` and `ebpf`'s ring-buffer consumer.

The event socket is separate from the command socket because multicast
membership is per-socket: sharing one would force every dump loop to filter
unsolicited events out of its own replies.

Ordering hazard, documented at both ends: **subscribe before triggering**, or
the completion event can fire in the gap and be lost.

### 2.4 Lifetimes

`Dump.next` hands back attribute bytes that borrow the socket's receive buffer
and are valid only until the next call (the buffer is reallocated on demand).
Every internal caller either copies into a fixed-size field (`Interface`,
`Station`), duplicates (`Bss.ies`, `raw`), or feeds a parser that copies
(`wiphy.Parser`).

`Bss` owns its IE streams for exactly this reason: a scan result must outlive
the datagram it arrived in.

## 3. Threat model

The one untrusted input is **information elements**: verbatim bytes off the
air, written by any transmitter in range, reachable by anyone within radio
range of the machine without authentication or association. A `GET_SCAN` dump
after a scan of a hostile environment is the realistic attack.

Mitigations, in `src/ie.zig`:

- every element header and body is bounds-checked before it is read;
- iteration advances ≥ 2 bytes per step, so a walk over N bytes is capped at
  N/2 steps by construction — no attacker-chosen loop count;
- no allocation anywhere in the IE path; suite lists are fixed-capacity, with
  the wire's declared count reported separately so clipping is visible;
- a length that overruns is `error.Truncated`; a *count* that does not fit is
  `error.Malformed` (a lie about the element's own structure, as opposed to a
  legitimately short element — the RSN element is specified so a transmitter
  may stop after any field);
- `summarize` never fails: it stops at the first malformed element and returns
  what it decoded, so one bad IE cannot make a whole BSS undecodable. Because
  that stop is attacker-triggerable, the doubt is carried in the result:
  `Summary.truncated` is set, and `Summary.security` reports
  `Security.unknown` instead of falling through to the Privacy bit — otherwise
  a transmitter in range could force `.open` for any BSS by putting one
  malformed element in front of its RSN element.

**SSIDs are raw bytes.** 0–32 bytes, any content, frequently invalid UTF-8, and
an attacker can pick them. A consumer that renders one must escape it; this
module never treats one as a string and never NUL-terminates it.

Everything else on this wire comes from the local kernel, so the netlink
decoders defend against bugs and version skew rather than an adversary — but
they use the same fuzz-tested bounds-checked codec, return typed errors and
never panic.

**Writes need CAP_NET_ADMIN**, so a process that can `triggerScan` or `connect`
can already do far worse to the network stack; this module adds no privilege.
`requestRegDomain` is only a hint — the kernel intersects it with the driver's
constraints, so it cannot be used to escape a regulatory limit.

## 4. Deferred

Explicitly not implemented, in rough order of likely usefulness. Each is
reachable today through `Nl80211.raw` with caller-encoded attributes.

| area | commands |
|---|---|
| Survey / channel occupancy | `GET_SURVEY` |
| Scheduled scan (low-power background) | `START_SCHED_SCAN`, `STOP_SCHED_SCAN`, `SCHED_SCAN_RESULTS` |
| Interface lifecycle | `NEW_INTERFACE`, `DEL_INTERFACE`, `SET_INTERFACE` |
| Radio configuration | `SET_WIPHY` (channel, tx power, RTS/frag thresholds, antenna) |
| Key management | `NEW_KEY`, `DEL_KEY`, `SET_KEY`, `GET_KEY` |
| Raw MLME | `AUTHENTICATE`, `ASSOCIATE`, `DEAUTHENTICATE`, `DISASSOCIATE` |
| PMKSA caching | `SET_PMKSA`, `DEL_PMKSA`, `FLUSH_PMKSA` |
| AP mode | `START_AP`, `STOP_AP`, `SET_BSS`, `NEW_STATION`, `DEL_STATION` |
| Mesh | `GET_MESH_CONFIG`, `SET_MESH_CONFIG`, `JOIN_MESH`, `LEAVE_MESH`, mpath |
| IBSS | `JOIN_IBSS`, `LEAVE_IBSS` |
| P2P | `START_P2P_DEVICE`, `STOP_P2P_DEVICE`, remain-on-channel, frame TX/RX |
| Monitor mode | `NL80211_ATTR_MNTR_FLAGS` configuration |
| TDLS | `TDLS_MGMT`, `TDLS_OPER` |
| Power / offload | `SET_POWER_SAVE`, WoWLAN triggers, coalesce rules, rekey offload |
| CQM | connection-quality-monitor thresholds and events |
| Vendor | `VENDOR` commands and events |
| MLO (802.11be) | multi-link `BSS_MLD_ADDR` / `MLO_LINK_ID` handling beyond decoding the attributes |
| Capability decoding | HT/VHT/HE/EHT capability bitfields, interface combinations, `EXT_FEATURE` bits, `TID_STATS`, `BSS_PARAM`, `CHAIN_SIGNAL` |
| Events beyond scan | the `mlme` and `regulatory` groups decode into `Event`, but only the scan-terminal predicates are modelled |

**Permanently out of scope:** a supplicant. `NL80211_CMD_CONNECT` only works
end-to-end on drivers with an internal SME; on mac80211 hardware WPA needs
EAPOL exchange, PTK/GTK derivation and installation, PMKSA caching and SAE —
a large, security-critical state machine. Shipping half of one would be worse
than shipping none. See `src/connect.zig`'s header for which of the three
association paths this module implements.

## 5. Provenance

Clean-room from the kernel UAPI (`linux/nl80211.h`, `linux/genetlink.h`,
`linux/netlink.h` — GPL-2.0 WITH Linux-syscall-note; the constants and layouts
are the kernel's OS ABI, not copyrightable interface code) and the IEEE 802.11
information-element formats.

`iw` was run as a **black-box test oracle under `strace`** and its output bytes
diffed against this module's — the same relationship the `tc` module has with
`iproute2` and the `nftables` module has with `nft`. No `iw` or
`wpa_supplicant` source was read, studied for design, or ported, so per
`CONVENTIONS.md` §5 this needs no `/NOTICE` design-reference entry. See
`NOTICE` for the module's own attribution line.

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** goldens captured from real iw under strace; live kernel tests skip cleanly (bonus)

**How it got there.** The anchoring work landed. CLOSED 2026-08-08 (wave-2 F7). The counterpart the finding asked for was obtained by going where the privilege legitimately exists instead of asking the host for root: scripts/vm's Debian guest, whose STOCK cloud kernel does carry mac80211_hwsim (verified before anything was built -- `modprobe mac80211_hwsim radios=2` -> phy0/phy1, wlan0/wlan1). hostapd ran a WPA2-PSK AP on wlan0 and wpa_supplicant associated on wlan1 with `driver_param=force_connect_cmd=1`, which is the load-bearing detail: without it a mac80211 driver makes wpa_supplicant run its OWN SME and emit AUTHENTICATE+ASSOCIATE, never CONNECT, so the capture would not exist. The association completed for real (wpa_state=COMPLETED, key_mgmt=WPA2-PSK, PTK=CCMP GTK=CCMP). Exactly one NL80211_CMD_CONNECT appeared in the 147-message strace capture; its 320 bytes are frozen in goldens.zig as `wpa2_connect_capture` and compared attribute-by-attribute against what buildConnect emits for the same association. IFINDEX, MAC, SSID, WIPHY_FREQ, AUTH_TYPE, PRIVACY, WPA_VERSIONS, CIPHER_SUITES_PAIRWISE, CIPHER_SUITE_GROUP, AKM_SUITES and SOCKET_OWNER agree byte for byte -- number, length, payload width and value -- on the first comparison, with nothing adjusted to fit. That also anchors CIPHER.CCMP (00-0F-AC:4) and AKM.PSK (00-0F-AC:2) on a real wire, two suite selectors no header on the capture host declares (narrows F3). Mutation-tested: ATTR.WPA_VERSIONS 75 -> 175 gives exit 1, 1/108 fail, and ONLY the new test failed -- the other 106, connect.zig's own round-trips included, never noticed, which is exactly the consistent-mutation blindness F3 recorded as a negative control. Two genuine disagreements with the counterpart were found and PINNED rather than normalised away: the supplicant's message-wide attribute order differs from this module's (ours follows iw's; netlink does not care, and the four security attributes appear in the same relative order in both), and the supplicant emits SOCKET_OWNER twice where this module emits it once. STILL SELF-ONLY, and asserted absent from the capture rather than merely described: PMK, USE_MFP, WANT_1X_4WAY_HS, PREV_BSSID -- a PSK association driven through cfg80211's own SME sends none of them, and mac80211_hwsim offers no 4-way-handshake offload, so PMK is out of reach of this lane entirely; their attribute numbers stay standing-checked by scripts/check-uapi-consts.py. BONUS DEFECT, found by running the live suite as real root in that guest (scripts/vm/run.sh nl80211 debian, via run.sh's new guest_setup hook): TRIGGER_SCAN on an administratively-down interface answers ENETDOWN (-100, measured with a temporary probe, not assumed) and client.errnoToError had no case for it, so the single commonest failure of a scan surfaced as error.Unexpected. Nothing unprivileged could ever have seen it -- the only test that reaches that line had always stopped at the AccessDenied skip. Now error.NetworkDown, and with the radios brought up in guest_setup the whole suite runs 108/108 with ZERO skips in the VM.
