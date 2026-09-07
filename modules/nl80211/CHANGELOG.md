# nl80211 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **all seven fuzz harnesses fetched their input and threw it away — and the
  collapse made them look perfect.** Each opened `smith.bytes(&raw)` and then sliced the buffer
  to `smith.valueRangeAtMost(u16, 0, raw.len)`; a `Smith` ranged draw reads eight input octets
  as a little-endian u64 and returns the range MINIMUM unless that word already lies inside the
  range, so the length was 0 for every seed and every parser here ran on an empty attribute
  list. ⛔ And an empty list is a **legal** reply everywhere in this module — every field of an
  interface, a station, a regulatory domain, a BSS or an event is optional — so measured with
  the old draws in place against the new corpora: `iface` 6 of 6 "parsed", `station` 7 of 7,
  `reg` 6 of 6, `scan` 6 of 6 nests, `client` 7 of 7 events, `wiphy` 7 of 7 messages fed
  cleanly, `ie` no failures at all. A clean sheet across the module, with **0 elements walked,
  0 regulatory rules decoded, 0 wiphys produced, 0 bitrates reached and 0 group ids found.**
  All seven now draw with one `smith.slice(&raw)` and carry a corpus. After: `iface` 3 parsed
  of which 3 carry an iftype; `station` 3 parsed and 3 bitrates through
  `RateInfo.kilobitsPerSecond`; `reg` 3 parsed and 1 rule; `scan` 3 nests and 1 BSS through the
  ATTR.BSS wrapper; `wiphy` 5 messages fed and 4 radios produced; `client` 4 events parsed, 2
  ending a scan and 1 mcast group id; `ie` 40 elements walked and 3 RSN/WPA1 elements decoded.
  Each harness carries a corpus guard pinning both numbers — "parsed" alone cannot tell a real
  reply from the empty one, which is exactly how this hid.
- **2026-09-07** — two knob draws with the same defect, both of which decided a security-
  relevant answer. `client.fuzzEvent` drew the genl command with
  `valueRangeAtMost(u8, 0, 255)`, so `cmd` was **0 on every round** and `Event.endsScan()`,
  `isScanComplete()` and `isScanAborted()` were false for every input the harness ever built.
  `ie.fuzzIes` passed `smith.value(u16)` as the frequency to `Summary.security(freq)` — a
  16-bit draw, likewise always its minimum — so the band that decides WEP-vs-open on an
  unprotected BSS was **0 MHz**, which is not a channel. Both are full-width `smith.value(u64)`
  draws now and both travel in the seed.
- **2026-09-07** — the nl80211 corpora are built at run time by `codec`'s own encoders rather
  than quoted as hex, because an nl80211 attribute is a netlink TLV and its length and scalars
  are HOST byte order. `ie.zig` is the exception and quotes its beacons verbatim: an 802.11
  information element is `id | len | body` octets, the same on every host.

- **2026-09-03** — Drift re-audit (last audited `d163578`, ~723 lines since). Four fixes,
  four mutations, four red.
  - ⛔ **The dump loop ignored `NLM_F_DUMP_INTR`.** The kernel sets it when its tables
    changed while it was walking them, so the reply may have skipped or duplicated objects.
    The shared triage `netlink.codec.classifyDumpMessage` returns `.restart` for exactly
    this, `netlink.Socket` retries such a dump up to `max_dump_attempts`, and `genetlink`
    drops a flagged reply — while `dumpStep`, factored out in this very window with a doc
    comment naming the sibling `conntrack`'s `dumpOver` as "the same technique", inspected
    only `m.type`. `scanResults` during ongoing scanning, `interfaces`/`stations` while an
    interface comes or goes, and the *split* `wiphys` dump (one radio spread over ~75
    messages, reassembled by `wiphy.Parser`) are precisely the dumps a busy host interrupts,
    and a partial radio was returned as a complete one with no error and no flag. Now
    `error.DumpInterrupted` — **source-breaking** for an exhaustive `switch` over
    `RequestError`. Surfaced rather than retried, deliberately: a retry needs the request
    re-sent with a fresh sequence number and this iterator does not own the send.
  - ⛔ **`max_dump_messages` bounded datagrams, not the memory the collectors retain.** The
    budget is real and fires exactly on schedule — after 65,536 datagrams. Measured against
    the real `dumpStep` with one ordinary 18,752-byte datagram (8 BSSes × 2304 bytes of IEs,
    nothing hostile): **1,285,750,080 bytes — 1226 MiB — of peak live allocation** and
    524,288 retained BSSes had accumulated by then, and since netlink's receive buffer grows
    to 16 MiB the derived memory bound was ~1 TiB. Honest scope: only the kernel can send
    here (`recvDatagramStrict` drops any non-zero source pid), so this is the malfunctioning
    driver the comment names — and on a small box the OOM arrives long before the datagram
    count does. Added `max_dump_bytes` (64 MiB), which bounds what actually grows.
  - ⛔ **The SSID cap was silent, and let a LATER element supply the name instead.** The
    in-window fix refused an over-length SSID element and kept walking, leaving `ssid.len ==
    0` — byte-identical in the answer to a beacon carrying no SSID element at all — after
    which the `ssid.len == 0` guard accepted the *next* SSID element. Measured against
    Wireshark's own 802.11 dissector on a beacon carrying SSID(33 × 'A') then SSID(8,
    "homewifi"): `sharkd` names the FIRST element the SSID and raises a Malformed expert
    error, leaving the second undecoded as a duplicate. This module named the BSS
    "homewifi" — disagreeing with every capture tool and with its own `find(ies, EID.SSID)`,
    which returns the first. A transmitter in range chose which name was reported. Now the
    first element decides whatever its length, and `Summary.ssid_oversized` carries the
    doubt, which is the principle this file's own header states.
  - `ie.find` is documented as returning an **unbounded** body — up to 255 bytes, chosen by
    the transmitter — because `nl80211.max_ssid_len` is re-exported precisely so callers can
    size a buffer on it, and the in-window fix put the cap on only one of the two public
    routes to the SSID while its own comment named the overflow as the hazard.
  - The live test's `s.ssid.len <= max_ssid_len` had become true by construction once
    `summarize` began clamping — a tautology, and the only assertion in the repo that could
    have caught an over-length SSID on real air. It now asserts on the uncapped route and
    reports the refusal when it happens.
- **2026-09-03** — Provenance, corrected in the two documents a reader reaches first. The
  module header and README's Provenance paragraph named `iw` as the only black-box oracle,
  while `goldens.zig` has carried 320 bytes of `wpa_supplicant` 2.11's own output against a
  real `hostapd` AP since the VM lane landed — `SPEC.md` §1.2 and `goldens.zig`'s own header
  said so and these did not. No licence obligation is breached (CONVENTIONS §5), but a
  public repo's provenance statement has to be complete. Also: `EventSocket.waitForEvent`'s
  comment asserted a pid/seq check the function does not make; the safety is real and lives
  in `netlink.Socket.recvDatagramStrict`, which is what the comment now says.
- **2026-08-08** — ⏪ *Backfilled 2026-09-03; these entries were missing.* **BREAKING:**
  `RequestError` gained `NetworkDown` (`ENETDOWN` — the interface exists but is
  administratively down) and, on 2026-08-07, `TooManyMessages`; an exhaustive `switch` over
  the error set written before them does not compile. New public `Nl80211.setRecvTimeout`
  and `Nl80211.fd` for poll/epoll integration.
- **2026-08-07** — ⏪ *Backfilled 2026-09-03; these entries were missing.* **BREAKING:**
  `ie.Security` gained `unknown`, and `security()` now returns it for a truncated element
  walk instead of `.open`/`.wep` — an exhaustive `switch` over `Security` written before it
  does not compile, and the answer for a truncated beacon changed. Plus: `summarize` began
  skipping an SSID element longer than `max_ssid_len`; `station.kilobitsPerSecond` saturates
  instead of panicking on overflow; `RegRule.covers` widened to `u64`.

- **2026-09-02** — `codec.nestEnd` became fallible (`netlink`, audit: it used to truncate a nest
  longer than 65535 bytes silently). Its `AttrTooLong` is mapped here onto this module's existing
  "the request cannot be encoded" error at each call site, the way `appendAttr`'s already was.

- **2026-08-06** — Security audit: six findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against a live capture from
  `iw` 6.17 over libnl — used in-repo as a black-box `strace` capture oracle;
  `wpa_supplicant` explicitly out of scope.
- **2026-07-22** — New module: Wi-Fi control over the nl80211 genetlink family —
  interface/wiphy enumeration, scan trigger + BSS results, connect/disconnect, station
  and link statistics, regulatory domain.
