# rawsock — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
