# rawsock — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — New: `ipv4Addr` / `ipv4Netmask` (`SIOCGIFADDR` / `SIOCGIFNETMASK`),
  following the exact `ifreq`-ioctl shape of `hwaddr`/`ifaceName`. Closes the last raw
  syscall a consumer had to hand-roll to learn its own subnet for an ARP sweep — the
  module previously stopped at the link layer (`SIOCGIFHWADDR`). Purely additive; no
  existing behavior changed.
- **2026-07-19** — Security audit: no findings. Modeled on `libpcap` (minimal AF_PACKET
  path) (design reference, not a test anchor).
- **2026-07-09** — New module: Linux AF_PACKET raw-frame capture + inject — BPF filter,
  promiscuous mode, typed frame decode.
