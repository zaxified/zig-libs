# l2disco — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Wireshark
  dissectors / lldpd / isc-dhcp (design reference, not a test anchor).
- **2026-07-07** — New module: Layer-2 / neighbor discovery codec — LLDP (802.1AB) + CDP
  + ARP (RFC 826) + DHCP options (RFC 2131/2132) + MAC helper.
