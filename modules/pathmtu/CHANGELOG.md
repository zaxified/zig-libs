# pathmtu — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — New module: Path MTU discovery for IPv4/IPv6 on Linux —
  `query` (kernel PMTU cache) and `probe` (authoritative DF-bit binary
  search that detects ICMP black holes the cache structurally cannot see).
  `probe`'s wire classification is anchored against ICMP Fragmentation
  Needed / Packet Too Big bytes captured from a real forwarding router with
  a genuinely lowered-MTU link (`veth` pair in an unprivileged netns); the
  search algorithm and the black-hole/well-behaved distinction are verified
  offline against a fake `Prober` (class A · oracle MIXED — see SPEC.md).
