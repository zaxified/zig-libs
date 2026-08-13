# l2forward — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: seven findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: The one anchorable constant
  *is* anchored.
- **2026-07-24** — New module: E-LAN edge forwarding table — per-I-SID customer-MAC
  learning (MAC → remote PE) with time-injected aging + the BUM ingress-replication set
  with split-horizon; forward decision.
