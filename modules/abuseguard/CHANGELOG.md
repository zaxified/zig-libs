# abuseguard — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: one finding fixed, two documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on nginx `limit_conn`
  (concurrent-conn caps, zone semantics) + fail2ban (strike→ban escalation) (design
  reference, not a test anchor).
- **2026-07-02** — New module: Per-IP + global connection caps, ban/greylist, strike→ban
  (accept-time).
