# abuseguard — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-25** — Fixed: `ban_threshold` was unreachable in every configuration that
  decays strikes. The drain was continuous, so three unit strikes arriving in the same
  microsecond summed to 2.99997 and a threshold of 3 needed a *fourth* strike — for any
  non-zero `strike_decay_ms`, which is every default. Strikes now drain in whole units,
  as the option always documented ("one strike drains per this interval"), and the drain
  mark advances by what actually drained so a client striking just inside the interval
  still drains. Found by a consumer whose gate never greylisted; the module's own
  threshold tests all set `strike_decay_ms = 0` "to keep the arithmetic exact", which is
  exactly the region where it was wrong.

- **2026-07-19** — Security audit: one finding fixed, two documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on nginx `limit_conn`
  (concurrent-conn caps, zone semantics) + fail2ban (strike→ban escalation) (design
  reference, not a test anchor).
- **2026-07-02** — New module: Per-IP + global connection caps, ban/greylist, strike→ban
  (accept-time).
