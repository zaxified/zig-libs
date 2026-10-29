# abuseguard — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-29** — **NO CONSUMER-VISIBLE CHANGE:** Delta audit of the no-panic sweep: 5 mutants over the changed code; 4 killed, 0 equivalent, 1 not scored (the hook-context checked panic). The survivor became a test: a counter at maxInt(u32) with an earlier ban keeps the ban verdict. Checked panics are not mutated (a test cannot observe a panic in-process). Cumulative 61/61, 0 eq. Card A1 again.
- **2026-10-28** — **Fix (no-panic sweep):** `admit` answers `.per_ip_cap` at `maxInt(u32)` live connections of one key — with `max_conns_per_ip = null` a `reconcile(ip, maxInt(u32))` followed by `admit` overflowed the counter (wrapped to 0 in ReleaseFast); the `http.Server` hooks panic with a message when wired without their context (was a null unwrap, UB in ReleaseFast). Report `~/CML/20261028-panic-sweep/abuseguard-sweep.report.md`.

- **2026-10-23** — **BREAKING:** `Guard.ban` and `Guard.greylist` return `error{StoreFull}!void` — a key the full store cannot track used to lose the ban silently. Fixed: eviction at capacity is O(1) (three LRU lists: idle, idle banned, live) — it walked every live and banned entry under the lock; an overfull `restore` keeps the most recently touched bans (records applied last to first); `init` checks its `Options` in every build mode (`@panic`, were debug-only asserts). Behavioural: closing a key's last connection counts as a touch for the LRU; `snapshot` lists ranges, then idle banned keys, live keys, other idle keys. Grade 1 (lead vs nginx `limit_conn`, `tools/nginx_probe`).

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC statements that Zig has no io-less blocking mutex / `std.Thread` primitives re-checked against the 0.17.0 std (still true).

- **2026-10-18** — Ported to Zig 0.17.0. model-fuzz reach loop uses `@typeInfo(..).field_names` (`std.meta.fields` is gone). No behaviour change.

- **2026-10-11** — Added (scope core → parity; fail2ban / nginx `limit_conn` parity pass): `Options.greylist_ttl_growth` / `greylist_ttl_max_ms` (fail2ban `bantime.increment` / `bantime.maxtime`: the n-th offense greylists for `ttl * growth^(n-1)`, capped; default 1 = unchanged); `Options.on_event` + `Event` / `EventHook` (fail2ban actions: `banned`, `greylisted`, `unbanned`, `evicted`, `prefix_banned`, `prefix_unbanned`, `all_cleared`, `dry_run_reject`, delivered after the lock is released); `Guard.unbanAll` (`fail2ban-client unban --all`); `Options.dry_run` (nginx `limit_conn_dry_run`: admit and count what would be refused, report it as an event). `AdmitVerdict` unchanged. The model-fuzz now also checks the exact event stream, growth, dry run and `unbanAll`.

- **2026-10-11** — Fix (stricter): `record` restarts the strike-drain interval at the strike when the previous balance had drained out completely. It used to keep the idle time's sub-interval remainder, so a strike after a long idle could drain up to one `strike_decay_ms` early and an offense could be missed (the code comment already said it should not). Two regression tests; the model-fuzz reference updated to match.

- **2026-10-11** — tests: model-fuzz against a naive ordered-array reference model (300 seeded random sequences over admit/close/record/ban/greylist/prefix bans/reconcile with an injected clock; per-step verdict and state checks incl. LRU eviction and sweep, snapshot multiset, text and restore round trips; reach classes enforced). No API or behaviour change.

- **2026-10-10** — Card Performance `n/a` with the reason (no timeable reference implementation). Docs only.

- **2026-10-04** — Added (survey 2026-09-30 backlog): `Options.allow` (fail2ban
  `ignoreip` allowlist of `netaddr.Prefix`; exempts from every reputation verdict and from
  `record`/auto-strike, caps still apply); `Options.ipv6_key_bits` / `ipv4_key_bits`
  (reputation keyed per masked prefix); `banPrefix` / `unbanPrefix` +
  `Options.max_prefix_bans` (range bans, new error `TooManyPrefixBans`); `BanRecord`,
  `Guard.snapshot` / `Guard.restore`, `writeSnapshot`, `parseSnapshotLine` (persist bans
  across a restart, text lines `ban` / `range` / `greylist`; a file written under other key
  widths still restores; strikes and offenses are not kept).
  ⚠ BEHAVIOUR CHANGE: `ipv6_key_bits` defaults to **64**, so IPv6 clients are keyed per /64
  (one subscriber, RFC 6177) instead of per address: `max_conns_per_ip`, strikes, bans and
  greylists are now shared by every address in a /64. Set `ipv6_key_bits = 128` for the old
  behaviour.

- **2026-09-29** — Added: `Options.on_store_full` (`.reject` default, `.admit_untracked`).
  The fail-closed store was itself a lockout: 4096 addresses each holding one idle
  connection filled the default store and every NEW address got `store_full` while the
  holders were served (measured from qap). `.admit_untracked` admits such an address with
  no entry — new verdict `.admitted_untracked`, released by `connClosedUntracked` (or by
  `connClosed`, which falls back to it when the address holds no live slot) — and still
  counts it in `total_conns`, so `max_conns_total` bounds it. `untrackedConns()` reports
  them. ⚠ `AdmitVerdict` has a new member: an exhaustive `switch` on it must add it.

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
