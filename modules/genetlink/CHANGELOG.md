# genetlink — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **both fuzz harnesses discarded the seed before reading a byte of it.**
  `fuzzSplitPayload` opened `smith.bytes(&buf)` and then sliced to
  `smith.valueRangeAtMost(u16, 0, buf.len)`; a `Smith` ranged draw reads eight input octets as
  a little-endian u64 and returns the range MINIMUM unless that word already lies inside the
  range, so the length was 0 for every seed and `splitPayload` only ever saw an empty slice.
  `fuzzFindMcastGroupId` opened with `smith.value(bool)` — a 1-bit draw, likewise always its
  minimum — so its raw-bytes branch was dead, and inside the surviving branch `n_groups` was
  `valueRangeAtMost(u8, 0, 4)`, also 0: **it built the identical 4-octet empty nest for every
  seed**, never reaching the inner nest walk or the name comparison that branch exists for.
  Both now draw with `smith.slice`, run both halves on every seed, and carry a corpus built at
  run time by this module's own `appendHeader`/`buildMcastGroupsAttrs` and `codec`'s encoders
  (netlink lengths and scalars are HOST byte order, so a hex corpus would be a little-endian
  one). Measured over those corpora: `fuzzSplitPayload` 0 → 6 of 6 seeds non-empty, 0 → 4
  payloads accepted and 0 → 3 attributes walked behind them; `fuzzFindMcastGroupId` 0 → 7 of 7
  seeds contributing their own octets, 0 → 1 group id found and 0 → 2 typed refusals. Both
  numbers are pinned by a corpus guard.
- **2026-09-07** — `testkit` added to the module's `test_deps` in `build.zig`, for
  `testkit.fuzz`'s corpus-seed helpers. Test-only; nothing a consumer imports changes.

- **2026-07-19** — Security audit: no findings. Verified:
  `buildGetFamilyRequest("wireguard")` is anchored by a hand-derived golden 36-byte
  vector matching kernel UAPI (`root.zig:332-348`), incl.
- **2026-07-14** — New module: Generic-netlink (genl) transport: genlmsghdr framing +
  nlctrl family-id resolution — the shared foundation for genetlink-family clients
  (ethtool/devlink/nl80211/wireguard).
