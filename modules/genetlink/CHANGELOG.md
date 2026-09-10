# genetlink — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **security audit follow-up: five findings closed in the reply-resolution path,
  two of them HIGH.**
  - **F1 (HIGH):** `ctrlGetFamily`'s reply loop had no message budget — a kernel reply stream that
    never reached `NLMSG_DONE`/a bare ACK (missing terminator, an endless `NLM_F_DUMP_INTR`
    stream, or a flood of foreign-`seq` datagrams) spun `resolveFamily`/`resolveMcastGroup`
    forever. Bounded at `max_reply_messages` (65536, same value/rationale as `netlink`'s
    `max_await_messages`/`max_dump_messages`); new `error.TooManyMessages` on `ResolveError`
    (additive — `nl80211`/`ethtool`/`devlink`'s `mapResolve` updated to fold it onto
    `MalformedReply`, the only exhaustive switches over it in the repo).
  - **F2 (HIGH):** a resolved family's identity was never checked — a reply naming a different
    family, with no `CTRL_ATTR_FAMILY_NAME` at all, carrying `CTRL_CMD_DELFAMILY` instead of
    `NEWFAMILY`, or with an id outside the kernel's own `[GENL_ID_CTRL, GENL_MAX_ID]` range, was
    all accepted. Live and reachable with no attacker: `resolveFamily("nlctrl\x00zz")` resolved,
    because the kernel reads `CTRL_ATTR_FAMILY_NAME` as a C string (stops at the embedded NUL)
    while this module compared nothing at all. All three axes are now verified before a record is
    accepted; any mismatch is `error.MalformedReply`, the vocabulary already used for a malformed
    datagram — no new error, no signature change.
  - **F3 (MED):** `lastErrorMessage()` could outlive the request it described — a caller reading it
    after a successful call, or after an unrelated failure, saw stale text from an earlier request.
    Cleared unconditionally before each request now.
  - **F7 (LOW):** a name too long for `GENL_NAMSIZ` still advanced the socket's sequence counter,
    even though the request was never built or sent. The length guard now runs before the counter
    is touched.
  - **F8 (LOW):** `findMcastGroupId` accepted a matching group entry whose id was 0 (every id this
    module has observed from a real kernel is dynamically assigned and nonzero), and matched an
    empty `want` against an empty group name. Both now `error.BadLength`/no match respectively.
  - **F6 (LOW, new API):** `Socket.resolveMcastGroups(family, names, out)` resolves several group
    names over one `CTRL_CMD_GETFAMILY` round trip instead of one round trip per name (measured:
    6 names = 30 syscalls before, matches `nl80211`'s own subscribe loop). Additive; existing
    resolvers unchanged.
  - **F9 (LOW):** `genetlink` registered with `scripts/check-uapi-consts.py` (previously the only
    automatic check of its constants ran through `nl80211`'s own private copy, which SPEC's backlog
    plans to delete).
  See `SPEC.md` for the full writeup and `~/CML/20260901-zig-libs-audit/A1/genetlink.md` for the
  audit record.

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
