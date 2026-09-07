# raft — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **All five wire-decoder fuzz harnesses were replaying an EMPTY
  slice, and the lying-count frame they exist for had never been built.**

  Each opened with `smith.bytes(&buf)` followed by a ranged length draw. `bytes`
  consumes `min(buf.len, in.len)` octets and a ranged draw then reads eight *more* as
  a little-endian u64, returning the range minimum when fewer remain — so the drawn
  length was 0 for every input a seed can carry, and `tagOf`, `LogEntry.decode`, both
  `RequestVote` decoders, both `AppendEntries` decoders and
  `PersistentState.deserialize` were each handed a zero-length slice while the frame
  sat unread in `buf`.

  ⭐ The comment above them was false when it was written: *"`smith.bytes` + a length
  draw covers both the short-input and the hostile-field-value cases, and the buffers
  are sized past `max_wire` so a well-formed header with a lying count is reachable."*
  Only the shortest short-input case ever ran. A header with a lying entry count is
  precisely the out-of-bounds write these decoders' guards were added for — the same
  class as the `PersistentState` regression this module already pins directly
  (1 000 000 entries once allocated 24 MB and read past the buffer; 0xFFFFFFFF demanded
  ~103 GB) — and the fuzz harness had never carried one.

  All five now take their bytes in one `smith.slice(&buf)` draw and have a hex corpus,
  with a single guard test in the ordinary lane pinning what each decoder produced.
  Measured before → after (every "before" is 0, since every decoder saw `""`): 6 tags ·
  5 log entries · 2 RequestVoteReq and 6 RequestVoteResp · **4 AppendEntriesReq
  carrying 11 entries** and 12 AppendEntriesResp · 4 persistent-state images carrying
  5 log entries.

  The entries-walked and log-entries columns are the discriminating numbers: a
  header-only AppendEntries is a legal heartbeat and a zero-length log is a legal
  persistent state, so an `accepted > 0` guard would have scored full marks on a corpus
  that never entered the entry loop at all.

- **2026-08-24** — `root.zig` now re-exports `tagOf` and `max_entries_per_msg`.
  Found by the module's first outside caller (`example-apps/raft-kv`): every
  RPC type was public but the dispatch helper and the decode-buffer bound were
  not, so an external consumer could not decode the wire the module itself
  defines without reaching into `types.zig`, which the package does not expose.
- **2026-08-11** — Security audit: three findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit.
- **2026-07-17** — New module: Raft consensus (Ongaro & Ousterhout) — leader election +
  log replication, model-checked in netsim against all five formal safety properties.
