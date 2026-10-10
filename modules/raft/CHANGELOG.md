# raft — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — tests: deterministic fuzz driver `RAFT_FUZZ` over the existing harnesses (message decode + re-encode round trip, tag, log entry, request-vote, append-entries, persistent state); reach labels count real outcomes. No code or API change.
- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: Scope line dates the survey 2026-09-30 and the poc -> mvp re-assessment 2026-10-04, matching Compared with.
- **2026-10-04** — **`raft.Node`: a runnable server; scope poc → mvp (user decision, reverses 2026-09-30).**
  `Node` (`node.zig`) is one Raft server as a pure state machine — `tick` / `step` /
  `stepBytes` / `propose` → `ready` / `advance` — over caller-owned transport, disk and
  clock, any cluster size, entries carrying bytes (`Entry`, `Message` and a fail-closed
  codec in `message.zig`), restart from persisted state (`Restore`). The leader counts
  its own log toward a majority only up to what `advance` confirmed persisted.
  **Breaking for the netsim harness:** `RaftServer` now runs N `Node`s (`nodes` →
  `slots` / `node(i)`, `malformed_dropped` → `malformedDropped()`, `RaftConfig` gains
  `tick` and `drain_every_event`, `InjectedBug` moved to `node.zig`); a restart rebuilds
  a server from its persisted state alone, and the disk must equal the log after every
  drain. Structural fixes on the way: tick-driven elections (the "step-down forgot to
  re-arm the timer" class cannot recur), no term past `max_term` (two elections at the
  ceiling used to overflow `current_term += 1`), senders taken from the transport, not
  the frame. `example-apps/raft-kv` now runs on `Node` (its own plumbing had no bound
  on a peer's claimed match index — a forged ack could commit what no majority held).
  **Review (Sonnet, adversarial): 1 HIGH fixed** — H1: a leader deposed by a `step`
  between `propose` and `ready` broadcast its stale tail under the NEW term; unreachable
  for the old harness, which drained after every event; pinned by a unit test (the new
  batched-Ready sweep was measured NOT to catch it re-introduced).
  MED fixed: no re-send on a duplicate/stale ack or an unmoved rejection; persist order
  inside a Ready documented; term-0 requests/entries refused. **Mutation** (schemata,
  ReleaseSafe): 36 + 17 mutants; every survivor got a test except two equivalent ones
  (the two independent H1 guards, each redundant alone — both removed is killed) (late grant from an older
  term, verified-prefix ack, unpersisted no-op, immediate commit broadcast, propose on a
  follower, vote-grant timer reset, `Restore.applied`, stale ack lowering `match`,
  trailing bytes on fixed messages). Not done: snapshots, membership, pre-vote,
  ReadIndex, a torn-Ready fault (SPEC § Backlog 3, 5, 7–11).

- **2026-09-11** — Consumer-side follow-up to the `netsim` A1 fix campaign
  (F2/F3/F6): `netsim.Protocol.resetFn` is mandatory now, so
  `StepDownProbe.reset`'s `inner.resetFn.?(inner.ctx)` no longer compiles
  (`resetFn` is not an optional to unwrap) — dropped the `.?`. And
  `BrokenRaft` fires unconditionally, with no injected fault (documented:
  "Fires on a clean run with no injected faults"), so `netsim`'s shrinker
  now correctly reduces its counterexample to the EMPTY fault set instead
  of a pre-fix floor of `>= 1` — the "shrink" test's assertion updated from
  `if (res.before >= 1) try testing.expect(res.after >= 1);` to
  `try testing.expectEqual(@as(usize, 0), res.after);`. No behavioural
  change to `raft` itself. `scripts/modtest raft`: 61/61.

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
