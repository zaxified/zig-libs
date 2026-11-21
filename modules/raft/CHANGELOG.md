# raft — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-21** — **NEW (membership changes and log compaction, closes both SPEC Backlog items):** `Node.proposeConfChange(changes)` (Raft thesis §4/§6; etcd/raft `ConfChangeV2` with the automatic transition, hashicorp/raft `AddVoter`/`AddNonvoter`/`RemoveServer`): new `ConfChange` (`add_voter`, `add_learner`, `remove`), single-server when at most one voter changes, joint consensus otherwise (every quorum needs both majorities; the leader appends C_new alone once the joint entry commits), learners replicated to but never voting; a membership is in force once in the log (thesis §4.1), one change at a time and only after an entry of the leader's term committed (`ConfChangeError.ConfChangePending`); a leader that removes itself steps down once the change commits; non-voters never campaign. New `message.Membership` (the whole membership as a `config` entry's data and in snapshots), `Node.membership()`, `isVoter`, `isMember`, `Config.max_servers` (ids `0 .. max(cluster_size, max_servers) - 1`, at most `max_servers_limit` = 1024), `safety.leaderCommitIndexJoint`. `Node.compact(index, data)` (§7; etcd/raft `CreateSnapshot` + `Compact`) drops the log up to an applied index, `Node.snapshot()` returns it to persist, `Restore.snapshot` restarts from it; a follower whose next entry the leader compacted is sent InstallSnapshot (new `message.Tag.snapshot` = 0x19, `message.SnapshotMsg`), answered with an `append_resp`, reported in the new `Ready.snapshot` and resent after an election timeout if lost. **API change:** `Ready` gains `snapshot` and `Restore` gains `snapshot` (struct literals of `Ready` must add it), `message.Tag` / `Body` gain `snapshot` (exhaustive switches must add an arm), `InjectedBug` gains `joint_incoming_only` (test control). **Behaviour change:** `init` returns `error.InvalidConfig` when `max(cluster_size, max_servers)` exceeds 1024; a config entry or snapshot naming an id past `max_servers`, or a malformed membership, is dropped and counted (`malformed_dropped`); `transferLeadership` to a non-voter is `InvalidTarget`. An older decoder drops the new tag: upgrade every server before compacting. Harness (`RaftConfig`): `boot_voters`, `conf_churn_ticks` / `min_voters` (random single and joint membership changes), `compact_every` (compaction on every server, a per-index state-machine digest every server and snapshot must agree on); sweeps with churn, compaction, torn Readys. Tests: per rule in `node.zig`, the wire in `message.zig`, the offset log in `log.zig`, the joint commit rule in `safety.zig`.

- **2026-11-21** — **NEW (linearizable reads, closes the SPEC Backlog item) and harness checks:** `Node.readIndex(ctx: u64)` (Raft thesis §6.4; etcd/raft `ReadIndex`, `ReadOnlySafe`): on the leader, after this term's first entry has committed (§8), a probe round (`message.Tag` gains `read_req` 0x17 and `read_resp` 0x18, new `message.ReadProbe`) confirms a quorum still follows it, and `Ready.read_states` (new field) carries `{ctx, index}` for the caller to serve once `applied` reaches `index`; `Config.read_lease` (needs `check_quorum`, else `InvalidConfig`) answers at once from the lease (`ReadOnlyLeaseBased`); a follower answers `error.NotLeader` (new `ReadError`). **API change:** `Ready` gains `read_states` (a `Ready` built as a struct literal must add it), `message.Tag` / `Body` gain two values (exhaustive switches must add arms), `InjectedBug` gains `never_campaign` and `unconfirmed_reads` (test controls). An older decoder drops the new tags, so upgrade every server before the first read. Harness (`RaftServer`, tests): `torn_ready_permille` crashes a server in the middle of a `Ready` (any prefix of persist, send, apply) and restarts it from its disk, with the control `unsafe_send_before_persist`; `checkLiveness` / `checkProgress`, a post-run bounded-liveness analysis after fuzzed churn (**finding:** without PreVote, deterministic timeouts livelock on seed 6, pinned as a test; with PreVote the property holds for 60 seeds); `read_period_ticks` makes leaders ask for reads and the sweep checks each against the highest commit index at asking time (`error.StaleRead`, control `InjectedBug.unconfirmed_reads`). Tests: one per read rule in `node.zig`, the wire in `message.zig`, sweeps in `server.zig`.


- **2026-11-18** — **NEW (leadership transfer, closes SPEC Backlog 7):** `Node.transferLeadership(target)` (Raft thesis §3.10; etcd/raft `TransferLeadership` / `MsgTimeoutNow`, hashicorp/raft `LeadershipTransfer`): the leader refuses proposals while it runs (`ProposeError` gains `ProposalDropped`, etcd's `ErrProposalDropped`), catches the target's log up, then sends it `timeout_now`; the target campaigns at once (never through PreVote) with RequestVotes flagged as a transfer, which receivers honour inside a CheckQuorum lease; abandoned after one election timeout (proposals accepted again), ended by any step-down. Same target again = no-op, another target restarts it, the leader itself cancels. `Node.transferee` names the target. **API change:** `ProposeError.ProposalDropped` (exhaustive error switches must add an arm), new `TransferError`, `message.Tag`/`Body` gain `timeout_now` (0x16), `message.VoteReq` gains `transfer` (default false; wire: an optional 26th byte = 1). An older decoder drops both, so upgrade every server before transferring. **Behaviour change:** a leader now counts `election_elapsed` through each election-timeout period even without `check_quorum` (no observable effect besides the transfer deadline). `RaftServer.proposals_dropped` counts refused harness proposals. Tests: one per rule in `node.zig`, the wire in `message.zig`; netsim: transfer succeeds (defaults and PreVote + CheckQuorum), a lagging target is caught up first, a dead target aborts and the old leader resumes, a 100-seed fault sweep with periodic transfers. raft-kv: `ProposalDropped` arm only (no transfer command).


- **2026-11-18** — **NEW (PreVote and CheckQuorum, SPEC Backlog 7):** `Node.Config` gains `pre_vote` (Raft thesis §9.6, etcd/raft `Config.PreVote`) and `check_quorum` (etcd/raft `Config.CheckQuorum`), both **off by default** as in etcd/raft — with both off, behaviour is unchanged. PreVote: an election timeout first polls peers for `term + 1` without changing term, vote or hard state; a peer grants only an up-to-date log while it has not heard from a live leader within `election_ticks`; a majority of grants starts the real election. CheckQuorum: a leader without AppendEntries responses from a majority during an election timeout steps down in the same term; a node that heard from a leader within `election_ticks` ignores (no reply, no term adoption) a higher-term RequestVote or PreVote. **API change:** `Role` gains `.pre_candidate` (exhaustive switches must add an arm); `message.Tag` / `Body` gain `pre_vote_req` (0x14) and `pre_vote_resp` (0x15), same layouts as the vote messages — an older decoder drops them, so upgrade every server before enabling `pre_vote`. `RaftConfig` (netsim harness) gains `pre_vote` / `check_quorum`. Tests: one per rule in `node.zig`; netsim: a partitioned node rejoining deposes the leader without PreVote and does not with it (term stays 1), a minority leader steps down only with CheckQuorum, a 150-seed fault sweep with both on. Leadership transfer is still open.


- **2026-11-18** — **NEW (hostile-peer limits, SPEC Backlog 10):** `Node.Config` gains `max_append_bytes` (default 1 MiB, etcd's `MaxSizePerMsg` as the etcd server sets it), `max_inflight_msgs` (default 512, etcd's `MaxInflightMsgs`) and `max_inflight_bytes` (default 0 = unbounded, etcd's `MaxInflightBytes`); `Node.maxFrameLen()` gives a transport the largest frame to accept. The leader batches AppendEntries by bytes as well as by count (etcd's `limitSize`: never empty) and keeps a per-follower window of unacknowledged batches (etcd's `Inflights`: freed by the acks that cover them, the oldest freed by an ack that covers none while full, emptied by a rejection); a full window gets heartbeats only. **Behaviour change:** a follower drops and counts (`malformed_dropped`) an AppendEntries whose entries exceed `max_append_bytes`, before allocating for them or observing its term; `propose` returns `error.EntryTooLarge` above `max_append_bytes - 13` (was: the wire's 4 GiB); `init` returns `error.InvalidConfig` for `max_append_bytes < 13`, `max_inflight_msgs == 0`, or a non-zero `max_inflight_bytes < max_append_bytes`. Every server must use the same `max_append_bytes`. No term-jump bound: neither etcd/raft nor hashicorp/raft has one (SPEC § Flow control and hostile-peer limits). `RaftConfig` (netsim harness) gains `max_append_bytes` / `max_inflight_msgs`. Tests: cap and cap+1 for the follower refusal, the leader batch, `propose`, both window bounds; a hostile-peer directed run and a 100-seed fault sweep.

- **2026-11-16** — **NEW (conflict-term hint, §5.3):** `message.AppendResp` gains `conflict_term` and `conflict_index` (default 0 = no hint, so struct literals still compile). A `Node` follower rejecting on a log mismatch reports the term of its entry at `prevLogIndex` and the first index of that term (or, past its end, term 0 and one past its last index); the leader resumes after its own last entry of that term, else at `conflict_index` (never above one step back, never below `matchIndex + 1`). Wire: a rejection with a hint is a 34-byte frame; the 18-byte frame still decodes (no hint), but an OLD decoder refuses the 34-byte frame, so upgrade leaders before followers. Tests: a 350-entry divergent tail converges in at most 12 rejections instead of over 100.


- **2026-10-10** — tests: deterministic fuzz driver `RAFT_FUZZ` over the existing harnesses (message decode + re-encode round trip, tag, log entry, request-vote, append-entries, persistent state); reach labels count real outcomes. No code or API change.
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
