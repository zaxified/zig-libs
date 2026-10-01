# df-elect

EVPN-style Designated-Forwarder election with failover, plus split-horizon,
for a link-state L2VPN fabric that has no BGP. A customer site multihomed to N
edge nodes forms an *edge segment* (an EVPN Ethernet Segment); for every
Ethernet tag on it, exactly one member must deliver broadcast / unknown-unicast
/ multicast (BUM) traffic toward the site. Each member works the DF out from
its own view of a flooded Hello — who it currently hears, and who they hear —
with RFC 7432 §8.5 service carving (`modulo`, tag mod N), RFC 8584 §3.2
Highest Random Weight (`hrw`) or preference-based election (`preference`, what
FRRouting runs); it gives a role up at once and takes one only after
`df_wait`. Model-checked in `netsim` under partitions, one-way link cuts,
crashes, restarts and clock jumps: split-horizon never fails, a duplicate
happens only in the heal race right after connectivity returns, a dead or
deaf DF is replaced within a bounded window, and no frame a reachable member
could have delivered is lost outside such a window (one known limit: a
one-way failure deeper in the core, SPEC "Known limit").

```zig
const dfe = @import("df-elect");

// Who is DF for tag 10 among the members this node currently sees?
const df = dfe.designatedForwarder(.modulo, segment.esi, live_members, 10);

// Take the role only after the view has named us for df_wait; drop it at once.
role = dfe.stepRole(role, df == self, now, cfg.df_wait);

// Deliver a BUM frame only as DF, and never back into its ingress segment.
if (role.is_df and dfe.allowForward(frame.ingress_segment, segment.id)) deliver(frame);
```

- `designatedForwarder(algorithm, esi, candidates, tag) ?NodeId` — the DF
  function, pure: `moduloDf` (RFC 7432 §8.5: ordinal `tag mod N` over the
  address-sorted list), `hrwDf` (RFC 8584 §3.2: highest
  `hrwWeight(tag, esi, addr)`, ties to the least address) or `preferenceDf`
  (highest `Member.pref`, ties to the least address, one DF per segment —
  checked against FRRouting observed as a black box).
- `Role` / `stepRole(role, named, now, df_wait)` — the per-tag role state
  machine: losing is immediate, gaining waits `df_wait` of continuous naming
  (RFC 7432 §8.5 step 2 / RFC 8584 §2.1 DF_Wait).
- `allowForward(ingress, this_segment)` — split-horizon (RFC 7432 §8.3),
  independent of DF state.
- `EdgeSegment` (id, ESI, address-sorted `members`, `tags`; `validate`),
  `Member`, `Tag`, `Algorithm`, `ElectConfig` (`hello_period`, `stale_after`,
  `df_wait`, `algorithm`).
- `Hello` (origin, seq, segment or `no_segment`, `view` = the members the
  origin sees; empty = it declares itself isolated) / `BumFrame` (origin,
  seq, ingress segment, tag) / `no_ingress` — the two 17-octet wire
  messages; both decoders fail closed.
- `DfElect` — the `netsim.Protocol` that runs it all over a Hello flood. A
  member is named DF only when its own view AND every live peer's advertised
  view name it, which makes a one-way failure safe (the member nobody hears
  yields); a member that hears no fabric node at all is isolated and holds
  nothing (EVPN-MH core isolation). Every node floods Hellos.
  `BrokenAlwaysDf` — the positive control.
- `DeliveryChecker`, `firstUnexplainedDuplicate` / `maxDuplicateWindow`,
  `worstZeroDfWindow` / `maxZeroDfWindow`, `firstUnexplainedLoss` — the
  invariant machinery.

- **Role:** util. **Platform:** any. **Deps:** `netsim`. **Concurrency:**
  single-owner — `DfElect` holds per-run state; the DF functions and
  `stepRole` are pure.

Provenance: clean-room from RFC 7432 (§8.3, §8.5) and RFC 8584 (§2.1, §3.2),
re-derived for a Hello-flood fabric. The committed test vectors
(`src/kat_vectors.zig`) are generated data from our own tooling
(`tools/rederive.py`, stdlib-only Python). FRRouting (GPL-2.0-or-later) is
observed as a black box by `tools/frr/` (its outputs are committed as
observation data, no FRR source was read). No third-party source consulted or
copied.

## Verification

`zig build test-df-elect` — offline; the fuzz sweep runs 120 seeds per
algorithm in Debug and 400 optimized:

- split-horizon: zero violations (live check, halts the run);
- duplicates: every one follows a heal / link-up / restart within
  `maxDuplicateWindow` (= 100; measured worst 50 ticks);
- zero-DF: every stretch without a DF, measured from the last disruptive
  fault, stays within `maxZeroDfWindow` (= 420; measured worst 377);
- fault-free runs: no duplicate at all, and the roles settle on the RFC
  assignment; explicit failover (DF crash + restart) and partition/heal cases;
- negative control: `df_wait = 0` duplicates at startup with no fault to
  explain it; positive control `BrokenAlwaysDf` trips the checker;
- REDERIVED: `kat_test.zig` checks `hrwWeight`, `moduloDf` and `hrwDf`
  against an independent Python re-derivation of the RFC formulas;
- EXTERNAL: `frr_test.zig` checks `preferenceDf` against 12 settled phases
  observed from FRRouting 10.7.1 (`tools/frr/`).

See `SPEC.md` for the argument (why failover makes duplicates bounded rather
than zero, why the view consensus is needed) and the measured numbers.
