# ethfrag — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** the fuzz harness gained a
  burst step kind so coverage-guided fuzzing reaches the
  `max_fragments_per_datagram` guard (A1 F6; `TooManyFragments` was 0 in
  200,151 runs, now reached), and the two exhaustion guards return through
  private `noinline` markers so a fuzz run can measure them. `insert` returns
  the same `error.TableFull` / `error.TooManyFragments` on the same inputs;
  the public API is unchanged.
- **2026-09-11** — **BEHAVIOURAL, not breaking:** `insert`'s overlap check
  and buffer allocation no longer scale with an attacker-chosen `n` the way
  they did (A1 F8+F9). Fragment intervals are now kept sorted internally
  (overlap check is a binary search + short neighbor scan instead of a full
  list scan every time — measured 16.1x checks for 16x fragments, was 56x
  wall-clock), and a datagram's reassembly buffer now grows lazily to what
  its fragments actually need instead of eagerly paying `max_frame_len` for
  every fragment id (measured 225,000 B total for a 50,000-insert churn
  pattern that previously cost 1,641,675,624 B). `Reassembler`'s public API
  (`init`/`deinit`/`insert`/`expireOlderThan`/`inflightCount`) and every
  observable `InsertResult`/error are unchanged.
- **2026-09-10** — A1 fix campaign (0 in-repo consumers, P1 applies): closed 2 HIGH + 4
  MED + 4 LOW of the 14-finding audit (10 of 14; F6/F8/F9/F13 left open, see below).
  - **F2 (HIGH):** `timeout_ns` only measured idle time, so a steady trickle of
    individually-legitimate, non-overlapping fragments for one `frag_id` kept an entry
    "fresh" forever and a competing `frag_id` starved on `TableFull` no matter how long
    it waited. Added `ReassemblerConfig.max_lifetime_ns` (default `8 * timeout_ns`), an
    absolute age cap enforced by `expireOlderThan` (including the internal sweep
    `insert` runs when the table is full) — deliberately not on an entry's own inline
    refresh path, so an incumbent cannot renew its own slot forever just by continuing
    to send. Measured: 100 individually-accepted fragments, 10ns apart (always well
    under `timeout_ns`), a competing `frag_id` got `TableFull` before the fix and
    `incomplete` (accepted) after.
  - **F3 (HIGH):** the overlap/bounds test suite pinned the EXISTENCE of guards, not
    their exact boundaries — 8 of 17 hand-mutated weakenings left the suite green,
    including two that a real mutation reproduces as a crash (`panic: index out of
    bounds`, `panic: source and destination arguments have non-equal lengths`, both on
    the same `@memcpy`). Added 7 boundary-pinning regression tests (non-last-interval
    overlap, exact 1-byte overlap, `max_frame_len`/`max_frame_len+1`, idle time exactly
    equal to `timeout_ns`, a retroactive bound landing exactly at vs. one past a
    newly-established `total_len`, and a `more=false` disagreement in EITHER direction
    plus the payload-longer-than-declared direction of `LengthMismatch`), each verified
    RED against the exact mutation it targets and GREEN against the real module.
  - **F1 (MED):** a `length == 0` fragment never overlapped anything (including an
    exact resend of itself) under the half-open `[offset, offset+length)` test, so it
    could be replayed at the wire's cheapest possible cost forever, feeding F2. A
    non-final (`more = true`) zero-length fragment is now rejected outright
    (`error.EmptyNonFinalFragment` — `fragment()` never produces one); a final
    (`more = false`) zero-length duplicate at the same offset is now caught as an
    ordinary overlap. A zero-length fragment that does not exactly duplicate an
    existing interval (e.g. one sharing an offset with a later, larger REAL fragment)
    still reassembles correctly — regression-tested.
  - **F7 (MED):** `Reassembler.init`'s config validation was `std.debug.assert`,
    compiled OUT of ReleaseFast — measured as a raw `SIGSEGV` with no diagnostic for
    `max_inflight = 0`. Replaced with unconditional `if`+`@panic`, active in every build
    mode; also added the one config field with no validation at all
    (`max_fragments_per_datagram >= 1`), which previously churned a full
    `max_frame_len` allocate/free per fragment forever when set to 0. Measured: Debug
    `max_fragments_per_datagram = 0` silently accepted before, `panic:
    ReassemblerConfig.max_fragments_per_datagram must be at least 1` after; ReleaseFast
    `max_inflight = 0` a bare `SIGSEGV` before, a clean `panic:
    ReassemblerConfig.max_inflight must be at least 1` after.
  - **F4 (MED, doc):** SPEC.md claimed worst-case memory was a deterministic
    `max_inflight * max_frame_len` "no matter how many fragments... it sends" — the
    formula omits the interval list, whose size the sender chooses. Corrected to state
    the buffer bound is real but partial (measured 1.37×–17.49× over the buffer-only
    bound depending on configured `max_frame_len`, per the audit).
  - **F5 (MED, doc):** the README's example config (`max_inflight = 64`, default
    `max_frame_len`) gives no hint that it holds up to ~4.2 MB live for 512 bytes of
    wire input. Added the measured number and a pointer to SPEC.md's fuller accounting
    directly under the example.
  - **F10/F11/F12 (LOW, doc):** README's hardcoded "26 pass" (actual, then and now,
    tracks the growing suite — no longer hardcoded); SPEC.md claimed the module had no
    README when one has existed since the provenance sweep; `kernel_oracle.zig`
    misattributed a quote to `root.zig` that only ever lived in `SPEC.md`.
  - **F14 (LOW):** `LengthMismatch`'s doc comment promised rejecting payload both too
    short AND too long; only the too-short direction had a test (the code was already
    correct — `payload.len != hdr.length` is symmetric). Added the too-long direction.
  - **Not closed:** F6 (MED) — the specific "0 steps run" collapse this audit measured
    was already fixed upstream in `66808284` (2026-09-07, ancestor of this branch,
    confirmed via `git show 66808284^:modules/ethfrag/src/root.zig`); the remaining
    half (the fuzz generator's offset draw spans the full `u16` against a 512-byte
    `max_frame_len`, so `TooManyFragments`/`TableFull` are never reached under
    `--fuzz`) was left alone this session — narrowing it risks reshaping the byte
    layout the named corpus seeds (including one built specifically around `offset =
    0xFFFF`) depend on, and re-verifying it needs an actual `--fuzz` run outside this
    session's budget. F8/F9 (quadratic overlap scan, eager full-size allocation) need a
    data-structure change (sorted intervals, lazy allocation) out of scope for one
    session. F13 (extending the kernel-oracle capture to adversarial shapes) needs a
    `capture.py` that does not exist yet and a privileged network-namespace session.

- **2026-09-07** — `fuzzReassembler` had never executed its own loop body. The step count came
  from `smith.valueRangeAtMost(u8, 0, 64)`, a ranged draw, which reads eight octets as a
  little-endian `u64` and returns the range MINIMUM unless that whole word lands inside the
  range — so it was 0 on every replay: the reassembler was constructed, handed NOTHING, and
  destroyed, and the `inflightCount() <= max_inflight` assertion the test is named for never
  ran either. The fragment stream now comes out of one `smith.slice` call as the first draw
  and is read with `testkit.fuzz.Cursor` (`NN` steps, then a time advance, a branch and the
  header fields per step), with a nine-script corpus covering an in-order completion, an
  out-of-order one, an exact duplicate followed by a disagreeing overlap, five distinct
  `frag_id`s against `max_inflight = 4`, a jump past `timeout_ns`, an offset of `0xFFFF`, raw
  sub-header buffers, and the maximum step count. Measured: **0 steps run, 0 datagrams
  completed and a peak in-flight count of 0 before; 81 steps, 3 completions and a peak of 4
  after.**

- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on Linux `ip_defrag`
  (conceptual — IP fragmentation/reassembly threat model, RFC 791 §3.2 + RFC 5722 §3
  overlap rejection) (design reference, not a test anchor).
- **2026-07-15** — New module: Hardened inner-frame fragmentation/reassembly codec — RFC
  5722 whole-datagram overlap rejection, bounded per-datagram + concurrent-datagram
  memory, caller-clocked timeout, fuzz-tested never-panic.
