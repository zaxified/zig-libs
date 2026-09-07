# ethfrag — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
