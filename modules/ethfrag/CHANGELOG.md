# ethfrag — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on Linux `ip_defrag`
  (conceptual — IP fragmentation/reassembly threat model, RFC 791 §3.2 + RFC 5722 §3
  overlap rejection) (design reference, not a test anchor).
- **2026-07-15** — New module: Hardened inner-frame fragmentation/reassembly codec — RFC
  5722 whole-datagram overlap rejection, bounded per-datagram + concurrent-datagram
  memory, caller-clocked timeout, fuzz-tested never-panic.
