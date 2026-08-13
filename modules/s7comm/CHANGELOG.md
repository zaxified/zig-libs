# s7comm — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: an unauthenticated 43-byte Read Var request could
  drive an out-of-bounds read one byte past a registered memory area; fixed, along with
  4 further findings.
- **2026-07-23** — New module: Siemens S7 communication — ISO-on-TCP (RFC 1006 TPKT +
  COTP) plus the S7 protocol: connection setup, area read/write (DB/M/I/Q/T/C), PLC info
  and cyclic services.
