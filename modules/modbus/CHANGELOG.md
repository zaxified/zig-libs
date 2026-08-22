# modbus — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — `TransportError` gained a `Canceled` variant so a `std.Io`
  cancellation (`Future.cancel`) surfaces distinctly from `TransportFailed`
  and from `Timeout`. `TcpTransport.exchangeFn` recovers it from the concrete
  reader's/writer's out-of-band `err` field instead of collapsing every
  failure into `TransportFailed`.
- **2026-08-11** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Byte-exact
  vs the Modbus Application Protocol V1.1b3 worked wire examples for
  FC01/02/03/04/05/06/0F/10/17 (`root.zig:721`– `822`) and vs the reveng CRC-catalogue
  check.
- **2026-07-07** — New module: Modbus TCP (MBAP) + RTU (CRC-16) codec, master client and
  slave server — core function codes, diagnostics, exceptions, broadcast/unit-id
  semantics, transport-agnostic seam.
