# fleetsim — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security audit: seven findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on ModbusPal / Kepware simulator
  (design ref); composes `netsim` + 7 protocol responders (design reference, not a test
  anchor).
- **2026-07-23** — New module: In-process simulated device fleet — hosts many protocol
  responders (Modbus, DNP3, IEC 104, S7comm, BACnet, EtherNet/IP, OPC UA) as addressable
  nodes on one deterministic, time-injected scheduler.
