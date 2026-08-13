# iec104 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against a
  live capture from `lib60870-C` (and its `c104` Python binding).
- **2026-07-23** — New module: IEC 60870-5-104 telecontrol — APCI/APDU framing, I/S/U
  formats with k/w flow control, ASDU codec for the common type IDs, and a
  transport-agnostic master (controlling station).
