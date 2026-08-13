# devlink — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against a
  live capture from `devlink` (iproute2 6.19) over libmnl — used in-repo as a black-box
  capture oracle.
- **2026-07-23** — New module: Linux devlink over genetlink — device/port enumeration,
  port split/unsplit, parameter and resource inspection, region snapshots, health
  reporters and eswitch mode.
