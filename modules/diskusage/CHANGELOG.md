# diskusage — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — New module: `statfs(2)`/`statfs64(2)` disk-space query
  (total/free/available bytes, inodes, block size, fs type magic — `f_bfree`
  vs `f_bavail` both exposed and documented) plus `/proc/self/mounts` and
  `/proc/self/mountinfo` parsers, with octal-escape decoding for paths
  containing spaces/tabs/backslashes. Class B, oracle REDERIVED — struct
  layouts re-derived from kernel UAPI headers (cross-checked against musl's
  per-arch `bits/statfs.h`) covering four architecture families
  (`Native64`/`MipsStatfs64`/`PackedGeneric32`/`NaturalGeneric32`); mount
  parsers golden-tested against real captures from this host.
