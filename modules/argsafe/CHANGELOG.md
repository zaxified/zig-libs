# argsafe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on Python
  `shlex.quote`/`subprocess` list-argv, Go `exec.Command` (argv array), Rust
  `std::process::Command` (design reference, not a test anchor).
- **2026-07-09** — New module: Allowlist validators + a typed argv builder — neutralizes
  argument/flag injection into an exec `argv`.
