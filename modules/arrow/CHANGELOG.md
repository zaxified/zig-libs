# `arrow` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-16** — New module (work in progress, wave A1): the FlatBuffers layer Arrow's metadata is written in — a
  bounds-checked reader (every offset, vtable, vector and string checked; a hostile buffer is `error.Malformed`) and a
  back-to-front builder.
