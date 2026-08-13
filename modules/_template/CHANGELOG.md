# `<name>` — changelog

<!--
SKELETON — put your module's name in the heading above and delete this comment.

Every module in `build.zig`'s `module_list` has one of these, including a module
whose only history is being created, and `zig build check-changelog` fails when
one is missing. Two things are needed, not one:

  this file, at `modules/<name>/CHANGELOG.md`. The root `CHANGELOG.md` carries
  only collection-wide notes and the release sections; it does not index the
  modules.

The `YYYY-MM-DD` below is deliberately not a date: leave it unfilled and the
gate's date check fails naming this file and line. See `CONVENTIONS.md` §8 for
the policy and `modules/tlock/CHANGELOG.md` for a filled-in example.
-->

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **YYYY-MM-DD** — New module: what it is and what it is for, in one sentence,
  plus the anchor it is verified against if it has one.
