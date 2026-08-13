# blobstore — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — Provenance record completed: the git object store (GPL-2.0)
  and restic (BSD-2-Clause) were already named as design references, without
  their licences, which `/NOTICE` §0 requires the record to carry. Nothing is
  owed either way — a design reference imposes no condition. Documentation only.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on git-objects /
  restic (Go) (design reference, not a test anchor).
- **2026-07-09** — New module: Content-addressed blob store (git-object/restic style) +
  name-addressed + small named-record layers, crash-safe.
