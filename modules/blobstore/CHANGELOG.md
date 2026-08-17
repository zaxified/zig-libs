# blobstore — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — **BEHAVIOURAL, not breaking:** `init`/`initOptions` no longer eagerly
  create the `cas/`/`raw/`/`named/`/`tmp/` subdirectories; each is now created lazily on
  that layer's first write, so a store that never uses a layer never creates its
  directory. Every existing read path already tolerated a missing layer directory, so
  this is not a breaking change, but a consumer whose own test harness asserted the
  full four-directory tree right after `Store.init` will now see fewer directories until
  it actually writes to each layer.
- **2026-08-18** — Added `Options.refcount: bool = true`. Set `false` for a store that
  never deletes and never calls `gc`: `casCommit` becomes rename-only (no `<hex>.rc`
  sidecar ever written), matching this module's pre-refcount on-disk layout. `gc`'s CAS
  sweep is a truthful no-op on such a store (sidecar-less blobs were already always
  treated as still-referenced — see SPEC.md); `casDelete`/`delete` return the new
  `error.RefcountDisabled` rather than fabricating a sidecar on demand. Default
  (`refcount = true`) is unchanged from every prior release — not a breaking change.

- **2026-08-14** — Provenance record completed: the git object store (GPL-2.0)
  and restic (BSD-2-Clause) were already named as design references, without
  their licences, which `/NOTICE` §0 requires the record to carry. Nothing is
  owed either way — a design reference imposes no condition. Documentation only.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on git-objects /
  restic (Go) (design reference, not a test anchor).
- **2026-07-09** — New module: Content-addressed blob store (git-object/restic style) +
  name-addressed + small named-record layers, crash-safe.
