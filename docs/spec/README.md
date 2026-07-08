# Design specs (historical / partial)

These `SPEC-*.md` files are **design-time specifications** written before (or alongside) the
first implementation of the older modules. They record each module's intended shape, its
**`Model after:`** reference implementation and **`Seed:`** source (the sibling-project code a
module was extracted from) — provenance worth keeping.

They are **not a living contract** and cover only ~22 of the 49 shipped modules (roughly those
built before 2026-07-04); newer modules (`coap`, `snmp` v3/USM, `conneg`, `cookies`, `jwt`,
`acme`, `mqtt`, `mcp-http`, `range`, `upstream`, …) intentionally have no spec here. For any
module the authoritative, up-to-date description is:

- the module's own `modules/<name>/README.md` + doc-comments + tests (the living contract),
- the root `README.md` module table,
- `NOTICE` (canonical provenance, design-refs, and third-party attributions), and
- `docs/CANDIDATES.md` (the full candidate catalog with per-module `Model after` / `Seed`).

We do **not** backfill specs for the newer modules — tests + README + NOTICE are the source of
truth. These are kept for historical design rationale.
