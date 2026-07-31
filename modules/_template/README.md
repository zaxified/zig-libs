# _template

Copy this folder to `modules/<name>/`, then:

1. Fill in `src/root.zig` (`meta` block + public API + tests).
2. Register `.{ .name = "<name>", .deps = &.{...} }` in the root `build.zig`.
3. `zig build test-<name>`.

Document here: **what it is**, **status** (extract/gap/adopt), **model-after**
(the other-language reference), and the **seed** location if extracting from an
existing project.

Then replace the line below. `zig build check-catalog` requires every module
README to carry one, and it must say which of the three cases applies (see
`CONVENTIONS.md` §5 and the root `NOTICE` §0):

- clean-room from a public spec/RFC → no `NOTICE` entry, cite the spec here;
- a third-party implementation **studied** as a design reference → an entry in
  the root `NOTICE`, linked from here;
- third-party source actually **ported** → its terms in `modules/<name>/NOTICE`,
  beside the code that owes them, linked from here.

Provenance: TODO — clean-room from <spec>, no third-party source ported or
studied, so no `NOTICE` entry is required (root [`NOTICE`](../../NOTICE) §0).
