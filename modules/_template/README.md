# _template

Copy this folder to `modules/<name>/`, then:

1. Fill in `src/root.zig` (`meta` block + public API + tests).
2. Register `.{ .name = "<name>", .deps = &.{...} }` in the root `build.zig`.
3. `zig build test-<name>`.

Document here: **what it is**, **status** (extract/gap/adopt), **model-after**
(the other-language reference), and the **seed** location if extracting from an
existing project.
