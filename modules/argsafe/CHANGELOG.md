# argsafe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — **Tests:** mutation run (40 schemata mutants, all killed after one new table
  test of documented predicate edges: DEL handling, `allow_alnum = false`, length caps, charsets).
  No code change.

- **2026-09-28** — New `Template`/`Hole`/`Filled`/`Refusal`/`FillOutcome` and
  `CharClass.explain`/`CharClass.Reason`, requested by ttydesk (2026-09-27): an
  argv shape from a **trusted config** (`["systemctl", "restart", "{unit}"]`)
  with named `{name}` holes filled from **untrusted** run-time values, each
  checked against its own `Hole.class` — the same `CharClass.check` rules
  `Argv.pushChecked` already enforces, so a templated value is held to
  exactly the same rules as a hand-built `Argv`. `Template.parse(tokens,
  holes)` validates up front and fails closed on a config error (unknown hole
  name, a hole in `argv[0]`, unbalanced `{`/`}`, or two holes sharing a name);
  `Template.fill(gpa, values)` returns either a `Filled` (owns its argv in one
  arena, freed by `Filled.deinit`) or a `Refusal{ hole, why: CharClass.Reason
  }` naming which hole and why. `CharClass.check` is now `explain(s) == null`
  rather than a separate hand-written copy of the same rules, so `explain`
  and `check` cannot drift apart. Literal `{`/`}` in a token is written
  doubled (`{{`/`}}`), matching `std.fmt`/`str.format`'s convention. Lets
  ttydesk (`src/actions.zig`, marked `zig-libs request: argsafe — argv
  template`) delete its own hand-rolled `reason()`/`fill()`. Purely additive
  — no existing predicate, `Argv` method, or `CharClass` field changed
  behavior. `fill` returns `error.ValueCountMismatch` (a `FillError`) when `values` does not match the holes.

- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on Python
  `shlex.quote`/`subprocess` list-argv, Go `exec.Command` (argv array), Rust
  `std::process::Command` (design reference, not a test anchor).
- **2026-07-09** — New module: Allowlist validators + a typed argv builder — neutralizes
  argument/flag injection into an exec `argv`.
