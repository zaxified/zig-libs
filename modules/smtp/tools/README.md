# `smtp` verification instruments

One instrument, run by hand. It is not wired into `zig build`: a row costs a
full build plus the module's ~137 tests, which is far more than a test lane
should carry (`CONVENTIONS.md` §9).

Figures below were measured on 2026-09-17 against the tree as it stands.

## Would the suite notice if a guard were removed?

    modules/smtp/tools/mutate.py             # the whole table
    modules/smtp/tools/mutate.py M8 M13      # only those rows
    modules/smtp/tools/mutate.py --controls  # only the two positive controls
    MUT_OPT=ReleaseFast modules/smtp/tools/mutate.py M6   # see the mode note

14 mutations and 2 positive controls, each copying the live
`modules/smtp/src/*.zig` into a per-process scratch tree.

Measured in the default (Debug) mode: **16 rows, 12 RED, 4 GREEN, 0 BROKEN,
0 anchor problems.** One green is the `PC-ok` control.

### ⚠ The optimize mode is part of the verdict

Three guards in this module are pinned by tests that **skip** unless the build
is ReleaseFast, or unless an environment variable is set. Run in Debug and
those rows come back GREEN — not because the suite is blind, but because the
test that watches them never ran. Re-measured with
`MUT_OPT=ReleaseFast SMTP_BENCH_F1=1`:

| mutant | guard | Debug | ReleaseFast |
|---|---|---|---|
| `M6` | `auth.zig`'s `secureZero` of the decoded credential | GREEN | **RED** |
| `M12` | the amortisation in `reply.Parser.compact` | GREEN | **GREEN** |
| `M13` | `session.zig`'s wipe of the command buffer | GREEN | **GREEN** |

So of the three, only `M6` is explained by a skipped test —
`session.zig`'s *"F5 (ReleaseFast only): plaintext password does not survive on
the dead stack after AUTH"*, whose first line is
`if (builtin.mode != .ReleaseFast) return error.SkipZigTest;`.

**`M12` and `M13` survive in both modes, and those are the real holes:**

- `M12` — the quadratic `compact()` (audit F1) can be reintroduced and nothing
  fails, *including* `reply.zig`'s opt-in `SMTP_BENCH_F1` bench, which was run
  with the variable set. A bench that is skipped by default and does not fail
  when the regression returns is not a pin.
- `M13` — the command buffer holding a plaintext `AUTH` line can stop being
  zeroed with a green suite in either mode. The F5 test watches the *stack*
  after AUTH, not `self.out`.

The table's pinned verdicts are the **Debug** ones, because that is what the
runner uses by default; `M6` carries its ReleaseFast result in a comment beside
the row, and the runner reports a pin mismatch rather than quietly accepting
either answer.

### The four ways a row can end, and why that distinction was earned

`GREEN` (the suite passed), `RED` (it failed), `BROKEN` (the mutant did not
compile), and within RED a **PANIC** is called by name. Five rows here go RED
by aborting at runtime (`M1`, `M3`, `M4`, `M10`, `M11b`); the first version of
this runner printed all of them as `compile: error: … signal ABRT`, which is
backwards — a test binary that aborts has compiled *and run*, which is a
stronger result than a compile error, not a weaker one. And a mutant that truly
fails to build is not a caught mutation at all: nothing ran, so scoring it RED
would claim the suite noticed something it never saw.

## Two defects in the shell runner this replaces

Both were found by reading it, not by trusting its output:

- **`M11_no_boundary_collision_check` had no `run_one` in front of it.** The
  edit sat in the file as a bare shell string, was expanded, and was discarded.
  The row looked present in the source and **never ran once**. It is restored
  here as `M11b`'s sibling anchor and still matches the live source exactly
  once — and it comes back RED.
- **`M15_stuffer_dot_free` replaced a string with itself.** Its diff-verify
  caught that and printed "MUTATION DID NOT LAND", so it never lied; it simply
  never measured. It is left out rather than ported as a row that can only
  report its own inertness.

And the shell runner had **no exit code**: every row echoed and the process
returned 0 whatever the table said.

## What was deliberately not brought over

`.zig-cache/audit-smtp` (617 MB) held the runner, its own `build.zig`, seven
probes, a `smith_probe.zig`, and three full copies of the module. The copies
had rotted 58–337 lines behind `src/` per file. Every probe's finding is now
closed **and pinned by a test that names it**, so none came over:

- `smuggle.zig` → `data.zig:427` *"SMTP smuggling: only CRLF.CRLF terminates
  the data"*, plus `data.zig:387` for F2.
- `inject.zig` → `message.zig:887` *"F4: MIME parameter injection through
  subtype, charset or content_type"*, `mime.zig:804` *"F4 regression"*,
  `command.zig:405` *"command injection: CR/LF/NUL in any argument is refused"*.
- `starttls.zig` → `client.zig:484` (F3, recorded as a documented gap) and
  `session.zig:1017` (F9).
- `authstack.zig` → became `session.zig:1231`, the F5 dead-stack test, the same
  way `paillier`'s stack probe became a test in its module.
- `fidelity.zig` → `session.zig:1373` *"SIZE counts the body as sent, not as
  given (A1 F6)"*.
- `harness_reach.zig`, `smith_probe.zig` → spent: the `Smith.bytes` +
  ranged-draw trap (F11) is fixed, `smith.slice` in `reply`, `capabilities`,
  `auth` and `mime`.
- `perf.zig` → its question lives on as `reply.zig:545`'s opt-in bench, though
  see `M12` above for what that bench does *not* catch.
