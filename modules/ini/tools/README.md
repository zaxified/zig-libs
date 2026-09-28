# ini — tools

`gen_goldens.py` is the recipe for `src/testdata/goldens.zig`, the module's
external anchor (`CONVENTIONS.md` §9). It runs a fixed probe list and 900
seeded random INI-shaped texts through two foreign implementations and records
what each made of every text:

- **CPython `configparser`** (`RawConfigParser`, default delimiters, `#`/`;`
  comments, `strict=False`, `empty_lines_in_values=False`, `optionxform=str`) —
  the anchor for `Options.python`. PSF licence.
- **GLib `GKeyFile`** through PyGObject (`load_from_data`, `get_value`) — the
  anchor for `Options.desktop`. **LGPL**: it is only ever *run* as a black box.
  Its source must not be read while working on this module — the same rule as
  `modules/uci/tools/` for libuci. Every rule in `SPEC.md` that cites GKeyFile
  cites a measured behaviour, not code.

Needs: `python3` with `gi` (PyGObject) and GLib 2.x (Debian/Ubuntu:
`python3-gi`). Run from the repository root:

    python3 modules/ini/tools/gen_goldens.py > modules/ini/src/testdata/goldens.zig

The corpus is seeded, so the output only changes when an oracle's behaviour
does; the header of the generated file records the versions used.
`src/oracle_test.zig` pins the number of cases and how many each reference
refused, so a regenerated corpus that lost its accept or refuse half fails.
