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

`gen_goldens_ext.py` is the same recipe for the opt-in features
(`src/testdata/goldens_ext.zig`, checked by `src/oracle_ext_test.zig`): inline
comments, `ConfigParser()`'s defaults with `[DEFAULT]` and the bytes of `write()`,
`allow_no_value`, Basic and Extended interpolation, `int`/`float`/`getboolean`,
and GKeyFile's string lists, locale strings and escapes.

    python3 modules/ini/tools/gen_goldens_ext.py > modules/ini/src/testdata/goldens_ext.zig

`writer_oracle.py` is the live half: the two references read back what our
writers wrote, including an `Editor` session (its docstring has the commands).

`bench.zig` is `zig build bench-ini`, the program behind the card's
`**Performance:**` line. Its other sides are `go_bench` (go-ini, Apache-2.0),
`rust_bench` (`configparser` crate, MIT OR LGPL, taken as MIT; `ini_core`, MIT;
`cfg-if`, MIT OR Apache-2.0) and `c_bench.c` (inih, BSD-3-Clause), all pinned and
read whole before the first compile. They come from the Go and cargo module
caches; the header of `bench.zig` has the fetch commands.
