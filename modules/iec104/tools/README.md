# `iec104` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test. Moved here on
2026-09-17 from a private `~/.cache` directory, where they were the only copy.

All three need Python with `c104` 2.2.1 (Fraunhofer FIT, over `lib60870-C`).

| file | produces |
|---|---|
| `global_ca_capture.py` | JSON of what a real c104 controlled station answers to the GLOBAL common address, via a recording proxy — source of `src/goldens.zig` |
| `global_ca_capture2.py` | the same with TWO controlled stations (CA 47 and 99) behind one server, so a global-address request fans out |
| `live_global_ca_master.py` | drives THIS module's outstation with a real c104 master on CA 0xFFFF (`<port>` argument) |
