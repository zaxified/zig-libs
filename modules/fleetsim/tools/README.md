# `fleetsim` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test. Moved here on
2026-09-17 from a private `~/.cache` directory, where they were the only copy.

| file | produces | input |
|---|---|---|
| `gen-dnp3-goldens.py` | the DNP3 `Step` arrays in `src/master_goldens.zig` | the `FLEETSIM_CAPTURE_BEGIN/END` block of a `scripts/vm/run.sh fleetsim debian` run with the opendnp3 master |
| `gen-iec104-goldens.py` | the IEC 104 `Step` arrays in `src/master_goldens.zig` | the same, with `FLEETSIM_MASTERS=iec104` |

The masters themselves run only inside the disposable VM — see the header of
`src/master_goldens.zig`.
