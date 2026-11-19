# `modbus` verification instruments

**STATUS: `oracle.py` has NOT YET BEEN RUN.** It was written against the pymodbus 3.16.2 source read as text; the wheel is not installed and nothing of pymodbus has executed (owner approval pending). Its API calls, the vectors file `src/oracle_vectors.zig` and the replay test `src/oracle_test.zig` do not exist yet, so nothing below counts as verification until a run has produced them.

| tool | role |
|---|---|
| `oracle.py` | `python3 -I tools/oracle.py gen src/oracle_vectors.zig`: drives pymodbus 3.16.2 (BSD-3) IN PROCESS (its PDU encoders, its server-side `datastore_update` for FC 0x16 and FC 0x2B/0x0E, its RTU framer `buildFrame`) and writes what it says as Zig vectors. No socket, no server, no network. |

Once run, `src/oracle_test.zig` (to be added) replays the frozen `src/oracle_vectors.zig` in the module's
own lane with no Python (`CONVENTIONS.md` §9: the recipe for committed vectors and a
differential oracle driving a foreign implementation). Every expected byte is
pymodbus's; nothing is seeded from this module.

## Running it (pinned, hash-checked, offline)

pymodbus is foreign code, so it is installed only from a checked wheel and run
without a network:

```sh
# 1. fetch the wheel only: no dependencies, no build step
python3 -I -m pip download --no-deps --only-binary :all: pymodbus==3.16.2 -d dl
# 2. compare with the published hash (https://pypi.org/pypi/pymodbus/3.16.2/json)
echo "385ad145955a7af15020ee55c266f7a2c6d9af2180d45c3755a56db9a5014078  dl/pymodbus-3.16.2-py3-none-any.whl" | sha256sum -c
# 3. install into a throwaway venv from that file (pure Python, no mandatory dependencies)
python3 -m venv venv && venv/bin/pip install --no-deps --no-index dl/pymodbus-3.16.2-py3-none-any.whl
# 4. run with no network
unshare -rn venv/bin/python3 -I modules/modbus/tools/oracle.py gen modules/modbus/src/oracle_vectors.zig
```

Pinned: pymodbus 3.16.2, wheel sha256
`385ad145955a7af15020ee55c266f7a2c6d9af2180d45c3755a56db9a5014078`. The script
refuses any other version. The wheel was inspected as text, without running it
(2026-11-19): pure Python, no `.pth`, no import-time side effects on the path used
(`pymodbus.pdu`, `pymodbus.framer`, `pymodbus.constants`), no subprocess, `eval`,
`exec`, `ctypes` or base64 blobs; its socket and ssl uses sit in transport code
this tool never starts.

## What the replay holds

Nothing yet (not run).
