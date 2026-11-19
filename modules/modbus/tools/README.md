# `modbus` verification instruments

**Last run 2026-11-19** (pymodbus 3.16.2, offline under `unshare -rn`): 50 FC 0x16 cases, 618 FC 0x2B/0x0E cases over 8 object tables, 6 RTU streams; frozen in `src/oracle_vectors.zig`, replayed by `src/oracle_test.zig`.

| tool | role |
|---|---|
| `oracle.py` | `python3 -I tools/oracle.py gen src/oracle_vectors.zig`: drives pymodbus 3.16.2 (BSD-3) IN PROCESS (its PDU encoders, its server-side `datastore_update` for FC 0x16 and FC 0x2B/0x0E, its RTU framer `buildFrame`) and writes what it says as Zig vectors. No socket, no server, no network. |

`src/oracle_test.zig` replays the frozen `src/oracle_vectors.zig` in the module's
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

- **FC 0x16:** every request, response and register value equals pymodbus's (spec 6.16 example plus edge and random masks; a register outside the window gives pymodbus's `IllegalDataAddress`).
- **FC 0x2B/0x0E:** every response equals pymodbus's byte for byte, except three departures where pymodbus differs from the spec text (V1.1b3 6.21) and the module follows the spec. Each has its own exact count in the test, so a new difference fails it:
  - the conformity byte: pymodbus always sends 0x83; the spec defines it as the device's own level, which the test computes from the table;
  - restart (168 cases): a stream request whose object id is no known object of that walk restarts at object 0 (spec: "restart at the beginning"); pymodbus answers an empty list;
  - an object longer than any response (3 cases): `ServerDeviceFailure`; pymodbus answers more-follows with the same object as next id and no objects, which a client follows forever.
- **RtuStream:** pymodbus-built RTU frames for both roles, back to back, with garbage between and with a broken CRC, come out as the same unit + PDU sequence. The expected bytes are cut from the frame `buildFrame` returned: pymodbus 3.16.2's device-identification response adds to its object count on every `x_encode`, so encoding it a second time gives a wrong count.
