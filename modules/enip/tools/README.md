# `enip` verification instruments

Not part of the module build (CONVENTIONS §9: foreign-implementation oracles live here).

| file | kind | what it answers |
|---|---|---|
| `pccc_serve.zig` + `pccc_oracle.py` | **differential oracle** (live) | Does a stock `pycomm3.SLCDriver` (1.2.16) read and write the adapter's PCCC data files (`N7`, `F8`, `T4`)? Build and run lines are in `pccc_serve.zig`'s header; `pccc_oracle.py` exits 0 only when every value is the served one and every write reads back. |
| `udt_serve.zig` + `udt_oracle.py` | **differential oracle** (live) | Does a stock `pycomm3.LogixDriver` (1.2.16, `pip install --user pycomm3`) browse the adapter's user-defined types? `udt_serve.zig` serves an `Adapter` with two types (one nested, one with an array member) on a loopback port; `udt_oracle.py` uploads the tag list, fetches the templates and reads the structures as named members, and exits 0 only when the decoded values are the served ones. Build and run lines are in the two files' headers. |
