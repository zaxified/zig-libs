# `argsafe` verification instruments

| tool | role |
|---|---|
| `oracle.py` | `python3 -I tools/oracle.py gen src/oracle_vectors.zig`: builds a seeded corpus (hostile bytes, edge lengths, mutations of valid shapes) and records what real parsers say about each string. About 10 s. |
| `go_oracle/` | go-playground/validator v10.30.5 (MIT) `hostname_rfc1123` and the port half of `hostname_port`; run by `oracle.py` with `GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off`; needs go 1.26 and the module in the module cache. |

Foreign verdicts per string: POSIX sh (Python `shlex.split` and `dash -c 'set -- S'` in a
directory with files `a Z 0 x`, empty PATH), the UCRT command-line rules (transcribed, not a
Windows run), the Go validators, and the kernel (`SIOCSIFNAME` on a dummy link inside
`unshare -rn`; EEXIST counts as a valid name). Needs python3, dash, ip, unshare; no root.
`src/oracle_test.zig` replays the frozen vectors in the module lane with none of that.
Both files are kept under `CONVENTIONS.md` §9: the recipe for committed vectors and a
differential oracle driving foreign implementations.
