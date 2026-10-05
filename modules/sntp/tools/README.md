# `sntp` verification instruments

One oracle, run by hand; the raw replies are frozen in
`src/ntp_oracle_vectors.zig` and replayed by `src/ntp_oracle_test.zig` in the
module's own lane, with no server (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-sntp`: runs `ntp_oracle.py judge`, and is itself the client inside the namespace (`--live ADDR PORT VERSION TIMEOUT_MS`: `query`; `--raw ADDR PORT VERSION COUNT`: the codec path, every reply's bytes with T1/T4). Writes the vectors, or with `--check` compares their `//= ` verdict lines. |
| `ntp_oracle.py` | Starts a fresh chronyd per scenario in `unshare -rn` (stratum 3 and 10, unsynchronized, `ratelimit … kod 1`, `deny`), runs our client, beevik/ntp and ntplib, judges against the configuration. |
| `go_oracle/` | beevik/ntp v1.6.0 (BSD-2-Clause; pinned in `go.sum`): query a server, print its `Validate` verdict and kiss code. |

```bash
zig build interop-sntp              # re-take, write src/ntp_oracle_vectors.zig (~30 s)
zig build interop-sntp -- --check   # re-take, compare the verdicts
```

Needs python3, `unshare`, `ip`, go (beevik/ntp in the module cache,
`GOPROXY=off`), chronyd 4 and ntplib, OUTSIDE the repo (check-copyleft walks
anything inside it):

```bash
B=~/.local/share/zig-libs; mkdir -p $B/oracle-bin/deb && cd $B/oracle-bin/deb
apt-get download chrony && dpkg-deb -x chrony_*.deb $B/oracle-bin/chrony   # no root needed
python3 -m venv $B/oracle-venvs/ntplib && $B/oracle-venvs/ntplib/bin/pip install ntplib
```

(`ZIGLIBS_CHRONYD`, `ZIGLIBS_NTPLIB_PY` override the paths.) chronyd runs with
`-x` (never touches the clock), `cmdport 0`, port 11123, its own loopback; the
copy outside `/usr/sbin` is not under the distribution's AppArmor profile.
`--check` compares verdicts, not bytes: every reply carries the time.

**What the replay holds** (2026-10-05): 5 scenarios, no disagreement with the
configured server; one listed divergence — beevik/ntp calls an unsynchronized
server's LI=3 / stratum 0 / Reference ID 0 reply a Kiss-o'-Death, RFC 4330 §8
and RFC 5905 §7.4 do not (no kiss code), and neither does this module.
