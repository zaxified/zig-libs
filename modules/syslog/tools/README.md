# `syslog` verification instruments

One differential oracle, run by hand; its answers are frozen in
`src/rsyslog_oracle_vectors.zig` and replayed by `src/rsyslog_oracle_test.zig`
and the last test in `src/unix.zig`, in the module's own lane, with no daemon
(`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-syslog`: has `rsyslog_oracle.py gen` draw cases, encodes each (`buildDatagram`, `writeOctetCounted`, `bsd.bufPrint`), catches what `UnixEmitter` and `journal.Emitter` put on a socket of its own, records `validFieldName`'s verdicts, has `rsyslog_oracle.py judge` judge them, and writes (or with `--check` compares) the vectors. |
| `rsyslog_oracle.py` | `gen`: every PRI, timestamps at and past every edge, every byte class in every header field, hostile SD names and values, MSG shapes, RFC 3164 lines, journal field sets and field-name probes. `judge`: rsyslogd and systemd-journald receive them; each parsed field must be what the message meant. |

```bash
zig build interop-syslog              # re-take, write src/rsyslog_oracle_vectors.zig
zig build interop-syslog -- --check   # re-take, compare with the committed file
```

Needs python3, rsyslogd 8 (imudp, imtcp, mmpstrucdata), systemd-journald +
journalctl, `unshare` and `ip`; no root, no network.

- **rsyslogd** runs from a copy under `.zig-cache/interop-syslog/`: the
  distribution's AppArmor profile attaches to `/usr/sbin/rsyslogd` by path,
  confines config and output to `/etc` and `/var/log`, and refuses signals
  from a confined shell (the daemon could not even be stopped). The copy is
  unconfined, reads a throwaway config, listens on loopback in `unshare -rn`.
- **systemd-journald** runs in `unshare -rm` with a tmpfs over `/run` and
  `/run/log/journal` bound to the scratch directory; `journalctl -D` reads
  what it stored. Native datagrams get an `ORACLE_CASE` field appended (the
  protocol is a run of fields) to pair records with cases.

**What the replay holds** (2026-10-05, rsyslogd 8.2512.0, systemd 259): 617
cases, none where a daemon read back something other than what the message
meant. Receiver policies taken as observed, not as our defects: rsyslogd turns
NUL into `#000`, keeps the last of a repeated SD-ID or PARAM-NAME in
mmpstrucdata's JSON, refuses an RFC 5424 year ≥ 2100 (`RSYSLOGD_YEAR_2100`,
listed divergence); journald reads no RFC 5424 on dev-log, strips trailing
whitespace and cuts MESSAGE at a NUL there, and keeps SYSLOG_PID only for a
positive number.
