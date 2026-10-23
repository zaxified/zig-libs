# `probe` verification instruments

| tool | role |
|---|---|
| `blackbox_probe/` | The evidence behind the card's `**Ahead:**` line: fetches Ubuntu's `prometheus-blackbox-exporter` package (`apt-get download`, unpacked under `.zig-cache/blackbox-probe`, no install, no root), runs it on 127.0.0.1:19115 with the tcp prober's defaults, and `probe.py` makes `localhost:P` dual-stack with `::1:P` a black hole (full accept queue) and `127.0.0.1:P` listening, then probes the name and, as the control, the IPv4 literal. |

```bash
modules/probe/tools/blackbox_probe/run.sh
```

Needs `apt-get`, `dpkg-deb`, `python3`, `curl`; loopback only, port 19115 free, and `localhost` resolving to `::1` for the exporter. Last run 2026-10-23, blackbox_exporter 0.26.0: `localhost:P` probe_success 0 (2.00 s), control 1.
