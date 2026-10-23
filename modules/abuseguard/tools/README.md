# `abuseguard` verification instruments

| tool | role |
|---|---|
| `nginx_probe/` | The evidence behind the card's `**Ahead:**` line: runs Ubuntu's nginx package (fetched with `apt-get download`, unpacked under `.zig-cache/nginx-probe`, no install, no root) on 127.0.0.1:18431 with `limit_conn perip 1`, then `probe.py` — a control (a second request while one is served: 503) and the slowloris shape (20 sockets parked on an unfinished header, then a full request: 200). |

```bash
modules/abuseguard/tools/nginx_probe/run.sh
```

Needs `apt-get`, `dpkg-deb`, `python3`; loopback only, port 18431 must be free.
Last run 2026-10-23, nginx 1.28.3-2ubuntu1.11: control 503, parked sockets 200.
