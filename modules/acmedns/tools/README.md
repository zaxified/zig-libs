# `acmedns` verification instruments

| tool | role |
|---|---|
| `interop.sh` | Starts `peer.py` and Pebble (`-strict`, `-dnsserver` = the peer's DNS server), then `zig build interop-acmedns`. Builds, so run it under `hw run`. |
| `interop.zig` | `zig build interop-acmedns -- --scratch DIR --dns-port N --http-port N --exec PATH`: the zone questions, then one Pebble issuance per publisher and the failure scenarios (see its header). |
| `peer.py` | One process: the authoritative DNS server with RFC 2136 + TSIG from `modules/dns/tools/update_server.py` (zones example.org and delegated.test), an acme-dns API stand-in (`/register`, `/update`, from joohoi/acme-dns's README), and an httpreq endpoint (default and `/raw`, basic auth). |
| `exec_nsupdate.sh` | The program the `Exec` publisher runs: lego's exec protocol, implemented with BIND's `nsupdate`. |

```bash
hw run -- modules/acmedns/tools/interop.sh
```

Needs python3 + dnspython, `nsupdate` (bind9-dnsutils), openssl, curl, and the Pebble binary (MPL-2.0,
run as a black box, never vendored):

```bash
GOBIN=~/.local/share/zig-libs/oracle-bin/pebble go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
```

Loopback only. Pebble listens on its fixed ports 14000 and 15000, so this cannot run beside
`modules/acme/tools/pebble.sh`; the peer takes free ports and writes them to
`.zig-cache/interop-acmedns/ports`.

Last run 2026-10-16 (Pebble v2.10.1, dnspython 2.8.0): 48 checks, 0 failures. On the way it found
that a `std.Io.Threaded` built without `.environ` spawns children with an empty environment (the
`Exec` hook saw no variables) — documented on `Exec.Options`.
