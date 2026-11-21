# `acmedns` verification instruments

| tool | role |
|---|---|
| `interop.sh` | Starts `peer.py` and Pebble (`-strict`, `-dnsserver` = the peer's DNS server), then `zig build interop-acmedns`. Builds, so run it under `hw run`. |
| `interop.zig` | `zig build interop-acmedns -- --scratch DIR --dns-port N --http-port N --exec PATH`: the zone questions, then one Pebble issuance per publisher and the failure scenarios (see its header). |
| `peer.py` | One process: the authoritative DNS server with RFC 2136 + TSIG from `modules/dns/tools/update_server.py` (zones example.org and delegated.test), an acme-dns API stand-in (`/register`, `/update`, from joohoi/acme-dns's README), and an httpreq endpoint (default and `/raw`, basic auth). |
| `real_acmedns.sh` | Starts the REAL joohoi/acme-dns server (Go, MIT; binary in `$ACMEDNS_BIN`, built once with `go install github.com/joohoi/acme-dns@master`, a pure-Go SQLite) with its own DNS listener for `auth.delegated.test`, then `zig build interop-acmedns -- --real-api URL --real-dns N --scratch DIR` (`realAcmeDns` in `interop.zig`): `AcmeDns.Store.register`, three updates (the server keeps the two newest, its DNS answers them), a wrong key and another account's subdomain refused, the account file round trip, `Dns01Solver` end to end against that DNS listener. Run under `hw run`. |
| `exec_nsupdate.sh` | The program the `Exec` publisher runs: lego's exec protocol, implemented with BIND's `nsupdate`. |

```bash
hw run -- modules/acmedns/tools/interop.sh
```

Needs python3 + dnspython, `nsupdate` (bind9-dnsutils), openssl, curl, and the Pebble binary (MPL-2.0,
run as a black box, never vendored):

```bash
GOBIN=~/.local/share/zig-libs/oracle-bin/pebble go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
```

The real acme-dns server (for `real_acmedns.sh`; MIT, run as a black box):

```bash
GOBIN=~/.local/share/zig-libs/oracle-bin/acme-dns go install github.com/joohoi/acme-dns@master
```

Its database runs with a memory journal (`journal_mode(MEMORY)`): the default journal mode failed with
`disk I/O error (5898)` on this machine's filesystem. Last run 2026-11-21 (acme-dns `master`, 9 checks, 0 failures).

Loopback only. Pebble listens on its fixed ports 14000 and 15000, so this cannot run beside
`modules/acme/tools/pebble.sh`; the peer takes free ports and writes them to
`.zig-cache/interop-acmedns/ports`.

Last run 2026-10-16 (Pebble v2.10.1, dnspython 2.8.0): 48 checks, 0 failures. On the way it found
that a `std.Io.Threaded` built without `.environ` spawns children with an empty environment (the
`Exec` hook saw no variables) — documented on `Exec.Options`.
