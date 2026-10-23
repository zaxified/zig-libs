# `acme` verification instruments

| tool | role |
|---|---|
| `pebble.sh` | Starts Pebble (`-strict`, 5% of nonces rejected), pebble-challtestsrv (DNS, TXT records) and `pebble_helper`, runs `zig build interop-acme`, and writes `src/testdata/pebble_transcript.zig` (or, with `--check`, only gives the live verdict). |
| `interop.zig` | `zig build interop-acme -- --scratch DIR`: the real `Client` through nine scenarios plus `lifecycle`, `steps` and `manager` (the `Manager` over `DirStorage`, `pebble.sh --check` only — not in the transcript) against Pebble; serves HTTP-01 on :5002 and the TLS-ALPN-01 material on :5003; verifies every chain to Pebble's root. |
| `gen_manager_fixtures.sh` | Regenerates `src/testdata/manager_fixtures.zig`: an openssl test CA and leaf certificates with fixed validity windows for the `Manager` tests (openssl ≥ 3.4). |
| `autocert_lead/` | The `**Ahead:**` probe (own tooling, Go): `golang.org/x/crypto/acme/autocert` v0.58.0 (BSD-3-Clause, read in full before it was built; `GOPROXY=off`, module cache only) against Pebble issuing 24-hour certificates — `fleet`: two Managers on one `DirCache`, one name, counts certificates issued; `renew`: `RenewBefore` 720 h, counts certificates issued in 10 s. `run.sh` starts Pebble + challtestsrv (ports 5001 5002 8053 8055 14000 15000). |
| `pebble_helper/` | Go, stdlib only: the recording TLS proxy in front of Pebble (:14001), the TLS-ALPN-01 listener (:5001), and the transcript → Zig generator. |

```bash
modules/acme/tools/pebble.sh            # live run + new transcript
modules/acme/tools/pebble.sh --check    # live run only
```

Needs `openssl`, `go`, and the Pebble binaries outside the repository (MPL-2.0, run as black
boxes, never vendored):

```bash
GOBIN=~/.local/share/zig-libs/oracle-bin/pebble go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
GOBIN=~/.local/share/zig-libs/oracle-bin/pebble go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@v2.10.1
```

Loopback only; fixed ports 5001 5002 5003 8053 8055 14000 14001 15000. A new transcript is not
byte-identical to the old one (Pebble draws its IDs, nonces and keys); the replay holds for any
transcript of a run in which all six scenarios came out as expected.

**What the replay holds** (2026-10-06, Pebble v2.10.1, go1.26.0): six scenarios, each served back
to the client from Pebble's recorded answers — the issued chain byte for byte, `badNonce`
rejections retried, the `connection` and `rejectedIdentifier` problems reported through
`lastProblem`.
