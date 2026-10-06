# `acme` verification instruments

| tool | role |
|---|---|
| `pebble.sh` | Starts Pebble (`-strict`, 15% of nonces rejected), pebble-challtestsrv (DNS, TXT records) and `pebble_helper`, runs `zig build interop-acme`, and writes `src/testdata/pebble_transcript.zig` (or, with `--check`, only gives the live verdict). |
| `interop.zig` | `zig build interop-acme -- --scratch DIR`: the real `Client` through six scenarios against Pebble; serves HTTP-01 on :5002 and the TLS-ALPN-01 material on :5003; verifies every chain to Pebble's root. |
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
