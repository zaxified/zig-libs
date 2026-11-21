# `coap` verification instruments

| tool | question it answers |
|---|---|
| `capture_goldens.py` | How were the datagrams of `src/external_goldens.zig` taken, and does a fresh capture from the same real `aiocoap` 0.4.17 endpoints agree with them? Run it with `.venv/bin/python capture_goldens.py --out DIR --compare ../src/external_goldens.zig`; the venv is created without root (`python3 -m venv .venv && .venv/bin/pip install aiocoap==0.4.17`) and ignores itself. Message IDs and tokens are random per run, so `--compare` checks options and payloads, not those fields. Last run 2026-11-21: hello and Block2 block 0 same. |

aiocoap is a black-box peer (root `NOTICE` §0); no source of it is read.
