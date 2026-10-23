#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Lead probe (maturity card `**Ahead:**` line): FastAPI drops a reachable route
from its document when two routes share one (path template, method).

Runs in FastAPI's own virtualenv (tools/README.md), FastAPI as a black box:

    ~/.local/share/zig-libs/oracle-venvs/fastapi/bin/python tools/fastapi_lead/probe.py

Registers GET /f/{p} and GET /f/{p:path} -- the Starlette spelling of this
module's router patterns `/f/:p` and `/f/*p` -- dispatches /f/a and /f/a/b
through the ASGI app itself (no HTTP client needed) to show both routes answer,
then prints the operations FastAPI's own document lists under /f/{p}.
`get_openapi` merges path items with `paths.setdefault(path_format,
{}).update(path)`, so the second GET replaces the first without a warning.
Here `Generator.build` refuses the same table with `error.PathCollision`
(test "generate: /f/:p and /f/*p collide too (F5)").
"""
import asyncio
import json
import warnings

import fastapi
from fastapi import FastAPI

app = FastAPI(title="T", version="1")


@app.get("/f/{p}", summary="param")
def by_param(p: str):
    return {"route": "param"}


@app.get("/f/{p:path}", summary="wildcard")
def by_wildcard(p: str):
    return {"route": "wildcard"}


async def call(path):
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "GET", "scheme": "http", "path": path, "raw_path": path.encode(),
        "root_path": "", "query_string": b"", "headers": [],
        "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 1),
    }
    out = {"status": None, "body": b""}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
        elif msg["type"] == "http.response.body":
            out["body"] += msg.get("body", b"")

    await app(scope, receive, send)
    return out["status"], json.loads(out["body"])


def main():
    print("fastapi", fastapi.__version__)
    for path in ("/f/a", "/f/a/b"):
        status, body = asyncio.run(call(path))
        print(f"GET {path} -> {status} {body}")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        doc = app.openapi()
    item = doc["paths"]["/f/{p}"]
    ops = {m: op["summary"] for m, op in item.items()}
    print("document /f/{p}:", ops)
    print("paths in document:", sorted(doc["paths"]))
    print("warnings:", [str(w.message) for w in caught])


if __name__ == "__main__":
    main()
