# SPDX-License-Identifier: MIT
"""Python side of `zig build bench-mcp` (modules/mcp/tools/bench.zig): times the
official MCP Python SDK (the version printed on stderr), used through its public
API only (`mcp.server.MCPServer` and its stdio runner), over the session bytes
the Zig program writes into the directory given as the first argument, for the
one workload named by the second. Prints one line: name, ns/op, result count
(tab-separated), like tools/go_bench.

One op = one whole session (`initialize`, `notifications/initialized`, then 64
requests of one kind) read from an in-memory text stream by the SDK's stdio
server (`run_stdio_async`, with `stdio_server` handed in-memory streams: the same
framing code, no process pipes), the responses collected in memory. Python
startup and import time are outside the timed region. Timing matches the Zig and
Go sides: double the batch until it takes over 100 ms, then the best of three (Python sessions are slow; the other sides take five).

Count = response lines + `"isError":true` occurrences (the sides order fields
differently, so bytes are not compared). A session whose output holds a JSON-RPC
error is refused.

    V=~/.local/share/zig-libs/oracle-venvs/mcp
    python3 -m venv $V && $V/bin/pip install mcp
"""
import asyncio
import io
import os
import re
import sys
import time
from importlib.metadata import version
from typing import TypedDict

import anyio
import mcp.server.stdio as stdio_mod
from mcp.server import MCPServer

NAMES = ["tools_call_echo", "tools_list_20", "resources_read", "prompts_get", "initialize_only"]


class EchoOut(TypedDict):
    echo: str


def server_for(name):
    s = MCPServer("bench", version="1.0.0", log_level="CRITICAL")
    if name == "tools_call_echo":

        @s.tool(name="echo", description="Echo the text back")
        def echo(text: str) -> EchoOut:
            return {"echo": text}

    elif name == "tools_list_20":
        for i in range(20):

            def make(i):
                def f(a: str, b: int = 0) -> str:
                    return "ok"

                return f

            s.add_tool(make(i), name=f"tool_{i:02d}", description=f"Small tool number {i}")
    elif name == "resources_read":
        text = "0123456789abcdef" * 64

        @s.resource("file:///doc.txt", name="doc", mime_type="text/plain")
        def doc() -> str:
            return text

    elif name == "prompts_get":

        @s.prompt(name="greet", description="Greet someone")
        def greet(name: str) -> str:
            return f"Hello, {name}!"

    elif name != "initialize_only":
        sys.exit(f"unknown workload {name}")
    return s


class Feed:
    """The session's stdin: the request lines, then EOF only once every request has
    been answered (what a client waiting for its answers does; the Go side does the
    same), because the SDK abandons requests still in flight when its reader ends."""

    def __init__(self, wire, out):
        self.lines = wire.splitlines(keepends=True)
        self.want = sum(1 for l in self.lines if '"id"' in l)
        self.out = out

    def __aiter__(self):
        return self._gen()

    async def _gen(self):
        for l in self.lines:
            yield l
        deadline = time.perf_counter() + 30
        while self.out.getvalue().count("\n") < self.want:
            if time.perf_counter() > deadline:
                sys.exit("mcp (python): the session did not answer every request")
            await anyio.sleep(0)

    async def aclose(self):
        pass


async def one_session(server, wire):
    out = io.StringIO()
    stdin = Feed(wire, out)
    stdout = anyio.wrap_file(out)
    real = stdio_mod.stdio_server
    # `run_stdio_async` finds `stdio_server` in its own module; patch where it is looked up.
    for mod in patched:
        setattr(mod, "stdio_server", lambda *a, **k: real(stdin, stdout))
    try:
        await server.run_stdio_async()
    finally:
        for mod in patched:
            setattr(mod, "stdio_server", real)
    resp = out.getvalue()
    if '"error":{' in resp:
        sys.exit("mcp (python) answered a JSON-RPC error: " + resp[:300])
    return resp.count("\n") + len(re.findall(r'"isError":\s*true', resp))


patched = []


def find_patch_targets(server):
    import inspect

    m = inspect.getmodule(type(server).run_stdio_async)
    patched.append(m)
    if stdio_mod not in patched:
        patched.append(stdio_mod)


def time_it(loop, f):
    n = 1
    while True:
        t = time.perf_counter()
        for _ in range(n):
            loop.run_until_complete(f())
        if time.perf_counter() - t > 0.1:
            break
        n *= 2
    best = float("inf")
    count = 0
    for _ in range(3):
        t = time.perf_counter()
        for _ in range(n):
            count = loop.run_until_complete(f())
        d = time.perf_counter() - t
        best = min(best, d)
    return best / n * 1e9, count


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: main.py <work dir> <workload>")
    d, name = sys.argv[1], sys.argv[2]
    if name not in NAMES:
        sys.exit(f"unknown workload {name}")
    with open(os.path.join(d, name + ".wire"), encoding="utf-8") as fh:
        wire = fh.read()
    sys.stderr.write(f"modelcontextprotocol python-sdk (mcp) {version('mcp')}\n")
    s = server_for(name)
    find_patch_targets(s)
    loop = asyncio.new_event_loop()
    ns, count = time_it(loop, lambda: one_session(s, wire))
    print(f"{name}\t{ns:.0f}\t{count}")


main()
