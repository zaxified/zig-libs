# SPDX-License-Identifier: MIT
"""Python side of mcp-http's HTTP benchmark (tools/http_bench/run.sh): the
official MCP Python SDK (the reference; public API only: `MCPServer` and its
`streamable_http_app`, stateless with JSON responses) under uvicorn on
127.0.0.1:<port>, serving the bench catalog: tool "echo" with a typed result
and 20 small tools (the same catalog as go/main.go and server.zig).

    V=~/.local/share/zig-libs/oracle-venvs/mcp   # mcp==2.3.0, uvicorn
    $V/bin/python -I tools/http_bench/py_server.py <port>
"""
import sys
from typing import TypedDict

import uvicorn
from mcp.server import MCPServer


class EchoOut(TypedDict):
    echo: str


def build():
    s = MCPServer("bench", version="1.0.0", log_level="CRITICAL")

    @s.tool(name="echo", description="Echo the text back")
    def echo(text: str) -> EchoOut:
        return {"echo": text}

    for i in range(20):

        def make():
            def f(a: str, b: int = 0) -> str:
                return "ok"

            return f

        s.add_tool(make(), name=f"tool_{i:02d}", description=f"Small tool number {i}")
    return s


def main():
    port = int(sys.argv[1])
    app = build().streamable_http_app(stateless_http=True, json_response=True)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="critical", access_log=False)


if __name__ == "__main__":
    main()
