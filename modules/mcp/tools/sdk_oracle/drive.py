# SPDX-License-Identifier: MIT
"""Differential oracle for modules/mcp: the official MCP Python SDK (run as a
black box, its source not read -- the SDKs are mid-relicensing, see SPEC
"Compared with") drives `server.zig` over stdio, once per protocol era:

  * session: `initialize` (the SDK's own handshake), then every method;
  * stateless 2026-07-28: `server/discover` (`ClientSession.discover`), then
    the same methods, plus a multi round-trip tool answered through the SDK's
    elicitation callback.

Every result is parsed by the SDK's typed models; each is checked here
against what the server was registered to answer. Only when every check
passes is the transcript -- the exact lines the SDK sent and the exact lines
the server answered -- written as `src/sdk_oracle_vectors.zig`, which
`src/sdk_oracle.zig` replays through `Server.handleMessage` byte for byte.

    V=~/.local/share/zig-libs/oracle-venvs/mcp
    python3 -m venv $V && $V/bin/pip install mcp
    $V/bin/python modules/mcp/tools/sdk_oracle/drive.py      # from the repo root
"""
import asyncio
import os
import subprocess
import sys
from importlib.metadata import version

import mcp.types as t
from mcp import ClientSession, MCPError, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = os.getcwd()
WORK = os.path.join(ROOT, ".zig-cache", "sdk-oracle")
BIN = os.path.join(WORK, "server")
OUT = os.path.join(ROOT, "modules", "mcp", "src", "sdk_oracle_vectors.zig")

checks = []


def check(era, what, ok, detail=""):
    checks.append((era, what, ok))
    if not ok:
        print(f"FAIL {era} {what}: {detail}", file=sys.stderr)


def text_of(res):
    return "".join(c.text for c in res.content if getattr(c, "type", "") == "text")


async def elicit(ctx, params):
    return t.ElicitResult(action="accept", content={"name": "Ada"})


async def run_era(era):
    req, resp = os.path.join(WORK, f"{era}.req"), os.path.join(WORK, f"{era}.resp")
    for p in (req, resp):
        open(p, "wb").close()
    params = StdioServerParameters(command="sh", args=["-c", f"tee -a {req} | {BIN} | tee -a {resp}"])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w, elicitation_callback=elicit) as s:
            if era == "session":
                init = await s.initialize()
                check(era, "initialize", init.server_info.name == "oracle-srv" and init.instructions == "SDK oracle", init)
            else:
                disc = await s.discover()
                check(era, "discover", "2026-07-28" in (disc.supported_versions or []), disc)

            tools = await s.list_tools()
            names = [x.name for x in tools.tools]
            check(era, "tools/list", names == ["echo", "broken", "add", "greet"], names)
            add = next(x for x in tools.tools if x.name == "add")
            check(era, "tools/list add", add.output_schema is not None and add.annotations.read_only_hint is True and add.title == "Adder", add)

            res = await s.call_tool("echo", {"text": "hi č"})
            check(era, "echo", text_of(res) == "hi č" and not res.is_error, res)
            res = await s.call_tool("echo", {})
            check(era, "echo missing arg", res.is_error, res)
            res = await s.call_tool("broken", {})
            check(era, "broken", res.is_error and "always fails" in text_of(res), res)
            res = await s.call_tool("add", {"a": 2, "b": 40})
            check(era, "add", res.structured_content == {"sum": 42} and not res.is_error, res)
            try:
                await s.validate_tool_result("add", res)
                check(era, "add validates", True)
            except Exception as e:  # noqa: BLE001
                check(era, "add validates", False, e)
            try:
                await s.call_tool("nope", {})
                check(era, "unknown tool", False, "no error")
            except MCPError as e:
                check(era, "unknown tool", e.error.code in (-32602, -32601), e.error)

            res = await s.call_tool("greet", {}, allow_input_required=True)
            if isinstance(res, t.InputRequiredResult):
                keys = list((res.input_requests or {}).keys())
                check(era, "greet asks", era == "modern" and keys == ["name"], res)
                answers = {k: t.ElicitResult(action="accept", content={"name": "Ada"}) for k in keys}
                res = await s.call_tool("greet", {}, input_responses=answers, request_state=res.request_state)
            want = "session path: no multi round-trip" if era == "session" else "hello, Ada"
            check(era, "greet", text_of(res) == want, res)

            rl = await s.list_resources()
            check(era, "resources/list", [str(x.uri) for x in rl.resources] == ["oracle://readme"], rl)
            rt = await s.list_resource_templates()
            check(era, "resources/templates/list", [x.uri_template for x in rt.resource_templates] == ["oracle://items/{id}"], rt)
            rr = await s.read_resource("oracle://readme")
            check(era, "read readme", rr.contents[0].text == "read me\n" and rr.contents[0].mime_type == "text/plain", rr)
            rr = await s.read_resource("oracle://items/7")
            check(era, "read template", rr.contents[0].text == '{"item":true}', rr)
            try:
                await s.read_resource("oracle://missing")
                check(era, "read missing", False, "no error")
            except MCPError as e:
                check(era, "read missing", e.error.code in (-32002, -32602), e.error)

            pl = await s.list_prompts()
            check(era, "prompts/list", [p.name for p in pl.prompts] == ["review"] and pl.prompts[0].arguments[0].name == "lang", pl)
            gp = await s.get_prompt("review", {"lang": "rust"})
            check(era, "prompts/get", [m.content.text for m in gp.messages] == ["Review this rust code.", "Paste it."]
                  and [m.role for m in gp.messages] == ["user", "assistant"], gp)
            try:
                await s.get_prompt("nope", {})
                check(era, "unknown prompt", False, "no error")
            except MCPError as e:
                check(era, "unknown prompt", e.error.code in (-32602, -32601), e.error)
            if era == "session":
                await s.send_ping()
                check(era, "ping", True)
            else:
                # The 2026-07-28 changelog, major change 5: "Remove `ping`, ...".
                # SDK 2.3.0 still sends it on the stateless path; the server's
                # -32601 is the revision's answer.
                try:
                    await s.send_ping()
                    check(era, "ping refused", False, "answered")
                except MCPError as e:
                    check(era, "ping refused", e.error.code == -32601, e.error)


# A server that answers `initialize` correctly and `tools/list` with a tool
# missing its required `inputSchema`: the SDK must refuse it, or its acceptance
# of our answers proves nothing.
STUB = r"""
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m: continue
    if m["method"] == "initialize":
        r = {"protocolVersion": m["params"]["protocolVersion"], "capabilities": {"tools": {}},
             "serverInfo": {"name": "stub", "version": "0"}}
    else:
        r = {"tools": [{"name": "x"}]}
    print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}), flush=True)
"""


async def teeth():
    params = StdioServerParameters(command=sys.executable, args=["-c", STUB])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            try:
                await s.list_tools()
                check("teeth", "malformed tools/list refused", False, "accepted")
            except Exception:  # noqa: BLE001
                check("teeth", "malformed tools/list refused", True)


def zstr(b):
    out = ['"']
    for ch in b:
        c = chr(ch)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c == "\n":
            out.append("\\n")
        elif 0x20 <= ch < 0x7F:
            out.append(c)
        else:
            out.append("\\x%02x" % ch)
    out.append('"')
    return "".join(out)


def main():
    os.makedirs(WORK, exist_ok=True)
    subprocess.run(["zig", "build-exe", "-OReleaseSafe", "-fllvm", "--dep", "mcp",
                    "-Mroot=modules/mcp/tools/sdk_oracle/server.zig", "-Mmcp=modules/mcp/src/root.zig",
                    f"-femit-bin={BIN}"], check=True)
    asyncio.run(teeth())
    for era in ("session", "modern"):
        asyncio.run(run_era(era))
    failed = [c for c in checks if not c[2]]
    print(f"{len(checks)} checks, {len(failed)} failed", file=sys.stderr)
    if failed:
        sys.exit(1)
    with open(OUT, "w") as f:
        f.write("// SPDX-License-Identifier: MIT\n")
        f.write(f"// GENERATED by modules/mcp/tools/sdk_oracle/drive.py (MCP Python SDK {version('mcp')}) -- do not hand-edit.\n")
        f.write("//! What the official MCP Python SDK sent to `tools/sdk_oracle/server.zig` and what the server\n")
        f.write(f"//! answered, one session per era; the SDK's typed client accepted every answer and {len(checks)}\n")
        f.write("//! checks on their content passed. Replayed by `sdk_oracle.zig`.\n\n")
        f.write(f"pub const sdk_version = {zstr(version('mcp').encode())};\n\n")
        f.write("pub const Era = struct { name: []const u8, requests: []const u8, responses: []const u8 };\n\n")
        f.write("pub const eras = [_]Era{\n")
        for era in ("session", "modern"):
            req = open(os.path.join(WORK, f"{era}.req"), "rb").read()
            resp = open(os.path.join(WORK, f"{era}.resp"), "rb").read()
            f.write(f"    .{{ .name = {zstr(era.encode())}, .requests = {zstr(req)}, .responses = {zstr(resp)} }},\n")
        f.write("};\n")


main()
