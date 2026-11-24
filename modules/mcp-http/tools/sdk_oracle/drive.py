# SPDX-License-Identifier: MIT
"""Driver of the mcp-http differential oracle (see `../interop.zig`, which
serves the transport and records the exchanges): the official MCP Python SDK
(run as a black box, its source not read -- the SDKs are mid-relicensing)
talks to 127.0.0.1:PORT through its own Streamable HTTP client, once per era:

  * modern 2026-07-28: `discover`, every method, a multi round-trip tool, live
    progress, a held `subscriptions/listen` that receives a pushed
    `notifications/tools/list_changed` and ends with the graceful close, and a
    `tools/call` the client cancels;
  * session (2025-11-25 and earlier): `initialize`, then the same methods, and a
    notification pushed to the session that arrives on the held `GET` stream.

Every answer is parsed by the SDK's typed models and checked here. Exit 0 only
when every check passed; the SDK version goes to WORKDIR/sdk-version.

    $V/bin/python modules/mcp-http/tools/sdk_oracle/drive.py PORT WORKDIR
"""
import os
import sys
from importlib.metadata import version

import anyio
import mcp.types as t
from mcp import ClientSession, MCPError
from mcp.client.streamable_http import streamable_http_client

PORT, WORK = sys.argv[1], sys.argv[2]
URL = f"http://127.0.0.1:{PORT}/mcp"
checks = []


def check(era, what, ok, detail=""):
    checks.append((era, what, ok))
    if not ok:
        print(f"FAIL {era} {what}: {detail}", file=sys.stderr)


def text_of(res):
    return "".join(c.text for c in res.content if getattr(c, "type", "") == "text")


async def elicit(ctx, params):
    return t.ElicitResult(action="accept", content={"name": "Ada"})


async def common(era, s):
    tools = await s.list_tools()
    names = [x.name for x in tools.tools]
    check(era, "tools/list", names[:4] == ["echo", "add", "greet", "work"], names)
    res = await s.call_tool("echo", {"text": "hi č"})
    check(era, "echo", text_of(res) == "hi č" and not res.is_error, res)
    res = await s.call_tool("add", {"a": 2, "b": 40})
    check(era, "add", res.structured_content == {"sum": 42} and not res.is_error, res)
    seen = []

    async def on_progress(progress, total, message):
        seen.append((progress, total, message))

    res = await s.call_tool("work", {}, progress_callback=on_progress)
    check(era, "work", text_of(res) == "worked", res)
    check(era, "work progress", seen == [(1, 2, "half"), (2, 2, "done")], seen)
    res = await s.call_tool("greet", {}, allow_input_required=True)
    if isinstance(res, t.InputRequiredResult):
        keys = list((res.input_requests or {}).keys())
        check(era, "greet asks", era == "modern" and keys == ["name"], res)
        answers = {k: t.ElicitResult(action="accept", content={"name": "Ada"}) for k in keys}
        res = await s.call_tool("greet", {}, input_responses=answers, request_state=res.request_state)
    want = "session path: no multi round-trip" if era == "session" else "hello, Ada"
    check(era, "greet", text_of(res) == want, res)
    rr = await s.read_resource("oracle://readme")
    check(era, "read readme", rr.contents[0].text == "read me\n", rr)
    gp = await s.get_prompt("review", {"lang": "rust"})
    check(era, "prompts/get", [m.content.text for m in gp.messages] == ["Review this rust code.", "Paste it."], gp)
    try:
        await s.call_tool("nope", {})
        check(era, "unknown tool", False, "no error")
    except MCPError as e:
        check(era, "unknown tool", e.error.code in (-32602, -32601), e.error)


async def listen_and_cancel(s):
    era = "modern"
    got = []

    async def on_message(msg):
        if isinstance(msg, Exception):
            return
        got.append(msg)

    s._message_handler = on_message  # noqa: SLF001 -- no public setter after construction
    req = t.SubscriptionsListenRequest(params=t.SubscriptionsListenRequestParams(
        notifications=t.SubscriptionFilter(tools_list_changed=True)))
    result = {}

    async def listen():
        result["r"] = await s.send_request(req, t.SubscriptionsListenResult)

    async with anyio.create_task_group() as tg:
        tg.start_soon(listen)
        # The listen is held once the server acknowledged it.
        for _ in range(500):
            if any("acknowledged" in repr(m) for m in got):
                break
            await anyio.sleep(0.01)
        check(era, "listen acknowledged", any("acknowledged" in repr(m) for m in got), got)
        res = await s.call_tool("touch", {})
        check(era, "touch reached one listen", text_of(res) == "1", res)
        for _ in range(500):
            if any("tools/list_changed" in repr(m) or "ToolListChanged" in repr(m) for m in got):
                break
            await anyio.sleep(0.01)
        check(era, "list_changed pushed", any("tools/list_changed" in repr(m) or "ToolListChanged" in repr(m) for m in got), got)
        res = await s.call_tool("finish_listens", {})
        check(era, "finish_listens", text_of(res) == "ok", res)
    check(era, "listen ended with the graceful close", isinstance(result.get("r"), t.SubscriptionsListenResult), result)

    # Cancellation: the client gives up on a running call.
    with anyio.move_on_after(0.5):
        await s.call_tool("slow", {})
    res = await s.call_tool("slow_cancelled", {})
    check(era, "slow cancelled", text_of(res) == "yes", res)


async def session_push(s, got):
    """Session era: a notification the server issues while the client is
    connected arrives on the held `GET` stream (the SDK opens it after
    `initialize`) -- the reference holds it open, so it must arrive live."""
    era = "session"
    res = await s.call_tool("touch", {})
    check(era, "touch reached the session", text_of(res) == "1", res)
    for _ in range(500):
        if any("tools/list_changed" in repr(m) or "ToolListChanged" in repr(m) for m in got):
            break
        await anyio.sleep(0.01)
    check(era, "list_changed pushed on the GET stream", any("tools/list_changed" in repr(m) or "ToolListChanged" in repr(m) for m in got), got)


async def run_era(era):
    got = []

    async def on_message(msg):
        if not isinstance(msg, Exception):
            got.append(msg)

    async with streamable_http_client(URL) as (r, w):
        async with ClientSession(r, w, elicitation_callback=elicit, message_handler=on_message) as s:
            if era == "session":
                init = await s.initialize()
                check(era, "initialize", init.server_info.name == "oracle-http", init)
            else:
                disc = await s.discover()
                check(era, "discover", "2026-07-28" in (disc.supported_versions or []), disc)
            await common(era, s)
            if era == "session":
                await session_push(s, got)
            if era == "modern":
                await listen_and_cancel(s)


def main():
    os.makedirs(WORK, exist_ok=True)
    with open(os.path.join(WORK, "sdk-version"), "w") as f:
        f.write(version("mcp"))
    for era in ("modern", "session"):
        anyio.run(run_era, era)
    failed = [c for c in checks if not c[2]]
    print(f"{len(checks)} checks, {len(failed)} failed", file=sys.stderr)
    sys.exit(1 if failed else 0)


main()
