#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Needs aiocoap 0.4.17 (MIT), installed WITHOUT root into a throwaway venv:
#   python3 -m venv .venv && .venv/bin/pip install aiocoap==0.4.17
#   .venv/bin/python capture_goldens.py [--out DIR]
# aiocoap is a black-box peer: no source of it is read (root NOTICE §0).
"""Re-takes the datagrams frozen in `src/external_goldens.zig`.

A real `aiocoap` server (`aiocoap.resource.Site`) and a real `aiocoap` client run
on loopback with a byte-logging UDP proxy between them; every datagram that
crosses the proxy is logged as hex, in order, with its direction.

Resources of the server (the ones the goldens name):

  /hello   plain GET, text body "Hello there!"
  /big     a body whose octet i is (7 + 31*i) & 0xFF; 3000 octets, or the size
           in the `big` argument (17000 octets for the 17-block transfer that
           needs a 2-octet Block2 value)
  /data    PUT target (Block1 is volunteered by the client for a large body)
  /obs     observable counter; `POST /bump` changes it and pushes a notification

Scenarios, each written to `<out>/<name>.hex` (one `c2s <hex>` / `s2c <hex>`
line per datagram):

  hello      GET /hello
  big3000    GET /big (3000 octets): the volunteered Block2 transfer, 3 pairs
  put3000    PUT /data with a 3000-octet body: Block1 with a Size1 option
  observe    GET /obs with Observe, then two POST /bump: two pushed notifications
  big17000   GET /big with 17000 octets: block 16 needs a 2-octet Block2 value

The Message IDs and Tokens are random in every run, so the bytes differ from the
frozen ones in exactly those fields; `--compare` checks that everything else (the
options, the Block/Size values and the payloads) is identical to what
`external_goldens.zig` holds. Version, address and timing differ per host.
"""
import argparse
import asyncio
import os
import re
import sys

import aiocoap
import aiocoap.resource as resource
from aiocoap import Code, Message


def big_body(n):
    return bytes((7 + 31 * i) & 0xFF for i in range(n))


class Hello(resource.Resource):
    async def render_get(self, request):
        return Message(payload=b"Hello there!")


class Big(resource.Resource):
    def __init__(self, n):
        super().__init__()
        self.n = n

    async def render_get(self, request):
        return Message(payload=big_body(self.n))


class Data(resource.Resource):
    async def render_put(self, request):
        return Message(code=Code.CHANGED)


class Obs(resource.ObservableResource):
    def __init__(self):
        super().__init__()
        self.value = 0

    async def render_get(self, request):
        return Message(payload=str(self.value).encode())

    def bump(self):
        self.value += 1
        self.updated_state()


class Bump(resource.Resource):
    def __init__(self, obs):
        super().__init__()
        self.obs = obs

    async def render_post(self, request):
        self.obs.bump()
        return Message(code=Code.CHANGED)


class Proxy(asyncio.DatagramProtocol):
    """Relays datagrams between one client and the server, logging each."""

    def __init__(self, server_addr, log):
        self.server_addr = server_addr
        self.log = log
        self.client_addr = None
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if addr == self.server_addr:
            self.log.append("s2c " + data.hex())
            if self.client_addr:
                self.transport.sendto(data, self.client_addr)
        else:
            self.client_addr = addr
            self.log.append("c2s " + data.hex())
            self.transport.sendto(data, self.server_addr)


async def scenario(name, big_n, out):
    obs = Obs()
    site = resource.Site()
    site.add_resource(["hello"], Hello())
    site.add_resource(["big"], Big(big_n))
    site.add_resource(["data"], Data())
    site.add_resource(["obs"], obs)
    site.add_resource(["bump"], Bump(obs))
    # A free loopback port for the server (bind to 0, read it back, release it).
    import socket
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    sock_port = probe.getsockname()[1]
    probe.close()
    server = await aiocoap.Context.create_server_context(site, bind=("127.0.0.1", sock_port))
    server_addr = ("127.0.0.1", sock_port)
    log = []
    loop = asyncio.get_running_loop()
    proxy_tr, _ = await loop.create_datagram_endpoint(
        lambda: Proxy(server_addr, log), local_addr=("127.0.0.1", 0)
    )
    proxy_port = proxy_tr.get_extra_info("sockname")[1]
    client = await aiocoap.Context.create_client_context()
    base = f"coap://127.0.0.1:{proxy_port}"
    if name == "hello":
        await client.request(Message(code=Code.GET, uri=base + "/hello")).response
    elif name in ("big3000", "big17000"):
        await client.request(Message(code=Code.GET, uri=base + "/big")).response
    elif name == "put3000":
        await client.request(Message(code=Code.PUT, uri=base + "/data", payload=b"X" * 3000)).response
    elif name == "observe":
        req = client.request(Message(code=Code.GET, uri=base + "/obs", observe=0))
        first = await req.response
        seen = 0
        async def watch():
            nonlocal seen
            async for _ in req.observation:
                seen += 1
                if seen == 2:
                    return
        watcher = asyncio.ensure_future(watch())
        for _ in range(2):
            await asyncio.sleep(0.3)
            await client.request(Message(code=Code.POST, uri=base + "/bump")).response
        await asyncio.wait_for(watcher, 5)
        req.observation.cancel()
        await asyncio.sleep(0.3)
    await asyncio.sleep(0.2)
    await client.shutdown()
    await server.shutdown()
    proxy_tr.close()
    path = os.path.join(out, name + ".hex")
    with open(path, "w") as f:
        f.write("\n".join(log) + "\n")
    print(f"{name}: {len(log)} datagrams -> {path}")
    return log


def frozen_bodies(zig_path):
    """The `pub const <name>: []const u8 = &[_]u8{ ... }` arrays of external_goldens.zig."""
    text = open(zig_path).read()
    out = {}
    for m in re.finditer(r"pub const (\w+): \[\]const u8 = &\[_\]u8\{(.*?)\};", text, re.S):
        out[m.group(1)] = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(2)))
    return out


def body_of(datagram):
    """Everything after the token: options and payload, i.e. what the proxy bytes
    share with the frozen ones once MID and Token are masked."""
    tkl = datagram[0] & 0x0F
    return datagram[4 + tkl:]


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="capture")
    ap.add_argument("--compare", metavar="external_goldens.zig")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    logs = {}
    for name, n in [("hello", 0), ("big3000", 3000), ("put3000", 0), ("observe", 0), ("big17000", 17000)]:
        logs[name] = await scenario(name, n, args.out)
    if args.compare:
        frozen = frozen_bodies(args.compare)
        checks = [("hello_get", logs["hello"][0]), ("hello_content", logs["hello"][1]),
                  ("big3000_get_b0", logs["big3000"][0]), ("big3000_resp_b0", logs["big3000"][1])]
        bad = 0
        for key, line in checks:
            got = bytes.fromhex(line.split()[1])
            want = frozen.get(key)
            same = want is not None and body_of(got) == body_of(want)
            print(f"{key}: {'same options/payload' if same else 'DIFFERS'}")
            bad += not same
        sys.exit(1 if bad else 0)


asyncio.run(main())
