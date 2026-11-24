# SPDX-License-Identifier: MIT
"""llhttp (the HTTP parser of Node.js and uvicorn) as an oracle for
`zig build interop-http -- --phase h1parsers` (tools/h1parsers.zig): what
llhttp's request parser does with each raw wire, in the shape
tools/rust_fast_bench/src/bin/h1_verdicts.rs prints for hyper.

llhttp is a parser, not a server: there is no handler, no Host check and no
status. A request "reaches the handler" when its headers are complete (as for a
server that dispatches then); its body is what the parser delivered if the
message completed, else unreadable. A parse error in a head is the reject (status
400, as every server on llhttp answers); an error inside a body is what a
server's handler sees as an unreadable body (`-`, no status), as in the Go
oracle, and so is a truncated message at the end of the wire. CONNECT and `Upgrade`
requests stop the parser (`HttpParserUpgrade`): the message so far counts, the
rest of the wire belongs to the tunnel.

Input: a file of `<id>\t<wire as hex>` lines. Output per case, tab-separated:
`<id>`, reject (0 or 400), number of calls, then per call method, target and
body as hex (`-` body not read to its end, `+` an empty body).

    $V/bin/python -I modules/http/tools/h1_llhttp.py CASES
"""
import sys

import httptools


class Collector:
    def __init__(self):
        self.calls = []
        self.url = b""
        self.cur = None
        self.parser = None

    def on_message_begin(self):
        self.url = b""
        self.cur = None

    def on_url(self, url):
        self.url += url

    def on_headers_complete(self):
        self.cur = {"url": self.url, "body": b"", "done": False, "method": self.parser.get_method()}
        self.calls.append(self.cur)

    def on_body(self, body):
        self.cur["body"] += body

    def on_message_complete(self):
        self.cur["done"] = True


def main():
    with open(sys.argv[1]) as f:
        lines = [l.rstrip("\n") for l in f if "\t" in l]
    for line in lines:
        ident, hexw = line.split("\t", 1)
        wire = bytes.fromhex(hexw)
        # The method is known only to the parser object: ask at each headers_complete.
        c = Collector()
        p = httptools.HttpRequestParser(c)
        c.parser = p
        reject = 0
        try:
            p.feed_data(wire)
        except httptools.HttpParserUpgrade:
            if c.cur is not None:
                c.cur["done"] = True  # the rest of the wire is the tunnel's
        except httptools.HttpParserError as e:
            msg = str(e)
            cur = c.cur
            if msg.startswith("Data after"):
                pass  # a server stops reading after `Connection: close`
            elif msg.startswith("Request has invalid"):
                # A framing error at the end of the head, after its callback:
                # the server refuses before it dispatches.
                if cur is not None and not cur["done"]:
                    c.calls.remove(cur)
                reject = 400
            elif cur is not None and not cur["done"]:
                pass  # in the body: the handler's read fails (body unread), no status of the parser's
            else:
                reject = 400
        row = [ident, str(reject), str(len(c.calls))]
        for call in c.calls:
            m = call["method"]
            if call["done"]:
                body = call["body"]
                bt = "+" if not body else body.hex()
            else:
                bt = "-"
            row += [m.hex(), call["url"].hex(), bt]
        print("\t".join(row))


main()
