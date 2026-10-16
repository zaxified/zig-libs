#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The peers `acmedns`'s interop runs against, in one process:

  * the authoritative DNS server with RFC 2136 + TSIG from
    `modules/dns/tools/update_server.py` (zones example.org, delegated.test;
    keys `<alg>.key.`, secret SHA-256 of the name) -- Pebble's -dnsserver,
    the propagation check's authoritative server, the Rfc2136 publisher's
    primary, and the target of the exec publisher's `nsupdate`;
  * an acme-dns API STAND-IN (`POST /register`, `POST /update`), written
    from joohoi/acme-dns's README (MIT; the server itself is not run here:
    it is a Go service with its own DNS listener and database, and what
    `AcmeDns` speaks is these two calls). Accounts get `<uuid>.auth.
    delegated.test` as fulldomain; `/update` keeps the two newest values per
    subdomain, as acme-dns does, and writes them into the DNS server;
  * an httpreq endpoint (lego's `httpreq` protocol: `POST /present`,
    `/cleanup`; default `{fqdn, value}` and RAW `{domain, token, keyAuth}`
    under `/raw/...`), basic auth `httpreq:httpreq-pass`.

    python3 -I modules/acmedns/tools/peer.py READY_FILE

Writes "DNS_PORT HTTP_PORT" to READY_FILE once both listen, then serves until
killed. Run by `tools/interop.sh`.
"""

import base64
import hashlib
import http.server
import json
import os
import sys
import threading
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "dns", "tools"))

import dns.name  # noqa: E402
import dns.rdataclass  # noqa: E402
import dns.rdata  # noqa: E402
import dns.rdataset  # noqa: E402
import dns.rdatatype  # noqa: E402

import update_server as us  # noqa: E402

accounts = {}  # username -> {password, subdomain, fulldomain, values}
HTTPREQ_AUTH = "Basic " + base64.b64encode(b"httpreq:httpreq-pass").decode()


def set_txt(fqdn, values):
    name = dns.name.from_text(fqdn)
    with us.lock:
        key = (name, dns.rdatatype.TXT)
        us.records.pop(key, None)
        if values:
            rs = us.records.setdefault(key, dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.TXT))
            for v in values:
                rs.add(dns.rdata.from_text("IN", "TXT", f'"{v}"'), 60)


def add_txt(fqdn, value):
    name = dns.name.from_text(fqdn)
    with us.lock:
        rs = us.records.setdefault((name, dns.rdatatype.TXT), dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.TXT))
        rs.add(dns.rdata.from_text("IN", "TXT", f'"{value}"'), 60)


def remove_txt(fqdn, value):
    name = dns.name.from_text(fqdn)
    with us.lock:
        rs = us.records.get((name, dns.rdatatype.TXT))
        if rs is None:
            return
        rs.discard(dns.rdata.from_text("IN", "TXT", f'"{value}"'))
        if len(rs) == 0:
            del us.records[(name, dns.rdatatype.TXT)]


def txt_value(key_auth):
    digest = hashlib.sha256(key_auth.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


class Api(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self.reply(400, {"error": "malformed_json_payload"})

        if self.path == "/register":
            user, sub = str(uuid.uuid4()), str(uuid.uuid4())
            acct = {
                "password": base64.urlsafe_b64encode(os.urandom(30)).decode(),
                "subdomain": sub,
                "fulldomain": f"{sub}.auth.delegated.test",
                "values": [],
            }
            accounts[user] = acct
            return self.reply(201, {"username": user, "password": acct["password"], "fulldomain": acct["fulldomain"],
                                    "subdomain": sub, "allowfrom": req.get("allowfrom", [])})

        if self.path == "/update":
            acct = accounts.get(self.headers.get("X-Api-User", ""))
            if acct is None or acct["password"] != self.headers.get("X-Api-Key", ""):
                return self.reply(401, {"error": "forbidden"})
            if req.get("subdomain") != acct["subdomain"]:
                return self.reply(401, {"error": "forbidden"})
            txt = req.get("txt", "")
            if len(txt) != 43:
                return self.reply(400, {"error": "bad_txt"})
            acct["values"] = (acct["values"] + [txt])[-2:]
            set_txt(acct["fulldomain"] + ".", acct["values"])
            return self.reply(200, {"txt": txt})

        if self.path.startswith(("/present", "/cleanup", "/raw/present", "/raw/cleanup")):
            if self.headers.get("Authorization") != HTTPREQ_AUTH:
                return self.reply(401, {"error": "unauthorized"})
            raw = self.path.startswith("/raw/")
            action = self.path.rsplit("/", 1)[1]
            if raw:
                fqdn = f"_acme-challenge.{req['domain']}."
                value = txt_value(req["keyAuth"])
            else:
                fqdn, value = req["fqdn"], req["value"]
                if not fqdn.endswith("."):
                    return self.reply(400, {"error": "fqdn must be absolute"})
            (add_txt if action == "present" else remove_txt)(fqdn, value)
            return self.reply(200, {})

        return self.reply(404, {"error": "not found"})


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    dns_port = us.start(0)
    api = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    tmp = sys.argv[1] + ".tmp"
    with open(tmp, "w") as f:
        f.write(f"{dns_port} {api.server_address[1]}\n")
    os.rename(tmp, sys.argv[1])
    threading.Event().wait()


if __name__ == "__main__":
    main()
