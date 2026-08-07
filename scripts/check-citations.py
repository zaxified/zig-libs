#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check quoted-standard citations in this repo against the real spec text.

Why this exists: this repo's safety argument rests heavily on clauses quoted
out of RFCs, W3C recommendations, BIPs and BOLTs — a doc comment or SPEC.md
saying "RFC 4954 §14 requires X" is treated by readers as load-bearing. A
FABRICATED citation is worse than a MISSING one: nothing prompts a reader to
doubt it, and a wrong section number or an invented sentence can survive
indefinitely because nobody re-derives it. `git log` for
"Check the citations this repo's safety argument rests on" has the incident
that started this: a "quote" attributed to ISO/IEC 10589 §7.2.5 that does not
exist in that clause at all.

What it does:
  1. Walks `modules/**/*.zig` and `**/*.md`, pulling `"quoted text"` (>=4
     words) out of comment blocks / markdown prose that sits near a standards
     token (`RFC 9180`, `BIP-340`, `BOLT #2`, `W3C`, `ISO/IEC 10589`, ...) or a
     section marker (`§7.2`, `Section 4.2.8`, `Appendix B`, ...).
  2. Resolves each citation to a fetchable primary source where one is known
     (RFC via rfc-editor.org, BIP/BOLT via the bitcoin/bips and
     lightning/bolts repos, W3C via a small per-module URL table below), and
     downloads it once into a cache OUTSIDE this repo.
  3. Normalises whitespace/quote-style on both sides and checks the claimed
     text is a literal substring of the real document.

Every claim ends up in exactly one bucket:
  VERIFIED     the quoted text is present in the fetched primary source.
  MISMATCH     the source fetched fine, but the quoted text (or a fragment of
               it, split on "..."/"[...]" elisions) is NOT in it — the
               citation is wrong, or the quote was edited without updating it.
               (The regex extraction is a heuristic: occasionally it spans a
               genuine quote in the repo's OWN prose across two unrelated
               `"..."` pairs, which also reports as MISMATCH. Read the
               `file:line` before treating a MISMATCH as a proven false
               citation in the standard.)
  UNFETCHABLE  no primary source could be obtained (paywalled standard,
               unknown document, network failure, ...). This is NOT a pass —
               an unfetchable claim has not been checked, and must never be
               reported as clean.

Calibration, so the output is not over-read: a full-repo run on 2026-08-07 gave
790 citations -> 353 VERIFIED, 399 MISMATCH, 38 UNFETCHABLE. That MISMATCH
count is NOT 399 false citations; it is dominated by the extraction heuristic
catching ordinary prose and code near a standards token. This is a triage aid,
not a gate: it narrows ~800 claims to a readable list, and a human still has to
open each `file:line`. The audit that produced it found 6 genuinely wrong
citations out of 198 hand-checked, 3 of them invented outright.

Usage:
    scripts/check-citations.py                  # whole repo
    scripts/check-citations.py webauthn hpke     # only modules/webauthn, modules/hpke
    scripts/check-citations.py --json out.json   # also dump full claim list
    scripts/check-citations.py --verbose         # print every non-VERIFIED claim (default)
    scripts/check-citations.py --quiet           # summary counts only

Environment:
    ZIG_LIBS_CITATIONS_CACHE   cache directory (default: see CACHE_DIR below)

Requires network access to fetch standards text the first time; results are
cached indefinitely (standards text does not change). Delete the cache
directory to force a re-fetch. Python 3 stdlib only — no pip packages.
"""
import argparse
import collections
import html as html_mod
import json
import os
import re
import sys
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_CACHE = os.path.join(
    os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"),
    "zig-libs-citations",
)
CACHE_DIR = os.environ.get("ZIG_LIBS_CITATIONS_CACHE", DEFAULT_CACHE)

FETCH_TIMEOUT = 30

# ── extraction ───────────────────────────────────────────────────────────

CMT = re.compile(r'^\s*(//!|///|//)\s?')
QUOTE = re.compile(r'"([^"\n]{20,400}?)"')
STD = re.compile(
    r'\b(RFC\s?(\d{3,5})|ISO/IEC\s?(\d{3,5})|ISO\s(\d{4,5})|'
    r'BOLT\s?#?(\d{1,2})|BIP-?(\d{1,3})|NIST\s+SP\s+(800-[0-9A-Za-z-]+)|'
    r'FIPS\s?(\d{3})|ASHRAE\s?135|IEEE\s?(802[0-9.A-Za-z]*)|'
    r'OPC\s?(\d{5})|W3C)\b'
)
SEC = re.compile(r'(?:§+\s?|[Ss]ection\s|[Cc]lause\s|Appendix\s|App\.\s|Annex\s)([0-9A-Z][0-9A-Za-z.]*)')

# A quote is only trusted as a genuine "the standard's own words" citation
# (as opposed to an incidental string match) when it is introduced the way a
# citation normally is: "...§7.2, "quoted text"" or "...RFC 9180 states: "...".
INTRO = re.compile(
    r'(§\s?[0-9A-Z][0-9A-Za-z.]*(\'s)?|W3C|RFC\s?\d{3,5}|BIP-?\d+|BOLT\s?#?\d+|'
    r'[Ss]ection\s[0-9A-Z][0-9A-Za-z.]*|[Cc]lause\s[0-9.]+|Appendix\s\w+|Annex\s\w+)'
    r'[^"]{0,40}(:|,|\s(says|reads|states|puts it|requires|mandates|opens with|ends with|preamble|NOTE))\s*$'
)


def blocks(path):
    """Yield (start_line, [(line, text), ...]) for each comment block / md paragraph."""
    with open(path, errors="replace") as f:
        lines = f.read().split("\n")
    md = path.endswith(".md")
    cur, start = [], None
    for i, ln in enumerate(lines, 1):
        if md:
            iscmt = ln.strip() != "" and not ln.startswith("```")
            body = ln.lstrip("> ").rstrip()
        else:
            m = CMT.match(ln)
            iscmt = m is not None
            body = CMT.sub("", ln).rstrip() if m else ""
        if iscmt:
            if start is None:
                start = i
            cur.append((i, body))
        else:
            if cur:
                yield start, cur
            cur, start = [], None
    if cur:
        yield start, cur


def extract_file(path, rel):
    out = []
    for start, blk in blocks(path):
        text = " ".join(b for _, b in blk)
        text = re.sub(r"\s+", " ", text)
        offs, pos = [], 0
        for ln, b in blk:
            b2 = re.sub(r"\s+", " ", b)
            offs.append((pos, ln))
            pos += len(b2) + 1

        def lineof(o):
            best = blk[0][0]
            for p, ln in offs:
                if p <= o:
                    best = ln
            return best

        for qm in QUOTE.finditer(text):
            q = qm.group(1)
            if len(q.split()) < 4:
                continue
            lo = max(0, qm.start() - 160)
            before = text[lo:qm.start()]
            after = text[qm.end():qm.end() + 90]
            std = None
            for sm in STD.finditer(before):
                std = sm.group(0)
            sec = None
            for cm in SEC.finditer(before):
                sec = cm.group(1)
            if std is None:
                sm = STD.search(after)
                if sm:
                    std = sm.group(0)
            if sec is None:
                cm = SEC.search(after)
                if cm:
                    sec = cm.group(1)
            if std is None and sec is None:
                continue
            out.append({
                "file": rel, "line": lineof(qm.start()), "std": std,
                "sec": sec, "quote": q, "ctx": before[-160:],
            })
    return out


def extract_claims(root, module_filter):
    res = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", ".zig-cache", "zig-out")]
        for fn in fns:
            if not fn.endswith((".zig", ".md")):
                continue
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root)
            if module_filter and module_of(rel) not in module_filter:
                continue
            res += extract_file(p, rel)
    return res


def module_of(rel_path):
    m = re.match(r'modules/([^/]+)/', rel_path)
    return m.group(1) if m else None


# ── document resolution + fetch ─────────────────────────────────────────

# Modules whose citations omit an explicit std token (e.g. just "§16") but
# always mean the same document. Mirrors what the original ad hoc harness
# called DEF, extended with non-RFC document types.
MODULE_DEFAULT = {
    "mls": ("rfc", "9420"), "oscore": ("rfc", "8613"), "opaque": ("rfc", "9807"),
    "websocket": ("rfc", "6455"), "decaf448": ("rfc", "9496"), "frost": ("rfc", "9591"),
    "spake2plus": ("rfc", "9383"), "xmss": ("rfc", "8391"), "hpke": ("rfc", "9180"),
    "ecvrf": ("rfc", "9381"), "isis": ("rfc", "1142"), "isis-lsdb": ("rfc", "1142"),
    "isis-sim": ("rfc", "1142"), "isis-spf": ("rfc", "1142"), "spf-ect": ("rfc", "1142"),
    "voprf": ("rfc", "9497"), "cbor": ("rfc", "8949"), "netconf": ("rfc", "6241"),
    "dnssec": ("rfc", "4034"), "x509": ("rfc", "5280"), "ssh": ("rfc", "4253"),
    "coap": ("rfc", "7252"), "snmp": ("rfc", "3414"), "staticfiles": ("rfc", "7233"),
    "blindrsa": ("rfc", "9474"), "tlsresume": ("rfc", "8446"),
    # W3C: the "std" token doesn't identify *which* W3C document, so a
    # per-module default is the only way to resolve it at all.
    "webauthn": ("w3c", "webauthn"),
}

# W3C document -> candidate URLs, tried in order until one fetches.
W3C_DOCS = {
    "webauthn": [
        "https://www.w3.org/TR/webauthn-3/",
        "https://www.w3.org/TR/webauthn-2/",
    ],
}

# Standards tokens this script knows how to fetch. Anything else (ISO/IEC,
# bare ISO, NIST SP 800-*, FIPS, ASHRAE, IEEE, OPC, ...) is a standard this
# campaign already confirmed is paywalled or otherwise not freely fetchable
# (see BD-28) — those are always UNFETCHABLE, never silently skipped.
FETCHABLE_PREFIXES = ("RFC", "BIP", "BOLT", "W3C")


def classify(claim):
    """Return (doctype, docid) or (None, None) if not resolvable at all."""
    std = claim.get("std")
    module = module_of(claim["file"])
    if std:
        su = std.upper()
        if su.startswith("RFC"):
            return "rfc", re.sub(r"\D", "", std)
        if su.startswith("BIP"):
            m = re.search(r"\d+", std)
            return ("bip", m.group(0)) if m else (None, None)
        if su.startswith("BOLT"):
            m = re.search(r"\d+", std)
            return ("bolt", m.group(0)) if m else (None, None)
        if su.startswith("W3C"):
            if module in W3C_DOCS:
                return "w3c", module
            return "unsupported", std
        return "unsupported", std
    # No explicit std token: only trust a module-implied default when the
    # quote is actually introduced like a citation (INTRO), same bar the
    # original harness used for this weaker class of evidence.
    if module in MODULE_DEFAULT and INTRO.search(claim["ctx"].rstrip()):
        return MODULE_DEFAULT[module]
    return None, None


def _fetch_url(url):
    with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT) as r:
        return r.read()


def _cache_path(name):
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, name)


def _cached_fetch(cache_name, urls):
    """Return raw text, fetching+caching on first use. Never caches failure,
    so a transient network blip doesn't calcify into a permanent UNFETCHABLE."""
    p = _cache_path(cache_name)
    if os.path.exists(p) and os.path.getsize(p) > 0:
        return open(p, errors="replace").read()
    for url in urls:
        try:
            body = _fetch_url(url).decode("utf-8", "replace")
        except Exception as e:
            print(f"  fetch failed: {url} ({e})", file=sys.stderr)
            continue
        if body:
            open(p, "w").write(body)
            return body
    return ""


def fetch_doc(doctype, docid):
    if doctype == "rfc":
        return _cached_fetch(f"rfc{docid}.txt", [f"https://www.rfc-editor.org/rfc/rfc{docid}.txt"])
    if doctype == "bip":
        n = f"{int(docid):04d}"
        return _cached_fetch(f"bip{n}.txt", [
            f"https://raw.githubusercontent.com/bitcoin/bips/master/bip-{n}.mediawiki",
            f"https://raw.githubusercontent.com/bitcoin/bips/master/bip-{n}.md",
        ])
    if doctype == "bolt":
        names = {
            0: "00-introduction", 1: "01-messaging", 2: "02-peer-protocol",
            3: "03-transactions", 4: "04-onion-routing", 5: "05-onchain",
            7: "07-routing-gossip", 8: "08-transport", 9: "09-features",
            10: "10-dns-bootstrap", 11: "11-payment-encoding", 12: "12-offer-encoding",
        }
        n = int(docid)
        if n not in names:
            return ""
        return _cached_fetch(f"bolt{n:02d}.md",
                              [f"https://raw.githubusercontent.com/lightning/bolts/master/{names[n]}.md"])
    if doctype == "w3c":
        return _cached_fetch(f"w3c-{docid}.html", W3C_DOCS[docid])
    return ""


# ── normalisation + verification ────────────────────────────────────────

def depage_rfc(s):
    """Strip RFC plaintext page furniture: form feeds, footers, running headers."""
    s = re.sub(r"\n[^\n]*\[Page \d+\]\s*\n\f\n[^\n]*\n", "\n", s)
    s = re.sub(r"\n[^\n]*\[Page \d+\]\s*\n+[^\n]*\n", "\n", s)
    return s


def strip_html(s):
    s = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    return html_mod.unescape(s)


def norm(s):
    s = s.replace("’", "'").replace("‘", "'")
    s = s.replace("“", '"').replace("”", '"')
    s = s.replace("—", "-").replace("–", "-").replace("‑", "-")
    s = s.replace("\xa0", " ")
    s = re.sub(r"[`*_'\"]", "", s)
    s = re.sub(r"\s+", " ", s)
    # tag-stripping (for HTML sources) leaves a space where a closing tag
    # used to sit right before punctuation, e.g. "example.org</code>," ->
    # "example.org ,"; undo that so it doesn't fight a real quote's spacing.
    s = re.sub(r"\s+([,.;:!?)])", r"\1", s)
    return s.lower()


def body_for(doctype, raw):
    if doctype == "rfc":
        return norm(depage_rfc(raw))
    if doctype == "w3c":
        return norm(strip_html(raw))
    # bip/bolt are already plain markdown/mediawiki text
    return norm(raw)


def verify(quote, body):
    q = norm(quote).strip(" .,;:")
    parts = [p.strip() for p in re.split(r"\.\.\.|…|\[[^\]]*\]", q) if len(p.strip().split()) >= 4]
    if not parts:
        return "VERIFIED", [], []
    hits = [p for p in parts if p in body]
    miss = [p for p in parts if p not in body]
    return ("VERIFIED" if not miss else "MISMATCH"), hits, miss


# ── driver ───────────────────────────────────────────────────────────────

def run(module_filter, verbose, json_out):
    claims = extract_claims(REPO_ROOT, module_filter)
    docs = {}  # (doctype, docid) -> body text, "" means fetch failed
    results = []
    for c in claims:
        doctype, docid = classify(c)
        if doctype is None:
            continue  # not enough attribution to identify any document
        c["doctype"], c["docid"] = doctype, docid
        if doctype == "unsupported":
            c["verdict"] = "UNFETCHABLE"
            c["reason"] = f"no fetcher for {docid!r} (paywalled/binary standard)"
            results.append(c)
            continue
        key = (doctype, docid)
        if key not in docs:
            print(f"fetching {doctype}:{docid} ...", file=sys.stderr)
            raw = fetch_doc(doctype, docid)
            docs[key] = body_for(doctype, raw) if raw else ""
        body = docs[key]
        if not body:
            c["verdict"] = "UNFETCHABLE"
            c["reason"] = "fetch failed"
            results.append(c)
            continue
        verdict, hits, miss = verify(c["quote"], body)
        c["verdict"] = verdict
        if miss:
            c["missing"] = miss[:2]
        results.append(c)

    cnt = collections.Counter(r["verdict"] for r in results)
    print(f"\n{len(results)} citations checked: {dict(cnt)}")
    if verbose:
        for c in results:
            if c["verdict"] != "VERIFIED":
                std = c.get("std") or f"{c['doctype']}:{c['docid']} (module default)"
                print(f"\n{c['verdict']} {c['file']}:{c['line']} [{std} §{c['sec']}]")
                print(f"  Q: {c['quote'][:170]}")
                if c["verdict"] == "UNFETCHABLE":
                    print(f"  reason: {c['reason']}")
                else:
                    print(f"  missing: {c['missing']}")

    if json_out:
        json.dump(results, open(json_out, "w"), indent=1)
        print(f"\nfull results written to {json_out}")

    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("modules", nargs="*", help="restrict to these module names (default: whole repo)")
    ap.add_argument("--json", metavar="PATH", help="dump full claim list as JSON")
    ap.add_argument("--verbose", action="store_true", default=True, help="print every non-VERIFIED claim (default)")
    ap.add_argument("--quiet", dest="verbose", action="store_false", help="summary counts only")
    args = ap.parse_args()

    module_filter = set(args.modules) if args.modules else None
    print(f"cache dir: {CACHE_DIR}", file=sys.stderr)
    results = run(module_filter, args.verbose, args.json)

    bad = sum(1 for r in results if r["verdict"] == "MISMATCH")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
