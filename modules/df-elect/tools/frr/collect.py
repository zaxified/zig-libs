#!/usr/bin/env python3
"""Merge per-PE poll logs (`@@ <ns>` + `show evpn es detail json`) and lab
events (stdin: `<ns> <kind> <text>`) into JSON lines, on change only.

usage: collect.py <scenario> <t0_ns> <n:ip:logfile>...
Output lines (all carry scenario + t_ms relative to t0):
  {"event": "<text>", "kind": "action|note", ...}
  {"pe": ip, "es": esi|null, "df": bool, "df_pref": int, "flags": [...], "peers": {ip: pref}}
  {"summary": "df_change", "after": "<event>", "latency_ms": N, "df_before": [...], "df_after": [...]}
"""
import json, sys

scen, t0 = sys.argv[1], int(sys.argv[2])
logs = []
for a in sys.argv[3:]:
    n, ip, path = a.split(":", 2)
    logs.append((ip, path))

def ms(ns):
    return round((ns - t0) / 1e6, 1)

obs = []            # (ns, ip, state dict)
for ip, path in logs:
    try:
        text = open(path).read()
    except OSError:
        continue
    blocks = text.split("@@ ")[1:]
    last = object()
    for b in blocks:
        head, _, body = b.partition("\n")
        try:
            ns = int(head.strip()) * 1000      # poller stamps are microseconds
            d = json.loads(body)
        except ValueError:
            continue            # truncated by a stopping container, or vtysh error text
        if not isinstance(d, list):
            d = list(d.values())
        if not d:
            st = {"es": None, "df": False, "df_pref": None, "flags": [], "peers": {}}
        else:
            e = d[0]
            fl = e.get("flags", [])
            st = {"es": e.get("esi"), "df": "df" in fl, "df_pref": e.get("dfPreference"),
                  "flags": sorted(x for x in fl if x != "df"),
                  "peers": {v["vtep"]: v.get("dfPreference") for v in e.get("vteps", [])}}
        key = json.dumps(st, sort_keys=True)
        if key != last:
            obs.append((ns, ip, st))
            last = key

events = []
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    ns, kind, text = line.split(" ", 2)
    events.append((int(ns), kind, text))

rows = []
for ns, ip, st in obs:
    rows.append((ns, {"scenario": scen, "t_ms": ms(ns), "pe": ip, **st}))
for ns, kind, text in events:
    rows.append((ns, {"scenario": scen, "t_ms": ms(ns), "kind": kind, "event": text}))
rows.sort(key=lambda r: (r[0], "event" in r[1]))

# DF-set changes inside the window that follows each action event.  The PEs are
# polled ~60 ms apart, so a hand-over can show a transient "two DFs" or "no DF"
# set: first_change_ms is the first set that differs from the one before the
# action, settled_ms is the last set change before the next action (or the end).
cur = {}
dfset = lambda: sorted(ip for ip, s in cur.items() if s["df"])
windows = []          # [ns, text, before, [(ns, set)...]]
for ns, r in rows:
    if "event" in r:
        if r["event"].startswith("pe_down "):
            cur.pop(r["event"].split()[1], None)
        if r["kind"] == "action":
            windows.append([ns, r["event"], dfset(), []])
        continue
    cur[r["pe"]] = {"df": r["df"]}
    if windows:
        windows[-1][3].append((ns, dfset()))
summ = []
for ns, text, before, seq in windows:
    changes, prev = [], before
    for t, st in seq:
        if st != prev:
            changes.append((t, st)); prev = st
    if not changes:
        summ.append((ns, {"scenario": scen, "t_ms": ms(ns), "summary": "no_df_change", "after": text, "df": before}))
    else:
        summ.append((ns, {"scenario": scen, "t_ms": ms(ns), "summary": "df_change", "after": text,
                          "df_before": before, "df_after": changes[-1][1],
                          "first_change_ms": round(ms(changes[0][0]) - ms(ns), 1),
                          "settled_ms": round(ms(changes[-1][0]) - ms(ns), 1)}))

for _, r in rows + sorted(summ, key=lambda r: r[0]):
    print(json.dumps(r, separators=(",", ":")))
