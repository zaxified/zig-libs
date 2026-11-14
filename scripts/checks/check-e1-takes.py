#!/usr/bin/env python3
"""check-e1-takes — a class A/B module graded E1 must have had a GREEN live
take against its foreign peer within the last 30 days.

WHY THIS EXISTS
---------------
For class A/B modules `gates.zig` grades evidence E1 when the anchor oracle is
EXTERNAL and `modules/<m>/tools/interop.zig` exists -- the file's existence,
not a run of it. The owner's rule (2026-11-14, plan v3 D1): E1 means the
independent implementation's verdicts were RE-TAKEN within 30 days; between
takes the module replays the committed transcript. The repository cannot know
when a take last passed: that is in the interop lane's stamps (lane key
`interop week=<ISO week> ...`, column 4 = the time the take went green), which
CI carries from run to run as the `stamps-full-interop-<arch>` artifact. So
this runs where a release is cut, over that artifact.

USAGE
-----
  check-e1-takes.py --stamps <stamps.tsv> --report <maturity-report.tsv> [--today YYYY-MM-DD] [--advisory]

`--report` is `zig build maturity-report` output (column 2 module, column 3
axis profile). `--advisory` prints the list and exits 0: the dry run the plan
asks for before the rule is enforced.
"""
import argparse
import csv
import datetime
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAX_AGE_DAYS = 30


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stamps", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--today")
    ap.add_argument("--advisory", action="store_true")
    a = ap.parse_args()
    today = datetime.date.fromisoformat(a.today) if a.today else datetime.datetime.now(datetime.timezone.utc).date()

    last: dict[str, str] = {}
    with open(a.stamps, newline="") as f:
        for r in csv.reader(f, delimiter="\t"):
            if len(r) >= 4 and r[1].startswith("interop week=") and " DRY" not in r[1]:
                last[r[0]] = max(last.get(r[0], ""), r[3])

    claimed = []
    with open(a.report, newline="") as f:
        for r in csv.reader(f, delimiter="\t"):
            if len(r) < 3 or r[1] == "module":
                continue
            m, profile = r[1], r[2].split()
            if "E1" in profile and (ROOT / "modules" / m / "tools" / "interop.zig").is_file():
                claimed.append(m)
    if not claimed:
        print("check-e1-takes: the report names no module at E1 with tools/interop.zig -- wrong file?", file=sys.stderr)
        return 1

    stale = []
    for m in sorted(claimed):
        when = last.get(m)
        if when is None:
            stale.append((m, "no green take on record"))
            continue
        age = (today - datetime.date.fromisoformat(when[:10])).days
        if age > MAX_AGE_DAYS:
            stale.append((m, f"last green take {when[:10]} ({age} days)"))

    print(f"check-e1-takes: {len(claimed)} module(s) at E1 through a live oracle, "
          f"{len(claimed) - len(stale)} with a green take within {MAX_AGE_DAYS} days")
    for m, why in stale:
        print(f"  {m}: {why} -- E1 does not hold; re-take (`scripts/test.sh interop`) or the card drops to E2")
    if stale and not a.advisory:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
