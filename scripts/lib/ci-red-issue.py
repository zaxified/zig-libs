#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""ci-red-issue — one open issue for a red scheduled CI run, closed by a green one.

    python3 -I scripts/lib/ci-red-issue.py [--write]
    python3 -I scripts/lib/ci-red-issue.py --self-test

Reads this run's jobs through `gh api` (GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_SHA)
and either keeps the issue up to date or closes it. Without --write it prints what
it would do and writes nothing, which is what a dispatch with `release_dry_run` gets.

The issue is found by its fixed title, so a red week is one issue and not seven.
No retry here and no log text in the issue: job names and links from this run, and
module names that are checked against modules/ before they are written.
"""
import json
import os
import re
import subprocess
import sys

TITLE = "Scheduled CI is red"
BOT = "github-actions[bot]"  # only an issue this job opened is its to edit or close
RED = {"failure", "timed_out"}
# Superseded or stopped by hand: says nothing about the code, either way.
INCONCLUSIVE = {"cancelled"}
DATE_TAG_RE = re.compile(r"^20\d\d-\d\d-\d\d(\.\d+)?$")
MAX_LOGS = 12  # a run whose every lane is red does not need every log read
# The two shapes a lane's log names a failing module in: the build summary's
# `test-dns transitive failure`, and zig's `failed command: ./.zig-cache/o/<hash>/dns`.
LOG_RES = (
    re.compile(r"^(?:\S+Z )?\s*(?:[+|` -]*)test-([a-z0-9_]+)\b.*\bfailure\b", re.M),
    re.compile(r"failed command: \S*/\.zig-cache/o/[0-9a-f]+/([a-z0-9_]+)\b"),
)


def modules_in_log(text, known):
    found = set()
    for pattern in LOG_RES:
        found.update(pattern.findall(text))
    return sorted(found & known)


def real_gh(*args):
    p = subprocess.run(["gh", *args], capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"gh {args[0]} {args[1] if len(args) > 1 else ''}: {p.stderr.decode('utf-8', 'replace').strip()}")
    return p.stdout.decode("utf-8", "replace")


def run_jobs(gh, repo, run):
    out = gh("api", "--paginate", f"repos/{repo}/actions/runs/{run}/jobs?per_page=100",
             "--jq", ".jobs[] | {id, name, conclusion, html_url}")
    return [json.loads(line) for line in out.split("\n") if line.strip()]


def open_issue(gh, repo):
    out = gh("api", "--paginate", f"repos/{repo}/issues?state=open&per_page=100",
             "--jq", ".[] | select(.pull_request == null) | {number, title, user: .user.login}")
    numbers = [i["number"] for i in map(json.loads, filter(str.strip, out.split("\n")))
               if i["title"] == TITLE and i["user"] == BOT]
    return min(numbers) if numbers else None


def body_for(failing, sha, run_url, orphans=()):
    lines = [f"The scheduled full CI run at `{sha}` is red. No tag was cut.", "", f"Run: {run_url}", ""]
    if orphans:
        lines += [f"Date tag(s) without a Release: {', '.join(orphans)}. A person deletes each or cuts its "
                  "Release (CONVENTIONS.md §8); until then every scheduled run stays red.", ""]
    lines += ["| Lane | Modules named by its log |", "|------|--------------------------|"]
    for job, mods in failing:
        lines.append(f"| [{job['name']}]({job['html_url']}) | {', '.join(mods) if mods else '(none named)'} |")
    lines += ["", "Kept up to date by `scripts/lib/ci-red-issue.py`; a green scheduled run closes it."]
    return "\n".join(lines) + "\n"


def report(gh, env, known, write, say=print):
    repo, run, sha = env["GITHUB_REPOSITORY"], env["GITHUB_RUN_ID"], env["GITHUB_SHA"]
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    run_url = f"{server}/{repo}/actions/runs/{run}"
    jobs = run_jobs(gh, repo, run)
    if not jobs:
        raise RuntimeError("the run lists no jobs: refusing to read that as green")
    red = sorted((j for j in jobs if j["conclusion"] in RED), key=lambda j: j["name"])
    number = open_issue(gh, repo)
    orphans = [t for t in env.get("ORPHAN_TAGS", "").split() if DATE_TAG_RE.match(t)]

    if not red and any(j["conclusion"] in INCONCLUSIVE for j in jobs):
        say("cancelled, so neither red nor green: the issue stays as it is")
        return "inconclusive"
    if not red:
        if number is None:
            say("green, and no issue is open")
            return "nothing"
        say(f"green: closing issue #{number}")
        if write:
            gh("api", "-X", "POST", f"repos/{repo}/issues/{number}/comments",
               "-f", f"body=Green at `{sha}`: {run_url}")
            gh("api", "-X", "PATCH", f"repos/{repo}/issues/{number}", "-f", "state=closed", "-f", "state_reason=completed")
        return "closed"

    failing = []
    for i, job in enumerate(red):
        mods = []
        if i < MAX_LOGS:
            # A log that cannot be read costs the module names, not the report.
            try:
                mods = modules_in_log(gh("api", f"repos/{repo}/actions/jobs/{job['id']}/logs"), known)
            except RuntimeError as e:
                say(f"note: no log for {job['name']}: {e}")
        failing.append((job, mods))
    body = body_for(failing, sha, run_url, orphans)
    say(body)
    if number is None:
        say("red: opening the issue")
        if write:
            gh("api", "-X", "POST", f"repos/{repo}/issues", "-f", f"title={TITLE}", "-f", f"body={body}")
        return "opened"
    say(f"red: updating issue #{number}")
    if write:
        gh("api", "-X", "PATCH", f"repos/{repo}/issues/{number}", "-f", f"body={body}")
    return "updated"


def self_test():
    fails = []

    def expect(label, cond):
        if not cond:
            fails.append(label)

    # The shape of a real lane's log (run 41400687116).
    log = (
        "2026-11-02T06:59:58.7598362Z   loopback build+test (15 modules, netns-run) ... FAIL (36.0s)\n"
        "2026-11-02T06:59:58.7627139Z failed command: ./.zig-cache/o/c8dd034c/dns --cache-dir=./.zig-cache --seed=0xf\n"
        "2026-11-02T06:59:58.7631031Z test-stun success\n"
        "2026-11-02T06:59:58.7654375Z test-dns transitive failure\n"
        "2026-11-02T06:59:58.7654375Z test-private transitive failure\n"
    )
    expect("modules from a log, unknown names dropped", modules_in_log(log, {"dns", "stun"}) == ["dns"])
    expect("a clean log names nothing", modules_in_log("test-stun success\n", {"stun"}) == [])

    class Fake:
        def __init__(self, jobs, issues):
            self.jobs, self.issues, self.writes = jobs, issues, []

        def __call__(self, *args):
            joined = " ".join(args)
            if "-X" in args:
                self.writes.append(joined)
                return ""
            if "/jobs?" in joined:
                return "\n".join(json.dumps(j) for j in self.jobs)
            if "/issues?" in joined:
                return "\n".join(json.dumps(i) for i in self.issues)
            if joined.endswith("/logs"):
                return log
            raise RuntimeError(joined)

    env = {"GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "7", "GITHUB_SHA": "abc"}
    green = {"id": 1, "name": "gate", "conclusion": "success", "html_url": "u1"}
    bad = {"id": 2, "name": "modules ReleaseSafe amd64 [net]", "conclusion": "failure", "html_url": "u2"}
    known = {"dns"}
    quiet = lambda *_: None
    same = {"number": 9, "title": TITLE, "user": BOT}
    other = {"number": 3, "title": "something else", "user": BOT}
    stranger = {"number": 4, "title": TITLE, "user": "someone"}
    cancelled = {"id": 3, "name": "superseded", "conclusion": "cancelled", "html_url": "u3"}
    f = Fake([green], [stranger])
    expect("a stranger's issue of that title is not closed", report(f, env, known, True, quiet) == "nothing" and not f.writes)
    f = Fake([green, bad], [stranger])
    expect("a stranger's issue is not edited", report(f, env, known, True, quiet) == "opened" and "issues/4" not in f.writes[0])
    f = Fake([green, cancelled], [other])
    expect("a cancelled lane is not red", report(f, env, known, True, quiet) == "inconclusive" and not f.writes)
    f = Fake([green, cancelled], [same])
    expect("a cancelled run closes nothing", report(f, env, known, True, quiet) == "inconclusive" and not f.writes)
    f = Fake([green, bad], [other])
    report(f, dict(env, ORPHAN_TAGS="2026-11-04"), known, True, quiet)
    expect("an orphan tag is named in the issue", "2026-11-04" in f.writes[0] and "without a Release" in f.writes[0])
    f = Fake([green, bad], [other])
    report(f, dict(env, ORPHAN_TAGS="@someone $(x)"), known, True, quiet)
    expect("only date tags are repeated from the environment", "someone" not in f.writes[0])

    f = Fake([green], [other])
    expect("green, none open: nothing", report(f, env, known, True, quiet) == "nothing" and not f.writes)
    f = Fake([green], [other, same])
    expect("green closes", report(f, env, known, True, quiet) == "closed")
    expect("green closes the right one", any("issues/9 -f state=closed" in w for w in f.writes))
    f = Fake([green, bad], [other])
    expect("red opens", report(f, env, known, True, quiet) == "opened" and len(f.writes) == 1)
    expect("the body names lane and module", "[net]" in f.writes[0] and "| dns |" in f.writes[0])
    expect("the body holds no log text", "cache-dir" not in f.writes[0] and "private" not in f.writes[0])
    f = Fake([green, bad], [same])
    expect("red updates, never a second issue", report(f, env, known, True, quiet) == "updated" and "issues/9" in f.writes[0])
    f = Fake([green, bad], [same])
    report(f, env, known, False, quiet)
    expect("without --write nothing is written", f.writes == [])
    try:
        report(Fake([], []), env, known, True, quiet)
        expect("an empty job list is an error", False)
    except RuntimeError:
        pass

    if fails:
        for f in fails:
            print(f"  FAIL {f}")
        return 1
    print("ci-red-issue self-test: all cases behaved")
    return 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if argv not in ([], ["--write"]):
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "modules")
    known = {m for m in os.listdir(root) if not m.startswith("_")}
    report(real_gh, os.environ, known, write=argv == ["--write"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
