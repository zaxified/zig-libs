#!/usr/bin/env bash
# Self-test for scripts/tag.sh — the script's whole job is to say NO, and a
# gate that never says no is decoration.
#
# It earned this file by fooling its own author: the first attempt to verify
# the red-lane refusal planted a failing test in the working tree, and tag.sh
# refused — on the DIRTY TREE check, which fires first. The lane check never
# ran. A refusal for the wrong reason looks exactly like a refusal for the
# right one.
#
# Runs against a throwaway git repo with a STUBBED `gh` on PATH (tag.sh asks it
# one question: CI's status and conclusion on HEAD), so every CI outcome --
# green, red, cancelled, still running, never run -- is something the test can
# actually arrange, in milliseconds. Same pattern as
# scripts/hooks/test-pre-commit.sh.
#
#   usage: scripts/test-tag.sh
#   exit 0 = every case behaved; exit 1 = a case did not, and says which.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG_SH="$SCRIPT_DIR/tag.sh"
[[ -x "$TAG_SH" ]] || {
    echo "test-tag: $TAG_SH is not executable" >&2
    exit 1
}

WORK="$(mktemp -d)"
# Captured stdout must live OUTSIDE the repo under test. Writing it into $WORK
# made an untracked file in that repo, so tag.sh refused on the dirty-tree
# guard and never ran a lane — the log cases below then read a stale log from
# an earlier case and reported a logging bug that did not exist. Third time
# today that guard masked what was behind it.
OUT="$(mktemp -d)"
trap 'rm -rf "$WORK" "$OUT"' EXIT
mkdir -p "$WORK/scripts"
cp "$TAG_SH" "$WORK/scripts/tag.sh"
cd "$WORK" || exit 1
git init -q -b main .
git config user.email t@t
git config user.name t
# The real repo gitignores `.zig-cache/`; this throwaway one must too, or the
# lane logs tag.sh writes there make the tree dirty and every LATER case
# refuses on the dirty-tree guard instead of testing what it meant to. That
# is how the first version of these log cases failed: not because the logging
# was broken, but because the fixture was.
printf '.zig-cache/\n' > .gitignore

fails=0
check() { # check <label> <expected-exit> <actual-exit>
    if [[ "$2" == "$3" ]]; then
        printf '  ok   %-54s (exit %s)\n' "$1" "$3"
    else
        printf '  FAIL %-54s expected %s, got %s\n' "$1" "$2" "$3"
        fails=$((fails + 1))
    fi
}

# `gh` stub on PATH: answers the one query tag.sh makes with $FAKE_CI, the
# "<status> <conclusion>" pair of CI's run on HEAD ("" = no run at all).
mkdir -p "$WORK/bin"
cat > "$WORK/bin/gh" <<'STUB'
#!/usr/bin/env bash
[[ -n "${FAKE_CI-}" ]] && echo "$FAKE_CI"
exit 0
STUB
chmod +x "$WORK/bin/gh"
export PATH="$WORK/bin:$PATH"
printf 'bin/\n' >> .gitignore
git add -A
git commit -qm base

echo "tag.sh self-test"

FAKE_CI="completed success" bash scripts/tag.sh 2026-08-12 >/dev/null 2>&1
check "CI green on HEAD -> tags" 0 $?
[[ "$(git tag)" == "2026-08-12" ]] ||
    { printf '  FAIL %-54s tag list is "%s"\n' "tag is named for the date" "$(git tag)"; fails=$((fails + 1)); }

FAKE_CI="completed success" bash scripts/tag.sh 2026-08-12 >/dev/null 2>&1
check "second tag same day -> suffixed, no collision" 0 $?
git rev-parse -q --verify refs/tags/2026-08-12.1 >/dev/null ||
    { printf '  FAIL %-54s\n' "second tag became 2026-08-12.1"; fails=$((fails + 1)); }

for ci in "completed failure" "completed cancelled" "in_progress null" "queued null" ""; do
    before="$(git tag | wc -l)"
    FAKE_CI="$ci" bash scripts/tag.sh 2026-09-01 >"$OUT/out.txt" 2>&1
    check "CI '${ci:-no run}' -> refuse" 1 $?
    [[ "$(git tag | wc -l)" == "$before" ]] ||
        { printf '  FAIL %-54s\n' "no tag was created for CI '${ci:-no run}'"; fails=$((fails + 1)); }
    grep -q "NOT tagging" "$OUT/out.txt" ||
        { printf '  FAIL %-54s\n' "refusal for CI '${ci:-no run}' says why"; fails=$((fails + 1)); }
done

echo dirt > dirt.txt
FAKE_CI="completed success" bash scripts/tag.sh 2026-09-02 >/dev/null 2>&1
check "dirty tree -> refuse" 1 $?
rm -f dirt.txt

git checkout -q -b side
FAKE_CI="completed success" bash scripts/tag.sh 2026-09-03 >/dev/null 2>&1
check "not on main -> refuse" 1 $?
git checkout -q main

before="$(git tag | wc -l)"
FAKE_CI="completed success" bash scripts/tag.sh --dry-run 2026-09-04 >/dev/null 2>&1
check "--dry-run, CI green -> succeeds" 0 $?
[[ "$(git tag | wc -l)" == "$before" ]] ||
    { printf '  FAIL %-54s\n' "--dry-run created no tag"; fails=$((fails + 1)); }

FAKE_CI="completed success" bash scripts/tag.sh v1.2.3 >/dev/null 2>&1
check "semver-shaped argument -> refuse" 1 $?

echo
if [[ $fails -eq 0 ]]; then
    echo "tag.sh self-test: all cases behaved"
    exit 0
fi
echo "tag.sh self-test: $fails case(s) misbehaved" >&2
exit 1
