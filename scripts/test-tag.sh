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
# Runs against a throwaway git repo with a STUBBED scripts/test.sh, so a case
# costs milliseconds instead of four full gate runs, and so "one lane is red"
# is something the test can actually arrange. Same pattern as
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
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/scripts"
cp "$TAG_SH" "$WORK/scripts/tag.sh"
cd "$WORK" || exit 1
git init -q -b main .
git config user.email t@t
git config user.name t

fails=0
check() { # check <label> <expected-exit> <actual-exit>
    if [[ "$2" == "$3" ]]; then
        printf '  ok   %-54s (exit %s)\n' "$1" "$3"
    else
        printf '  FAIL %-54s expected %s, got %s\n' "$1" "$2" "$3"
        fails=$((fails + 1))
    fi
}

# The stub stands in for the real gate. `RED_LANE` selects which lane fails:
# empty = the default lane, or a flag string, or "none" for an all-green run.
cat > scripts/test.sh <<'STUB'
#!/usr/bin/env bash
lane="${2-}"
[[ "${RED_LANE-none}" == "none" ]] && exit 0
[[ "$lane" == "${RED_LANE}" ]] && exit 1
exit 0
STUB
chmod +x scripts/test.sh
git add -A
git commit -qm base

echo "tag.sh self-test"

# 1: the happy path — all lanes green, a tag appears, named for the date.
RED_LANE=none bash scripts/tag.sh 2026-08-12 >/dev/null 2>&1
check "all lanes green -> tags" 0 $?
[[ "$(git tag)" == "2026-08-12" ]] ||
    { printf '  FAIL %-54s tag list is "%s"\n' "tag is named for the date" "$(git tag)"; fails=$((fails + 1)); }

# 2: same day again -> a suffixed name, never a collision.
RED_LANE=none bash scripts/tag.sh 2026-08-12 >/dev/null 2>&1
check "second tag same day -> suffixed, no collision" 0 $?
git rev-parse -q --verify refs/tags/2026-08-12.1 >/dev/null ||
    { printf '  FAIL %-54s\n' "second tag became 2026-08-12.1"; fails=$((fails + 1)); }

# 3-6: THE POINT OF THE SCRIPT. Each lane, one at a time, must be able to
# veto the tag on its own — a loop that collects failures but only ever looks
# at the last one would pass a single-lane test and still be broken.
for lane in "" "-Dstrict-debug" "-Doptimize=ReleaseFast" "-Doptimize=ReleaseSafe"; do
    before="$(git tag | wc -l)"
    RED_LANE="$lane" bash scripts/tag.sh 2026-09-01 >/dev/null 2>&1
    check "red lane '${lane:-default}' -> refuse" 1 $?
    [[ "$(git tag | wc -l)" == "$before" ]] ||
        { printf '  FAIL %-54s\n' "no tag was created for '${lane:-default}'"; fails=$((fails + 1)); }
done

# 7: a dirty tree is refused BEFORE any lane runs — the guard that masked the
# lane check when this was first attempted by hand.
echo dirt > dirt.txt
RED_LANE=none bash scripts/tag.sh 2026-09-02 >/dev/null 2>&1
check "dirty tree -> refuse" 1 $?
rm -f dirt.txt

# 8: not on main -> refuse. Release tags come off main or they mean nothing.
git checkout -q -b side
RED_LANE=none bash scripts/tag.sh 2026-09-03 >/dev/null 2>&1
check "not on main -> refuse" 1 $?
git checkout -q main

# 9: --dry-run proves the lanes without leaving a tag behind.
before="$(git tag | wc -l)"
RED_LANE=none bash scripts/tag.sh --dry-run 2026-09-04 >/dev/null 2>&1
check "--dry-run, all green -> succeeds" 0 $?
[[ "$(git tag | wc -l)" == "$before" ]] ||
    { printf '  FAIL %-54s\n' "--dry-run created no tag"; fails=$((fails + 1)); }

# 10: a malformed date is refused rather than becoming a tag name.
RED_LANE=none bash scripts/tag.sh v1.2.3 >/dev/null 2>&1
check "semver-shaped argument -> refuse" 1 $?

echo
if [[ $fails -eq 0 ]]; then
    echo "tag.sh self-test: all cases behaved"
    exit 0
fi
echo "tag.sh self-test: $fails case(s) misbehaved" >&2
exit 1
