#!/usr/bin/env bash
# Self-test for scripts/lib/auto-release.sh, the only route to a date tag since
# 2026-11-11 (a scheduled run or a `release: live` dispatch; scripts/tag.sh is
# gone). Its whole job is to say NO, and a gate that never says no is decoration.
#
# A refusal for the wrong reason looks exactly like a refusal for the right one
# (the first version of this file, testing tag.sh, refused on the dirty-tree
# guard and never reached the check it meant to test), so every refusal below
# also greps for its own reason.
#
# Runs against a throwaway repository with a bare `origin` and stubbed `zig`
# and `gh` on PATH. Same pattern as scripts/hooks/test-pre-commit.sh.
#
#   usage: scripts/lib/test-tag.sh
#   exit 0 = every case behaved; exit 1 = a case did not, and says which.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Captured stdout lives OUTSIDE the repository under test: written inside, it
# made the tree dirty and every later case refused on that guard instead.
OUT="$(mktemp -d)"
fails=0
check() { # check <label> <expected-exit> <actual-exit>
    if [[ "$2" == "$3" ]]; then
        printf '  ok   %-54s (exit %s)\n' "$1" "$3"
    else
        printf '  FAIL %-54s expected %s, got %s\n' "$1" "$2" "$3"
        fails=$((fails + 1))
    fi
}

# ── the scheduled route: scripts/lib/auto-release.sh ─────────────────────────
#
# The repository has to look like the real thing: apps with pins, a bare
# `origin` to push to, a `zig` stub for the package hash.
echo "auto-release.sh self-test"
AR_WORK="$(mktemp -d)"
trap 'rm -rf "$OUT" "$AR_WORK"' EXIT
git init -q --bare "$AR_WORK/origin.git"
git init -q -b main "$AR_WORK/repo"
cd "$AR_WORK/repo" || exit 1
git config user.email t@t
git config user.name t
git remote add origin "$AR_WORK/origin.git"
mkdir -p scripts/lib .github/workflows example-apps/one example-apps/two modules/m
cp "$SCRIPT_DIR/tag-lib.sh" "$SCRIPT_DIR/release-notes.py" "$SCRIPT_DIR/auto-release.sh" scripts/lib/
printf 'env:\n  ZIGLIBS_DRY_RUN: "0"\n' > .github/workflows/ci.yml
printf '.zig-cache/\n' > .gitignore
for app in one two; do
    cat > "example-apps/$app/build.zig.zon" <<'ZON'
.{
    .dependencies = .{
        .zig_libs = .{
            .url = "git+https://github.com/o/zig-libs#2026-10-19",
            .hash = "zig_libs-0.0.0-OLD",
        },
        //   .url = "git+https://github.com/o/zig-libs#main",
    },
}
ZON
    printf 'curl .../tags/2026-10-19.tar.gz; publishes 2026-10-19 19:35:15 UTC\n' > "example-apps/$app/README.md"
done
printf '# m\n\n## Unreleased\n\n- **2026-10-01** — New module.\n' > modules/m/CHANGELOG.md
git add -A
git commit -qm base
git tag -a -m 2026-10-19 2026-10-19
git push -q origin main refs/tags/2026-10-19

# Stubs: `zig fetch` prints a hash; `gh` records its arguments and obeys $FAKE_GH_RC.
mkdir -p "$AR_WORK/bin"
cat > "$AR_WORK/bin/zig" <<'STUB'
#!/usr/bin/env bash
[[ "${FAKE_ZIG_FAIL-}" == 1 ]] && exit 1
echo zig_libs-0.0.0-NEWHASH
STUB
cat > "$AR_WORK/bin/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$AR_GH_LOG"
if [[ "$*" == *"/releases"* ]]; then
    cat "$AR_RELEASES"
    exit "${FAKE_GH_RC:-0}"
fi
if [[ "${1-} ${2-}" == "release create" ]]; then
    while [[ $# -gt 0 ]]; do
        [[ "$1" == --notes-file ]] && cp "$2" "$AR_NOTES"
        shift
    done
fi
exit "${FAKE_GH_RC:-0}"
STUB
chmod +x "$AR_WORK/bin/zig" "$AR_WORK/bin/gh"
export PATH="$AR_WORK/bin:$PATH"
export AR_GH_LOG="$AR_WORK/gh.log" AR_NOTES="$AR_WORK/notes.out" AR_RELEASES="$AR_WORK/releases"
export GITHUB_REPOSITORY=o/r AUTO_RELEASE_DAY=2026-11-04
printf '2026-10-19\n' > "$AR_RELEASES"
AR=scripts/lib/auto-release.sh
say() { printf '  FAIL %-54s %s\n' "$1" "${2-}"; fails=$((fails + 1)); }
out_get() { sed -n "s/^$1=//p" "$AR_WORK/out" | tail -1; }
remote_tag() { git ls-remote origin "refs/tags/$1"; }

# since: a tag ON main, then a commit after it.
: > "$AR_WORK/out"
GITHUB_OUTPUT="$AR_WORK/out" bash "$AR" since >/dev/null 2>&1
check "since: HEAD is the tag -> runs clean" 0 $?
[[ "$(out_get changed)" == false ]] || say "since: tag on main, no commit -> changed=false" "$(out_get changed)"
git commit -q --allow-empty -m work
: > "$AR_WORK/out"
GITHUB_OUTPUT="$AR_WORK/out" bash "$AR" since >/dev/null 2>&1
[[ "$(out_get changed)" == true ]] || say "since: one commit after the tag -> changed=true" "$(out_get changed)"

# prepare, dry: tags locally on a child of the tested commit, pushes nothing.
tested="$(git rev-parse HEAD)"
git checkout -q --detach
: > "$AR_WORK/out"
AUTO_TAG_LIVE=1 GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/main AUTO_RELEASE_DAY=2026-11-04 \
    GITHUB_OUTPUT="$AR_WORK/out" bash "$AR" prepare "$tested" "$AR_WORK/b1" >"$OUT/prep.txt" 2>&1
check "prepare on a dispatch -> succeeds" 0 $?
[[ "$(out_get live)" == 0 ]] || say "a dispatch that did not ask is not live, even with the switch on" "$(out_get live)"
grep -q 'nothing is pushed' "$OUT/prep.txt" || say "the dry path says what it would do"
[[ -z "$(remote_tag 2026-11-04)" ]] || say "the dry path pushed nothing"
tag="$(out_get tag)"; commit="$(out_get commit)"
[[ "$tag" == 2026-11-04 ]] || say "prepare names the tag for the day" "$tag"
[[ "$(git rev-parse "$commit^")" == "$tested" ]] || say "the tag's commit is a child of the tested commit"
[[ "$(git rev-parse "refs/tags/$tag^{commit}")" == "$commit" ]] || say "the tag is on that child"
grep -q '#2026-11-04"' example-apps/one/build.zig.zon && grep -q 'NEWHASH' example-apps/two/build.zig.zon ||
    say "the pins were bumped"
grep -q 'tags/2026-11-04.tar' example-apps/one/README.md && grep -q 'publishes 2026-10-19 19:35' example-apps/one/README.md ||
    say "the README's URL moved, and its prose did not"
grep -q 'zig-libs#main' example-apps/one/build.zig.zon || say "the commented alternative was left alone"
git tag -l --format='%(contents)' "$tag" | grep -q '^1 commit since 2026-10-19\.$' ||
    say "the notes count tested commits, not the pin commit"
git tag -l --format='%(contents)' "$tag" | grep -q "at $tested " || say "the claim names the tested commit"

# Back to the tested commit, as a separate job's fresh checkout would be.
back_to_tested() {
    git tag -d "$tag" >/dev/null 2>&1
    git checkout -q -f "$tested"
}
back_to_tested

# Refusals of prepare.
bash "$AR" prepare "$commit" "$AR_WORK/b0" >/dev/null 2>&1
check "prepare: HEAD is not the tested commit -> refuse" 1 $?
git checkout -q main
printf 'env:\n  ZIGLIBS_DRY_RUN: "1"\n' > .github/workflows/ci.yml
git commit -qam dry
dry_sha="$(git rev-parse HEAD)"
git checkout -q --detach
bash "$AR" prepare "$dry_sha" "$AR_WORK/b0" >"$OUT/dry.txt" 2>&1
check "prepare: ZIGLIBS_DRY_RUN on -> refuse" 1 $?
grep -q DRY_RUN "$OUT/dry.txt" || say "the dry refusal says why"
git checkout -q main
# Every spelling of "on" refuses (tag-lib.sh ci_dry_run_on), checked here since
# tag.sh, which used to carry these cases, is gone.
for spelling in "'1'" '"1"  # comment' '1' '"true"'; do
    printf 'env:\n  ZIGLIBS_DRY_RUN: %s\n' "$spelling" > .github/workflows/ci.yml
    git commit -qam "dry $spelling"
    s_sha="$(git rev-parse HEAD)"
    git checkout -q --detach
    bash "$AR" prepare "$s_sha" "$AR_WORK/b0" >/dev/null 2>&1
    check "prepare: dry run spelled $spelling -> refuse" 1 $?
    git checkout -q main
done
printf 'env:\n  ZIGLIBS_DRY_RUN: "0"\n' > .github/workflows/ci.yml
git commit -qam real
tested="$(git rev-parse HEAD)"
git checkout -q --detach
FAKE_ZIG_FAIL=1 bash "$AR" prepare "$tested" "$AR_WORK/b0" >/dev/null 2>&1
check "prepare: no package hash -> refuse" 1 $?
[[ "$(git tag -l)" == "2026-10-19" ]] || say "the failed prepare created no tag" "$(git tag -l)"
git checkout -q -f "$tested"

# A good bundle, live on the schedule.
: > "$AR_WORK/out"
AUTO_TAG_LIVE=1 GITHUB_EVENT_NAME=schedule GITHUB_REF=refs/heads/main AUTO_RELEASE_DAY=2026-11-04 \
    GITHUB_OUTPUT="$AR_WORK/out" bash "$AR" prepare "$tested" "$AR_WORK/good" >/dev/null 2>&1
check "prepare live -> succeeds" 0 $?
[[ "$(out_get live)" == 1 ]] || say "the schedule on main with the switch on is live"
tag="$(out_get tag)"; commit="$(out_get commit)"
back_to_tested
# A dispatch that asked for `release: live`, on main, is live too (2026-11-11).
: > "$AR_WORK/out"
AUTO_TAG_LIVE=1 GITHUB_EVENT_NAME=workflow_dispatch ZIGLIBS_RELEASE=live GITHUB_REF=refs/heads/main \
    AUTO_RELEASE_DAY=2026-11-05 GITHUB_OUTPUT="$AR_WORK/out" bash "$AR" prepare "$tested" "$AR_WORK/b0" >/dev/null 2>&1
check "prepare: dispatch with release live -> succeeds" 0 $?
[[ "$(out_get live)" == 1 ]] || say "a release: live dispatch on main is live" "$(out_get live)"
git tag -d 2026-11-05 >/dev/null 2>&1
git checkout -q -f "$tested"
for env_case in "AUTO_TAG_LIVE=0 GITHUB_EVENT_NAME=schedule GITHUB_REF=refs/heads/main" \
    "AUTO_TAG_LIVE=1 GITHUB_EVENT_NAME=schedule GITHUB_REF=refs/heads/side" \
    "AUTO_TAG_LIVE=true GITHUB_EVENT_NAME=schedule GITHUB_REF=refs/heads/main" \
    "AUTO_TAG_LIVE=1 GITHUB_EVENT_NAME=workflow_dispatch ZIGLIBS_RELEASE=dry-run GITHUB_REF=refs/heads/main" \
    "AUTO_TAG_LIVE=1 GITHUB_EVENT_NAME=workflow_dispatch ZIGLIBS_RELEASE=live GITHUB_REF=refs/heads/side" \
    "AUTO_TAG_LIVE=0 GITHUB_EVENT_NAME=workflow_dispatch ZIGLIBS_RELEASE=live GITHUB_REF=refs/heads/main" \
    "AUTO_TAG_LIVE=1 GITHUB_EVENT_NAME=push ZIGLIBS_RELEASE=live GITHUB_REF=refs/heads/main"; do
    : > "$AR_WORK/out"
    env $env_case AUTO_RELEASE_DAY=2026-11-05 GITHUB_OUTPUT="$AR_WORK/out" bash "$AR" prepare "$tested" "$AR_WORK/b0" >/dev/null 2>&1
    [[ "$(out_get live)" == 0 ]] || say "not live: $env_case" "$(out_get live)"
    git tag -d 2026-11-05 >/dev/null 2>&1
    git checkout -q -f "$tested"
done

: > "$AR_WORK/out"
GITHUB_OUTPUT="$AR_WORK/out" bash "$AR" verify-bundle "$tested" "$AR_WORK/good/release.bundle" "$tag" >/dev/null 2>&1
check "verify-bundle: the good bundle -> accepted" 0 $?
[[ "$(out_get tag)" == "$tag" && "$(out_get commit)" == "$commit" ]] || say "verify-bundle hands on what it verified"
[[ "$(out_get object)" == "$(git rev-parse "refs/tags/$tag")" ]] || say "verify-bundle hands on the tag object id"
object="$(git rev-parse "refs/tags/$tag")"
[[ "$(git rev-parse "refs/tags/$tag^{commit}")" == "$commit" ]] || say "the verified tag is left in the repository"
git tag -d "$tag" >/dev/null

# Bad bundles. Each is what a compromised read-only job could hand over, and each
# must be refused for ITS reason, or the test proves nothing (see the top).
forge() { # forge <name> <tag> <reason-to-grep> <label>
    git bundle create -q "$AR_WORK/$1.bundle" "refs/tags/$2" "^$tested" >/dev/null 2>&1
    git tag -d "$2" >/dev/null 2>&1
    git checkout -q -f "$tested"
    bash "$AR" verify-bundle "$tested" "$AR_WORK/$1.bundle" "$2" >"$OUT/forge.txt" 2>&1
    check "verify-bundle: $4 -> refuse" 1 $?
    grep -q "$3" "$OUT/forge.txt" || say "the refusal of '$4' gives its reason" "$(head -1 "$OUT/forge.txt")"
    git rev-parse -q --verify "refs/tags/$2" >/dev/null && say "no unverified tag is left after '$4'"
}
forge_commit() { # a pin commit with an extra edit made by "$1", tagged annotated
    git checkout -q -f "$tested"
    AUTO_RELEASE_DAY=2026-11-04 bash "$AR" prepare "$tested" "$AR_WORK/b0" >/dev/null 2>&1
    git tag -d 2026-11-04 >/dev/null
    eval "$1"
    git add -A
    git commit -q --amend -m pin
    git tag -a -m 2026-11-04 2026-11-04
}
forge_commit 'printf "evil\n" > modules/m/evil.zig'
forge evil-file 2026-11-04 'more than the apps' 'a file outside the apps'
forge_commit 'printf "\n// x\n" >> example-apps/one/build.zig.zon'
forge evil-zon 2026-11-04 'not the tested tree rewritten' 'an extra edit inside a manifest'
forge_commit 'sed -i "s|github.com/o/zig-libs#2026-11-04|evil.example/x#2026-11-04|" example-apps/two/build.zig.zon'
forge evil-url 2026-11-04 'not the tested tree rewritten' 'a pin URL pointing elsewhere'
forge_commit 'sed -i "s|NEWHASH|OTHERHASH|" example-apps/two/build.zig.zon'
forge two-hashes 2026-11-04 'one well-formed package hash' 'two different hashes'
forge_commit 'true'
git commit -q --allow-empty -m second
git tag -f -a -m 2026-11-04 2026-11-04 >/dev/null
forge two-commits 2026-11-04 'parents are not exactly' 'two commits on top'
forge_commit 'true'
git tag -f 2026-11-04 >/dev/null
forge lightweight 2026-11-04 'not an annotated tag' 'a lightweight tag'
forge_commit 'true'
git bundle create -q "$AR_WORK/two-refs.bundle" refs/tags/2026-11-04 HEAD "^$tested" >/dev/null 2>&1
git tag -d 2026-11-04 >/dev/null
git checkout -q -f "$tested"
bash "$AR" verify-bundle "$tested" "$AR_WORK/two-refs.bundle" 2026-11-04 >"$OUT/forge.txt" 2>&1
check "verify-bundle: a second ref in the bundle -> refuse" 1 $?
grep -q 'exactly refs/tags' "$OUT/forge.txt" || say "the refusal of a second ref gives its reason" "$(head -1 "$OUT/forge.txt")"
bash "$AR" verify-bundle "$dry_sha" "$AR_WORK/good/release.bundle" "$tag" >/dev/null 2>&1
check "verify-bundle: HEAD is not the tested commit -> refuse" 1 $?
bash "$AR" verify-bundle "$tested" "$AR_WORK/good/release.bundle" 2026-11-09 >"$OUT/forge.txt" 2>&1
check "verify-bundle: another tag name -> refuse" 1 $?
grep -q 'expected name' "$OUT/forge.txt" || say "the refusal of another name gives its reason" "$(head -1 "$OUT/forge.txt")"
AUTO_RELEASE_DAY=2026-11-05 bash "$AR" verify-bundle "$tested" "$AR_WORK/good/release.bundle" 2026-11-05 >"$OUT/forge.txt" 2>&1
check "verify-bundle: today's name, another tag inside -> refuse" 1 $?
grep -q 'exactly refs/tags' "$OUT/forge.txt" || say "the refusal of a mismatch gives its reason" "$(head -1 "$OUT/forge.txt")"

# Forged tree shapes: `git diff --name-only` sees the same paths for all of them.
forge_commit 'chmod +x example-apps/one/README.md'
forge mode-change 2026-11-04 'not the tested tree rewritten' 'a mode change'
forge_commit 'rm example-apps/one/README.md; ln -s ../two/README.md example-apps/one/README.md'
forge symlink 2026-11-04 'not the tested tree rewritten' 'a symlink'
forge_commit 'rm example-apps/one/README.md; mkdir example-apps/one/README.md; git rm -q --cached example-apps/one/README.md; git update-index --add --cacheinfo 160000,'"$tested"',example-apps/one/README.md'
forge submodule 2026-11-04 'not the tested tree rewritten' 'a submodule'

# The tag message: free text, so bounded and without control characters.
forge_message() { # forge_message <file>: a clean pin commit under an annotated tag with this message
    forge_commit 'true'
    git tag -f -a --cleanup=verbatim -F "$1" 2026-11-04 >/dev/null
}
python3 -c 'print("2026-11-04\n\n" + "x" * 80000)' > "$OUT/msg"
forge_message "$OUT/msg"
forge big-message 2026-11-04 'tag message is' 'an oversized tag message'
printf '2026-11-04\n\nred \033[31m text\n' > "$OUT/msg"
forge_message "$OUT/msg"
forge esc-message 2026-11-04 'control characters' 'an escape in the tag message'
printf '2026-11-04\n\nabc \xe2\x80\xae cba\n' > "$OUT/msg"
forge_message "$OUT/msg"
forge bidi-message 2026-11-04 'control characters' 'a bidi override in the tag message'
printf '2026-11-04\n\nthanks @someone, see #12\n' > "$OUT/msg"
forge_message "$OUT/msg"
forge mention-message 2026-11-04 'mention or an issue link' 'a mention in the tag message'
printf '2026-11-04\n\n## Heading\n\n- %s and %s are code\n' '`@splat`' '`#12`' > "$OUT/msg"
forge_message "$OUT/msg"
git bundle create -q "$AR_WORK/fine-message.bundle" refs/tags/2026-11-04 "^$tested" >/dev/null 2>&1
git tag -d 2026-11-04 >/dev/null
git checkout -q -f "$tested"
bash "$AR" verify-bundle "$tested" "$AR_WORK/fine-message.bundle" 2026-11-04 >"$OUT/forge.txt" 2>&1
check "verify-bundle: headings and code spans in the message -> accepted" 0 $?
git tag -d 2026-11-04 >/dev/null 2>&1

# The name: a far-future tag would stay newest for ever.
git checkout -q -f "$tested"
AUTO_RELEASE_DAY=2099-01-01 bash "$AR" prepare "$tested" "$AR_WORK/future" >/dev/null 2>&1
git tag -d 2099-01-01 >/dev/null
git checkout -q -f "$tested"
bash "$AR" verify-bundle "$tested" "$AR_WORK/future/release.bundle" 2099-01-01 >"$OUT/forge.txt" 2>&1
check "verify-bundle: a far-future name -> refuse" 1 $?
grep -q 'expected name' "$OUT/forge.txt" || say "the refusal of the future gives its reason" "$(head -1 "$OUT/forge.txt")"
# Month end: the run started before midnight, on the last day of the month.
AUTO_RELEASE_DAY=2026-11-30 bash "$AR" prepare "$tested" "$AR_WORK/eom" >/dev/null 2>&1
git tag -d 2026-11-30 >/dev/null
git checkout -q -f "$tested"
AUTO_RELEASE_DAY=2026-12-01 bash "$AR" verify-bundle "$tested" "$AR_WORK/eom/release.bundle" 2026-11-30 >/dev/null 2>&1
check "verify-bundle: month end, started the day before -> accepted" 0 $?
git tag -d 2026-11-30 >/dev/null 2>&1
AUTO_RELEASE_DAY=2026-12-02 bash "$AR" verify-bundle "$tested" "$AR_WORK/eom/release.bundle" 2026-11-30 >/dev/null 2>&1
check "verify-bundle: two days old -> refuse" 1 $?
# The same day's second tag: `.1`, and only `.1`.
git tag -a -m first 2026-11-04 "$tested"
bash "$AR" prepare "$tested" "$AR_WORK/second" >/dev/null 2>&1
git tag -d 2026-11-04.1 >/dev/null
git checkout -q -f "$tested"
bash "$AR" verify-bundle "$tested" "$AR_WORK/second/release.bundle" 2026-11-04.1 >/dev/null 2>&1
check "verify-bundle: the day's second tag as .1 -> accepted" 0 $?
git tag -d 2026-11-04.1 >/dev/null 2>&1
git tag -d 2026-11-04 >/dev/null
# Older than what exists: it would not be the newest, and `since` would skew.
git tag -a -m later 2026-11-05 "$tested"
bash "$AR" verify-bundle "$tested" "$AR_WORK/good/release.bundle" 2026-11-04 >"$OUT/forge.txt" 2>&1
check "verify-bundle: does not sort after the newest tag -> refuse" 1 $?
grep -q 'sort after' "$OUT/forge.txt" || say "the refusal of an old name gives its reason" "$(head -1 "$OUT/forge.txt")"
git tag -d 2026-11-05 >/dev/null
# Taken on origin, though not here.
git tag -a -m someone 2026-11-04 "$tested"
git push -q origin refs/tags/2026-11-04
git tag -d 2026-11-04 >/dev/null
bash "$AR" verify-bundle "$tested" "$AR_WORK/good/release.bundle" 2026-11-04 >"$OUT/forge.txt" 2>&1
check "verify-bundle: the name is taken on origin -> refuse" 1 $?
grep -q 'already on origin' "$OUT/forge.txt" || say "the refusal of a taken name gives its reason" "$(head -1 "$OUT/forge.txt")"
git rev-parse -q --verify refs/tags/2026-11-04 >/dev/null && { say "no unverified tag is left after a taken name"; git tag -d 2026-11-04 >/dev/null; }
# finish must not delete a tag it did not push.
someone="$(git ls-remote origin refs/tags/2026-11-04 | cut -f1)"
: > "$AR_GH_LOG"
bash "$AR" finish 2026-11-04 "$commit" "$object" failure skipped >"$OUT/fin.txt" 2>&1
check "finish: origin holds someone else's tag -> red" 1 $?
[[ "$(git ls-remote origin refs/tags/2026-11-04 | cut -f1)" == "$someone" ]] || say "finish: someone else's tag was left alone"
grep -q 'did not push' "$OUT/fin.txt" || say "finish: says it is not ours" "$(head -1 "$OUT/fin.txt")"
bash "$AR" finish 2026-11-04 "$commit" "$object" success success >/dev/null 2>&1
check "finish: pinned green over someone else's tag -> red" 1 $?
[[ "$(git ls-remote origin refs/tags/2026-11-04 | cut -f1)" == "$someone" && ! -s "$AR_GH_LOG" ]] || say "finish: no Release on someone else's tag"
bash "$AR" finish 2026-11-04 "" "" failure skipped >/dev/null 2>&1
check "finish: release-tag verified nothing, a tag is there -> red" 1 $?
[[ "$(git ls-remote origin refs/tags/2026-11-04 | cut -f1)" == "$someone" ]] || say "finish: nothing verified, nothing deleted"
git push -q origin :refs/tags/2026-11-04
bash "$AR" verify-bundle "$tested" "$AR_WORK/good/release.bundle" 'v1.2.3' >/dev/null 2>&1
check "verify-bundle: not a date tag -> refuse" 1 $?

# finish: the pushed tag either becomes a Release or is deleted. `gh auth
# git-credential` is never asked: origin is a local path.
push_good() {
    git tag -d "$tag" >/dev/null 2>&1
    bash "$AR" verify-bundle "$tested" "$AR_WORK/good/release.bundle" "$tag" >/dev/null 2>&1
    git push -q origin "refs/tags/$tag"
    git tag -d "$tag" >/dev/null 2>&1
    : > "$AR_GH_LOG"
    rm -f "$AR_NOTES"
}
push_good
bash "$AR" finish "$tag" "$commit" "$object" success failure >"$OUT/fin.txt" 2>&1
check "finish: pinned red -> red" 1 $?
[[ -z "$(remote_tag "$tag")" ]] || say "finish: pinned red deleted the tag"
[[ ! -s "$AR_GH_LOG" ]] || say "finish: pinned red created no Release" "$(cat "$AR_GH_LOG")"
for pinned in skipped cancelled ""; do
    push_good
    bash "$AR" finish "$tag" "$commit" "$object" success "$pinned" >/dev/null 2>&1
    check "finish: pinned '${pinned:-empty}' -> red" 1 $?
    [[ -z "$(remote_tag "$tag")" ]] || say "finish: pinned '${pinned:-empty}' deleted the tag"
done
push_good
bash "$AR" finish "$tag" "$dry_sha" "$object" success success >/dev/null 2>&1
check "finish: the tag is not at the verified commit -> red" 1 $?
[[ -z "$(remote_tag "$tag")" ]] || say "finish: a moved tag was deleted"
push_good
FAKE_GH_RC=1 bash "$AR" finish "$tag" "$commit" "$object" success success >/dev/null 2>&1
check "finish: the Release fails -> red" 1 $?
[[ -z "$(remote_tag "$tag")" ]] || say "finish: no Release means no tag"
bash "$AR" finish "$tag" "$commit" "$object" failure skipped >"$OUT/fin.txt" 2>&1
check "finish: no tag on origin -> red, nothing to delete" 1 $?
push_good
bash "$AR" finish "$tag" "$commit" "$object" success success >"$OUT/fin.txt" 2>&1
check "finish: pinned green -> Release" 0 $?
[[ -n "$(remote_tag "$tag")" ]] || say "finish: the tag stays"
grep -q "release create $tag --verify-tag" "$AR_GH_LOG" || say "finish: the Release is cut from the tag" "$(cat "$AR_GH_LOG")"
grep -q 'since 2026-10-19' "$AR_NOTES" || say "finish: the Release body is the tag's message"
git -C "$AR_WORK/origin.git" branch --contains "$commit" 2>/dev/null | grep -q . && say "the pin commit is reachable only from the tag"

# since against a tag whose pin commit sits only under it.
git checkout -q -f "$tested"
: > "$AR_WORK/out"
GITHUB_OUTPUT="$AR_WORK/out" bash "$AR" since >/dev/null 2>&1
# Its Release is not out yet: an orphan. Measured from the last real tag, and loud.
: > "$AR_WORK/out"
GITHUB_OUTPUT="$AR_WORK/out" bash "$AR" since >"$OUT/since.txt" 2>&1
check "since: an orphan tag -> runs" 0 $?
[[ "$(out_get orphan)" == "$tag" ]] || say "since: names the orphan" "$(out_get orphan)"
[[ "$(out_get changed)" == true ]] || say "since: an orphan does not count as the last tag" "$(out_get changed)"
grep -q "::error::.*$tag" "$OUT/since.txt" || say "since: the orphan is an error in the log"
FAKE_GH_RC=1 bash "$AR" since >/dev/null 2>&1
check "since: Releases cannot be read -> error, never a guess" 1 $?
printf '%s\n2026-10-19\n' "$tag" > "$AR_RELEASES"
: > "$AR_WORK/out"
GITHUB_OUTPUT="$AR_WORK/out" bash "$AR" since >/dev/null 2>&1
[[ -z "$(out_get orphan)" ]] || say "since: a tag with a Release is no orphan" "$(out_get orphan)"
[[ "$(out_get changed)" == false ]] || say "since: pin commit off main, no new commit -> changed=false" "$(out_get changed)"
git commit -q --allow-empty -m more
: > "$AR_WORK/out"
GITHUB_OUTPUT="$AR_WORK/out" bash "$AR" since >/dev/null 2>&1
[[ "$(out_get changed)" == true ]] || say "since: pin commit off main, one new commit -> changed=true" "$(out_get changed)"

echo
if [[ $fails -eq 0 ]]; then
    echo "auto-release.sh self-test: all cases behaved"
    exit 0
fi
echo "auto-release.sh self-test: $fails case(s) misbehaved" >&2
exit 1
