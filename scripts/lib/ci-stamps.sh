#!/usr/bin/env bash
# Fetch a lane's stamps from the newest trusted CI artifact of that name.
#
#   usage: scripts/lib/ci-stamps.sh fetch <artifact-name> <dest-file>
#
# A stamp says a module, at a fingerprint, passed a lane (see "stamps" in
# scripts/test.sh). CI carries a lane's stamps from run to run as an artifact
# named after the lane, uploaded by the lane itself after a green run. An
# artifact rather than an actions/cache entry, for two reasons measured against
# what this workflow already knew about the cache: a cache entry is scoped by
# ref, so what a tag run wrote was invisible to main and to the next tag; and
# an entry nobody touches for seven days is evicted, which would turn a quiet
# week into a full run. Artifacts are neither.
#
# ⚠ TRUST. A stamp SKIPS tests, so only artifacts from runs of THIS repository
# on `main` or on a date tag are read. A pull request from a fork runs this
# workflow too, can upload an artifact of the same name, and can name its own
# branch `main`; `head_repository_id` is what tells the two apart.
#
# No artifact found, or any error, leaves <dest-file> absent and exits 0: no
# stamps means every module runs, which is the safe direction. The log says
# which case it was.
set -uo pipefail

[[ "${1:-}" == fetch && $# -eq 3 ]] || {
    sed -n '4p' "$0" >&2
    exit 2
}
name="$2"
dest="$3"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set -- this runs in CI}"
rm -f "$dest"

repo_id=$(gh api "repos/$repo" --jq '.id') || {
    echo "ci-stamps: cannot read the repository id -- no stamps, every module runs"
    exit 0
}
# Candidates, newest first: unexpired, from runs of THIS repository.
cands=$(gh api -X GET "repos/$repo/actions/artifacts" -f name="$name" -f per_page=100 --jq "
    [ .artifacts[]
      | select(.expired == false)
      | select(.workflow_run.head_repository_id == $repo_id) ]
    | sort_by(.created_at) | reverse | .[] | \"\(.id) \(.workflow_run.id)\"") || cands=""

# ⭐ WHICH RUN UPLOADED IT decides trust, not the branch name alone (audit
# 2026-09-18): a branch can be NAMED like a date, and another workflow in this
# repo could upload an artifact of the same name. Trusted = ci.yml, triggered
# by a push or a manual dispatch, on `main` -- or a push of a date tag that
# exists and points at the run's commit.
trusted() {
    local run="$1" info path event branch sha tagsha
    info=$(gh api "repos/$repo/actions/runs/$run" --jq '"\(.path) \(.event) \(.head_branch) \(.head_sha)"') || return 1
    read -r path event branch sha <<< "$info"
    [[ "$path" == ".github/workflows/ci.yml" ]] || return 1
    [[ "$event" == push || "$event" == workflow_dispatch ]] || return 1
    [[ "$branch" == main ]] && return 0
    [[ "$event" == push && "$branch" =~ ^20[0-9]{2}-[0-9]{2}-[0-9]{2}(\.[0-9]+)?$ ]] || return 1
    tagsha=$(gh api "repos/$repo/commits/refs/tags/$branch" --jq .sha 2>/dev/null) || return 1
    [[ "$tagsha" == "$sha" ]]
}
id=""
while read -r aid rid; do
    [[ -n "$aid" ]] || continue
    if trusted "$rid"; then id="$aid"; break; fi
    echo "ci-stamps: artifact $aid (run $rid) is not from a trusted ci.yml run -- skipped"
done <<< "$cands"
if [[ -z "$id" ]]; then
    echo "ci-stamps: no trusted artifact named '$name' -- no stamps, every module runs"
    exit 0
fi

tmp=$(mktemp)
if gh api "repos/$repo/actions/artifacts/$id/zip" > "$tmp" && unzip -p "$tmp" stamps.tsv > "$dest"; then
    echo "ci-stamps: '$name' artifact $id -> $dest ($(wc -l < "$dest") stamps)"
else
    rm -f "$dest"
    echo "ci-stamps: download of artifact $id failed -- no stamps, every module runs"
fi
rm -f "$tmp"
exit 0
