#!/usr/bin/env bash
# The scheduled route to a dated tag (CONVENTIONS §8): what ci.yml's `since` and
# `release-*` jobs do, here so scripts/lib/test-tag.sh can make it say no.
#
#   auto-release.sh since
#       Is there a commit on HEAD's line since the newest date tag? Writes
#       `changed=true|false`. A hand-cut tag's pin commit sits on main; an
#       automatic tag's pin commit sits only under the tag, so what the tag
#       covered is its MERGE BASE with HEAD, which is the commit itself in the
#       first case and its parent in the second.
#
#   auto-release.sh prepare <tested-sha> <out-dir>      READ-ONLY job, runs zig
#       Bump the pins, commit them as a child of <tested-sha>, create the
#       annotated tag there with the generated notes, write
#       <out-dir>/release.bundle and print what a live run would do. Pushes
#       nothing. Writes `tag=`, `commit=`, `live=`.
#
#   auto-release.sh verify-bundle <tested-sha> <bundle> <tag>      WRITE job, no zig
#       Believe nothing the prepare job said: see verify_bundle below. Leaves the
#       verified tag in the local repository. Holds no token while it runs.
#
#   auto-release.sh finish <tag> <commit> <tag-job-result> <pinned-job-result>
#       WRITE job, no zig. Pinned green: create the Release from the tag's own
#       message. Anything else: delete the tag and exit non-zero.
#
# Environment: AUTO_TAG_LIVE, GITHUB_EVENT_NAME, GITHUB_REF, GITHUB_OUTPUT.
set -uo pipefail

LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$LIB/../.." || exit 1
# shellcheck source=scripts/lib/tag-lib.sh
source "$LIB/tag-lib.sh"

TAG_RE='^20[0-9]{2}-[0-9]{2}-[0-9]{2}(\.[0-9]+)?$'

die() {
    echo "auto-release: $*" >&2
    exit 1
}

output() {
    echo "$1"
    [ -z "${GITHUB_OUTPUT:-}" ] || echo "$1" >> "$GITHUB_OUTPUT"
}

cmd_since() {
    local newest base n
    newest="$(newest_date_tag)"
    if [ -z "$newest" ]; then
        echo "auto-release: no date tag yet"
        output "changed=true"
        return 0
    fi
    # A failure here is an error and never "nothing changed": a shallow clone has
    # no merge base, and reading that as a quiet day would stop the releases.
    base="$(git merge-base "$newest^{commit}" HEAD)" || die "no merge base between '$newest' and HEAD (shallow clone?)"
    n="$(git rev-list --count "$base..HEAD")" || die "cannot count $base..HEAD"
    echo "auto-release: newest tag $newest covers up to $base; $n commit(s) since"
    if [ "$n" -gt 0 ]; then output "changed=true"; else output "changed=false"; fi
}

# Live needs all of it, spelled exactly. Everything else is the dry path.
is_live() {
    [ "${AUTO_TAG_LIVE:-0}" = 1 ] && [ "${GITHUB_EVENT_NAME:-}" = schedule ] && [ "${GITHUB_REF:-}" = refs/heads/main ]
}

cmd_prepare() {
    local sha="$1" out="$2" day tag prev commit
    [ "$(git rev-parse HEAD)" = "$sha" ] || die "HEAD is $(git rev-parse HEAD), not the tested commit $sha"
    [ -z "$(git status --porcelain)" ] || die "working tree is dirty"
    if ci_dry_run_on HEAD; then
        die "NOT tagging — ci.yml at $sha has ZIGLIBS_DRY_RUN on, so CI tested nothing."
    fi
    mkdir -p "$out" || die "cannot create $out"
    # Not personal data, and the tag says who cut it: the workflow.
    export GIT_AUTHOR_NAME='github-actions[bot]' GIT_COMMITTER_NAME='github-actions[bot]'
    export GIT_AUTHOR_EMAIL='41898282+github-actions[bot]@users.noreply.github.com'
    export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"

    day="${AUTO_RELEASE_DAY:-$(date -u +%Y-%m-%d)}"
    tag="$(free_tag_name "$day")"
    prev="$(newest_date_tag)"
    bump_app_pins "$tag" || die "refusing to cut '$tag' — example-apps pins could not be bumped"
    commit="$(git rev-parse HEAD)"
    # A tag that carries no pin commit would not be the shape verify-bundle
    # accepts, and would pin the previous tag under this one's name.
    [ "$commit" != "$sha" ] || die "no pin commit was made (no example-apps?) — refusing"
    create_notes_tag "$tag" "$prev" "$sha" "$LIB" || die "could not create the tag"
    git bundle create -q "$out/release.bundle" "refs/tags/$tag" "^$sha" || die "could not write the bundle"

    echo "──── tag message ────"
    git tag -l --format='%(contents)' "$tag"
    echo "─────────────────────"
    if is_live; then
        output "live=1"
    else
        echo "auto-release: DRY, nothing is pushed. A live run would do:"
        echo "  verify-bundle $sha release.bundle $tag"
        echo "  git push origin refs/tags/$tag"
        echo "  scripts/check-apps.sh --pinned   (fresh runner, tag $tag, HEAD $commit)"
        echo "  gh release create $tag --verify-tag --title $tag --notes-file <the tag's message>"
        echo "  on any failure: git push origin :refs/tags/$tag"
        output "live=0"
    fi
    output "tag=$tag"
    output "commit=$commit"
}

# A compromised action in the read-only prepare job controls the bundle, so
# everything that can be derived here is derived here. What this does NOT
# establish is listed in CONVENTIONS §8 and in the tag job's comment in ci.yml.
verify_bundle() {
    local sha="$1" bundle="$2" tag="$3" header heads prereqs commit parents hash hashes wt want got msg_bytes first
    [[ "$tag" =~ $TAG_RE ]] || die "'$tag' is not a date tag name"
    [ -f "$bundle" ] || die "no bundle at $bundle"
    [ "$(git rev-parse HEAD)" = "$sha" ] || die "HEAD is not the tested commit $sha"
    ! git rev-parse -q --verify "refs/tags/$tag" >/dev/null || die "tag '$tag' already exists here"
    ci_dry_run_on HEAD && die "ci.yml at $sha has ZIGLIBS_DRY_RUN on"

    git bundle verify -q "$bundle" >/dev/null 2>&1 || die "the bundle does not verify against this repository"
    # Read the header ourselves: `list-heads` does not show prerequisites.
    header="$(head -c 65536 "$bundle" | LC_ALL=C sed -n '/^$/q;p' | LC_ALL=C tr -d '\000')"
    prereqs="$(printf '%s\n' "$header" | grep -E '^-' | cut -d' ' -f1 | cut -c2-)"
    [ "$prereqs" = "$sha" ] || die "the bundle's prerequisites are not exactly the tested commit: [$prereqs]"
    heads="$(printf '%s\n' "$header" | grep -E '^[0-9a-f]{40,64} ' | cut -d' ' -f2-)"
    [ "$heads" = "refs/tags/$tag" ] || die "the bundle must carry exactly refs/tags/$tag, and carries: [$heads]"

    git -c transfer.fsckObjects=true fetch -q --no-tags "$bundle" "refs/tags/$tag:refs/tags/$tag" ||
        die "could not fetch the tag out of the bundle"
    # From here on a failure must not leave the unverified tag lying around.
    trap 'git tag -d "$tag" >/dev/null 2>&1' EXIT
    [ "$(git cat-file -t "refs/tags/$tag")" = tag ] || die "'$tag' is not an annotated tag"
    [ "$(git cat-file -p "refs/tags/$tag" | sed -n 's/^tag //p' | head -1)" = "$tag" ] ||
        die "the tag object names another tag than '$tag'"
    [ "$(git cat-file -p "refs/tags/$tag" | sed -n 's/^type //p' | head -1)" = commit ] ||
        die "the tag does not point directly at a commit"
    commit="$(git rev-parse "refs/tags/$tag^{commit}")"
    parents="$(git rev-list --parents -n 1 "$commit" | cut -d' ' -f2-)"
    [ "$parents" = "$sha" ] || die "the tagged commit's parents are not exactly the tested commit: [$parents]"
    bad="$(git diff --name-only "$sha" "$commit" | grep -vE '^example-apps/[^/]+/(build\.zig\.zon|README\.md)$')" &&
        die "the pin commit touches more than the apps' manifests and READMEs: $bad"

    # ⭐ The pin commit's whole tree, recomputed: apply the same rewrite to the
    # tested tree with the tag's name and the hash the bundle claims, and compare.
    # What is left to the bundle's word is that one hash value (below).
    hashes="$(git diff "$sha" "$commit" -- 'example-apps/*/build.zig.zon' | sed -nE 's/^\+[[:space:]]*\.hash = "([^"]*)",?.*/\1/p' | LC_ALL=C sort -u)"
    hash="$hashes"
    [[ "$hash" =~ ^zig_libs-[0-9.]+-[A-Za-z0-9_-]+$ ]] || die "the pin commit does not carry one well-formed package hash: [$hashes]"
    wt="$(mktemp -d)" || die "mktemp"
    rmdir "$wt"
    git worktree add -q --detach "$wt" "$sha" || die "could not check out the tested tree"
    got="$(
        cd "$wt" || exit 1
        rewrite_app_pins "$tag" "$hash"
        git add -A example-apps 2>/dev/null
        git write-tree
    )"
    git worktree remove --force "$wt"
    want="$(git rev-parse "$commit^{tree}")"
    [ "$got" = "$want" ] || die "the pin commit's tree ($want) is not the tested tree rewritten for $tag and $hash ($got)"

    # The message is free text. Shape and size only: a Release body is capped by
    # GitHub at 125000 characters.
    msg_bytes="$(git cat-file -p "refs/tags/$tag" | wc -c)"
    [ "$msg_bytes" -le 125000 ] || die "the tag message is $msg_bytes bytes"
    first="$(git tag -l --format='%(contents:subject)' "$tag")"
    [ "$first" = "$tag" ] || die "the tag message's first line is not the tag's name"

    trap - EXIT
    echo "auto-release: bundle verified: $tag = $commit, one commit on $sha, pins only"
}

# Only a token-holding step calls this, and `gh` reads the token from GH_TOKEN, so
# it is on disk nowhere (the checkout keeps no credentials).
remote_git() {
    git -c credential.helper= -c 'credential.helper=!gh auth git-credential' -c core.hooksPath=/dev/null "$@"
}

withdraw() {
    local tag="$1"
    if remote_git push -q origin ":refs/tags/$tag"; then
        echo "auto-release: tag '$tag' withdrawn"
        return 0
    fi
    echo "::error::tag '$tag' could NOT be deleted and stands without a Release. By hand: git push origin :refs/tags/$tag"
    exit 2
}

cmd_finish() {
    local tag="$1" commit="$2" tag_result="$3" pinned="$4" remote notes
    [[ "$tag" =~ $TAG_RE ]] || die "'$tag' is not a date tag name"
    # `ls-remote` tells absent (empty, rc 0) from an error (rc != 0).
    remote="$(remote_git ls-remote origin "refs/tags/$tag")" || {
        echo "::error::cannot read tag '$tag' from origin; it may stand without a Release. By hand: git push origin :refs/tags/$tag"
        exit 2
    }
    if [ -z "$remote" ]; then
        echo "::error::tag '$tag' is not on origin (tag job: $tag_result). No Release."
        exit 1
    fi
    if [ "$pinned" != success ]; then
        echo "::error::the downloader's path is '$pinned' for '$tag': withdrawing it, no Release"
        withdraw "$tag"
        exit 1
    fi
    remote_git fetch -q --no-tags origin "+refs/tags/$tag:refs/tags/$tag" || {
        echo "::error::cannot fetch '$tag': withdrawing it, no Release"
        withdraw "$tag"
        exit 1
    }
    if [ "$(git rev-parse "refs/tags/$tag^{commit}")" != "$commit" ]; then
        echo "::error::tag '$tag' is not at the verified commit $commit: withdrawing it, no Release"
        withdraw "$tag"
        exit 1
    fi
    notes="$(mktemp)"
    git tag -l --format='%(contents:body)' "$tag" > "$notes"
    if ! gh release create "$tag" --verify-tag --title "$tag" --notes-file "$notes"; then
        rm -f "$notes"
        echo "::error::the Release for '$tag' could not be created: withdrawing the tag"
        withdraw "$tag"
        exit 1
    fi
    rm -f "$notes"
    echo "auto-release: '$tag' is final: Release created"
}

case "${1:-}" in
    since) [ $# -eq 1 ] || die "usage: since"; cmd_since ;;
    prepare) [ $# -eq 3 ] || die "usage: prepare <tested-sha> <out-dir>"; cmd_prepare "$2" "$3" ;;
    verify-bundle) [ $# -eq 4 ] || die "usage: verify-bundle <tested-sha> <bundle> <tag>"; verify_bundle "$2" "$3" "$4" ;;
    finish) [ $# -eq 5 ] || die "usage: finish <tag> <commit> <tag-job-result> <pinned-job-result>"; cmd_finish "$2" "$3" "$4" "$5" ;;
    *) die "usage: since | prepare | verify-bundle | finish (see the top of this file)" ;;
esac
