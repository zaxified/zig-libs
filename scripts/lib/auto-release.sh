#!/usr/bin/env bash
# The scheduled route to a dated tag (CONVENTIONS §8): what ci.yml's `since` and
# `release-*` jobs do, here so scripts/lib/test-tag.sh can make it say no.
#
#   auto-release.sh since
#       Is there a commit on HEAD's line since the newest date tag that HAS a
#       Release? Writes `changed=true|false` and `orphan=<newer tags with none>`. A
#       hand-cut tag's pin commit sits on main; an automatic tag's pin commit sits
#       only under the tag, so what the tag covered is its MERGE BASE with HEAD,
#       which is the commit itself in the first case and its parent in the second.
#
#   auto-release.sh prepare <tested-sha> <out-dir>      READ-ONLY job, runs zig
#       Bump the pins, commit them as a child of <tested-sha>, create the
#       annotated tag there with the generated notes, write
#       <out-dir>/release.bundle and print what a live run would do. Pushes
#       nothing. Writes `tag=`, `commit=`, `live=`.
#
#   auto-release.sh verify-bundle <tested-sha> <bundle> <tag>      WRITE job, no zig
#       Believe nothing the prepare job said: see verify_bundle below. Leaves the
#       verified tag in the local repository and writes `tag=`, `commit=`, `object=`.
#       Holds no token while it runs.
#
#   auto-release.sh finish <tag> <commit> <object> <tag-job-result> <pinned-job-result>
#       WRITE job, no zig. Pinned green: create the Release from the tag's own
#       message. Anything else: delete the tag and exit non-zero, but only the tag
#       object this run verified; another tag of that name is left alone.
#
# Environment: AUTO_TAG_LIVE, GITHUB_EVENT_NAME, GITHUB_REF, GITHUB_OUTPUT,
# GITHUB_REPOSITORY, and for `since` a GH_TOKEN that can read Releases.
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
    local repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}" released last="" orphans="" t base n
    # A tag without a Release is not final (CONVENTIONS §8), so it says nothing about
    # what was released: a run that died before publishing must not stand in for one.
    # An unreadable list is an error, never "no Releases".
    released="$(gh api --paginate "repos/$repo/releases?per_page=100" --jq '.[] | select(.draft == false) | .tag_name')" ||
        die "cannot read the Releases of $repo"
    while read -r t; do
        [ -n "$t" ] || continue
        if printf '%s\n' "$released" | grep -qxF "$t"; then
            last="$t"
            break
        fi
        orphans="$orphans${orphans:+ }$t"
    done < <(date_tags)
    if [ -n "$orphans" ]; then
        echo "::error::date tag(s) with no Release: $orphans. Unfinished or lost: a person deletes each or cuts its Release (CONVENTIONS §8). This run stays red until then, and tags nothing."
    fi
    output "orphan=$orphans"
    if [ -z "$last" ]; then
        echo "auto-release: no date tag with a Release yet"
        output "changed=true"
        return 0
    fi
    # A failure here is an error and never "nothing changed": a shallow clone has
    # no merge base, and reading that as a quiet day would stop the releases.
    base="$(git merge-base "$last^{commit}" HEAD)" || die "no merge base between '$last' and HEAD (shallow clone?)"
    n="$(git rev-list --count "$base..HEAD")" || die "cannot count $base..HEAD"
    echo "auto-release: newest released tag $last covers up to $base; $n commit(s) since"
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
    local sha="$1" bundle="$2" tag="$3" header heads prereqs commit parents hash hashes wt want got msg first
    local today yesterday newest taken
    [[ "$tag" =~ $TAG_RE ]] || die "'$tag' is not a date tag name"
    [ -f "$bundle" ] || die "no bundle at $bundle"
    [ "$(git rev-parse HEAD)" = "$sha" ] || die "HEAD is not the tested commit $sha"
    ! git rev-parse -q --verify "refs/tags/$tag" >/dev/null || die "tag '$tag' already exists here"
    ci_dry_run_on HEAD && die "ci.yml at $sha has ZIGLIBS_DRY_RUN on"

    # The name is derived here, not read: a far-future date would stay the newest
    # tag for ever. Today's free name, or yesterday's for a run that crossed
    # midnight between prepare and here.
    today="${AUTO_RELEASE_DAY:-$(date -u +%Y-%m-%d)}"
    yesterday="$(date -u -d "$today -1 day" +%Y-%m-%d)" || die "cannot compute the day before $today"
    [ "$tag" = "$(free_tag_name "$today")" ] || [ "$tag" = "$(free_tag_name "$yesterday")" ] ||
        die "'$tag' is not the expected name: $(free_tag_name "$today") or $(free_tag_name "$yesterday")"
    newest="$(newest_date_tag)"
    if [ -n "$newest" ] && [ "$(printf '%s\n%s\n' "$newest" "$tag" | sort -V | tail -1)" != "$tag" ]; then
        die "'$tag' does not sort after the newest date tag '$newest'"
    fi
    # `free_tag_name` sees local tags only. An error here is not "free".
    taken="$(git ls-remote origin "refs/tags/$tag")" || die "cannot read origin's tags"
    [ -z "$taken" ] || die "'$tag' is already on origin: $taken"

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

    # The message is free text and becomes the Release body: bounded (the notes
    # are capped at 60000 bytes), no control characters or bidi overrides, and no
    # mention or issue link outside a code span, which the generator never writes.
    msg="$(mktemp)" || die "mktemp"
    git cat-file tag "refs/tags/$tag" | sed '1,/^$/d' > "$msg"
    [ "$(wc -c < "$msg")" -le 70000 ] || { rm -f "$msg"; die "the tag message is $(wc -c < "$msg") bytes"; }
    if [ "$(LC_ALL=C tr -d '\11\12\40-\176\200-\377' < "$msg" | wc -c)" != 0 ] ||
        LC_ALL=C grep -qP '\xC2[\x80-\x9F]|\xE2\x80[\xAA-\xAE]|\xE2\x81[\xA6-\xA9]' "$msg"; then
        rm -f "$msg"
        die "the tag message holds control characters"
    fi
    if sed 's/`[^`]*`//g' "$msg" | grep -qE '[@#][[:alnum:]]|(^|[^[:alnum:]])GH-[0-9]'; then
        rm -f "$msg"
        die "the tag message holds a mention or an issue link outside a code span"
    fi
    rm -f "$msg"
    first="$(git tag -l --format='%(contents:subject)' "$tag")"
    [ "$first" = "$tag" ] || die "the tag message's first line is not the tag's name"

    trap - EXIT
    echo "auto-release: bundle verified: $tag = $commit, one commit on $sha, pins only"
    output "tag=$tag"
    output "commit=$commit"
    output "object=$(git rev-parse "refs/tags/$tag")"
}

# Only a token-holding step calls this, and `gh` reads the token from GH_TOKEN, so
# it is on disk nowhere (the checkout keeps no credentials).
remote_git() {
    git -c credential.helper= -c 'credential.helper=!gh auth git-credential' -c core.hooksPath=/dev/null "$@"
}

# The lease makes it atomic: only the object this run pushed is ever deleted.
withdraw() {
    local tag="$1" object="$2"
    if remote_git push -q "--force-with-lease=refs/tags/$tag:$object" origin ":refs/tags/$tag"; then
        echo "auto-release: tag '$tag' withdrawn"
        return 0
    fi
    echo "::error::tag '$tag' could NOT be deleted and stands without a Release. By hand: git push origin :refs/tags/$tag"
    exit 2
}

cmd_finish() {
    local tag="$1" commit="$2" object="$3" tag_result="$4" pinned="$5" remote notes
    [[ "$tag" =~ $TAG_RE ]] || die "'$tag' is not a date tag name (tag job: $tag_result, verified nothing)"
    # `ls-remote` tells absent (empty, rc 0) from an error (rc != 0).
    remote="$(remote_git ls-remote origin "refs/tags/$tag")" || {
        echo "::error::cannot read tag '$tag' from origin; it may stand without a Release. By hand: git push origin :refs/tags/$tag"
        exit 2
    }
    if [ -z "$remote" ]; then
        echo "::error::tag '$tag' is not on origin (tag job: $tag_result). No Release."
        exit 1
    fi
    # Not ours: the push was refused because the name was taken, or it never
    # happened and someone else's tag stands there, perhaps with a Release.
    remote="${remote%%[[:space:]]*}"
    if [ -z "$object" ] || [ "$remote" != "$object" ]; then
        echo "::error::tag '$tag' on origin is $remote, not the object this run verified (${object:-none}): this run did not push it. Touching nothing, no Release (tag job: $tag_result)."
        exit 1
    fi
    if [ "$pinned" != success ]; then
        echo "::error::the downloader's path is '$pinned' for '$tag': withdrawing it, no Release"
        withdraw "$tag" "$object"
        exit 1
    fi
    remote_git fetch -q --no-tags origin "+refs/tags/$tag:refs/tags/$tag" || {
        echo "::error::cannot fetch '$tag': withdrawing it, no Release"
        withdraw "$tag" "$object"
        exit 1
    }
    if [ "$(git rev-parse "refs/tags/$tag^{commit}")" != "$commit" ]; then
        echo "::error::tag '$tag' is not at the verified commit $commit: withdrawing it, no Release"
        withdraw "$tag" "$object"
        exit 1
    fi
    notes="$(mktemp)"
    git tag -l --format='%(contents:body)' "$tag" > "$notes"
    if ! gh release create "$tag" --verify-tag --title "$tag" --notes-file "$notes"; then
        rm -f "$notes"
        echo "::error::the Release for '$tag' could not be created: withdrawing the tag"
        withdraw "$tag" "$object"
        exit 1
    fi
    rm -f "$notes"
    echo "auto-release: '$tag' is final: Release created"
}

case "${1:-}" in
    since) [ $# -eq 1 ] || die "usage: since"; cmd_since ;;
    prepare) [ $# -eq 3 ] || die "usage: prepare <tested-sha> <out-dir>"; cmd_prepare "$2" "$3" ;;
    verify-bundle) [ $# -eq 4 ] || die "usage: verify-bundle <tested-sha> <bundle> <tag>"; verify_bundle "$2" "$3" "$4" ;;
    finish) [ $# -eq 6 ] || die "usage: finish <tag> <commit> <object> <tag-job-result> <pinned-job-result>"; cmd_finish "$2" "$3" "$4" "$5" "$6" ;;
    *) die "usage: since | prepare | verify-bundle | finish (see the top of this file)" ;;
esac
