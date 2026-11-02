# shellcheck shell=bash
# What cutting a dated tag means, shared by the two routes to one: scripts/tag.sh
# (by hand) and scripts/lib/auto-release.sh (a scheduled CI run). Sourced, sets no
# shell options, and works on the current directory, which must be a repo root.

# Exit 0 when ci.yml at <rev> has ZIGLIBS_DRY_RUN on. A DRY-RUN CI proves the
# pipeline and nothing about the code (see the ZIGLIBS_DRY_RUN block at the top of
# ci.yml), so its green is not a tag's.
# Fail closed: any `ZIGLIBS_DRY_RUN:` line whose value is not literally 0 --
# quoted either way, with or without a trailing comment -- counts as ON. The
# first version matched only `"1"` exactly and let `'1'` through (audit).
ci_dry_run_on() {
    local rev="$1" val
    val="$(git show "$rev:.github/workflows/ci.yml" 2>/dev/null |
        sed -nE 's/^[[:space:]]*ZIGLIBS_DRY_RUN:[[:space:]]*//p' | head -1 |
        sed -E 's/[[:space:]]*#.*$//; s/^["'"'"']//; s/["'"'"'][[:space:]]*$//; s/[[:space:]]*$//')"
    git show "$rev:.github/workflows/ci.yml" 2>/dev/null | grep -qE '^[[:space:]]*ZIGLIBS_DRY_RUN:' && [[ "$val" != "0" ]]
}

# Newest date tag by name, ignoring anything that is not one (`v0.1.0`, or
# `2026-08-15-experiment`). Prints nothing when there is none.
date_tags() {
    git tag -l '20*' --sort=-v:refname | grep -E '^20[0-9]{2}-[0-9]{2}-[0-9]{2}(\.[0-9]+)?$'
    return 0
}
newest_date_tag() {
    date_tags | head -1
    return 0
}

# A free name for <day>: 2026-08-12, then 2026-08-12.1, ...
free_tag_name() {
    local day="$1" tag="$1" n=1
    while git rev-parse -q --verify "refs/tags/$tag" >/dev/null; do
        tag="$day.$n"
        n=$((n + 1))
    done
    printf '%s\n' "$tag"
}

# Rewrite the apps' pins to <tag> and <package hash> in the working tree, and
# nothing else. Deterministic from those two values and the tree: the release-tag
# job re-runs exactly this to check what a read-only job handed it.
#
# Only the FIRST .url/.hash pair is touched. That is the live pin; the commented
# `#main` / `#<commit>` alternatives below it are left as written.
rewrite_app_pins() {
    local newtag="$1" pkg_hash="$2" z oldtag
    for z in example-apps/*/build.zig.zon; do
        [ -f "$z" ] || continue
        oldtag="$(sed -n 's|.*zig-libs#\([0-9][-0-9.]*\)".*|\1|p' "$z" | head -1)"
        sed -i "0,/zig-libs#/{s|\(zig-libs#\)[^\"]*|\1$newtag|}" "$z"
        sed -i "0,/\.hash = /{s|\(\.hash = \"\)[^\"]*|\1$pkg_hash|}" "$z"
        # The README's download URL names the same tag; check-apps.sh fails if
        # the two disagree, so they move together or not at all.
        #
        # ⚠ SCOPED to the tag's three real forms (`tags/…`, `zig-libs-…`,
        # `-b …`). A whole-file `s|$oldtag|$newtag|g` also rewrote prose that
        # merely shared the date — timecapsule's README says "publishes
        # 2026-08-24 19:35:15 UTC" as an example — silently corrupting it on
        # every tag cut.
        if [ -n "$oldtag" ] && [ -f "$(dirname "$z")/README.md" ]; then
            sed -i -E "s#(tags/|zig-libs-|-b )$oldtag#\\1$newtag#g" "$(dirname "$z")/README.md"
        fi
    done
}

# The apps under example-apps/ pin zig-libs by tag, because that is what a
# person who downloads one needs. Bump them to the tag being cut and commit, so a
# copy taken from tag T is built against T rather than against T-1.
#
# Only possible because example-apps/ is OUTSIDE `.paths`: editing an app does
# not change the package hash, so the hash written here stays correct after the
# very commit that writes it. Verified by hashing a clean export with and
# without an example-apps/ tree — identical.
bump_app_pins() {
    local newtag="$1" export_dir pkg_hash
    [ -d example-apps ] || return 0
    # Off tmpfs: this extracts a full ~54 MB repo archive, and /tmp is RAM here
    # (the house rule that closed a prior OOM). test.sh redirects TMPDIR for its
    # own children but does not run this; `.zig-cache` is the repo's scratch.
    mkdir -p .zig-cache
    export_dir="$(mktemp -d "$PWD/.zig-cache/tag-export.XXXXXX")"
    git archive HEAD | tar -x -C "$export_dir"
    if ! pkg_hash="$(zig fetch "$export_dir" 2>/dev/null)"; then
        echo "tag: could not compute the package hash — example-apps pins NOT bumped" >&2
        rm -rf "$export_dir"
        return 1
    fi
    rm -rf "$export_dir"
    rewrite_app_pins "$newtag" "$pkg_hash"
    if ! git diff --quiet -- example-apps; then
        git add example-apps
        git commit -q -m "example-apps: pin $newtag" -m "So a copy taken from this tag builds against this tag. example-apps/ is outside build.zig.zon's .paths, so this commit does not change the package hash it just wrote."
        echo "tag: example-apps pins bumped to $newtag ($pkg_hash)"
    fi
}

# Create annotated tag <tag> on HEAD with the generated notes for <prev>..<notes
# rev> as its message. <prev> may be empty (no tag yet).
#
# ⚠ `--cleanup=verbatim`: the default for `git tag -F` is `strip`, which deletes
# every line starting with `#`, and those are the notes' section headings.
create_notes_tag() {
    local tag="$1" prev="$2" rev="$3" lib="$4" msg
    msg="$(mktemp)"
    {
        printf '%s\n\n' "$tag"
        if [ -n "$prev" ]; then
            python3 -I "$lib/release-notes.py" "$prev" "$rev" || {
                rm -f "$msg"
                return 1
            }
        else
            python3 -I "$lib/release-notes.py" --claim "$rev" || {
                rm -f "$msg"
                return 1
            }
        fi
    } > "$msg"
    git tag -a --cleanup=verbatim -F "$msg" "$tag" || {
        rm -f "$msg"
        return 1
    }
    rm -f "$msg"
}
