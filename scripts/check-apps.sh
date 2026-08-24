#!/usr/bin/env bash
# Build every example-apps/ project — against this working tree, or through the
# pin the way a person who downloads the directory does.
#
# THE RULE, in one place, because three files used to state it three ways:
#
#   An app's source is written against THIS TREE. Its manifest pins the last
#   dated tag, and that pin exists for the downloader, not for us: a tag is the
#   only ref carrying the all-lanes-green claim, so it is the only thing worth
#   handing a stranger. `scripts/tag.sh` rewrites the pin when a tag is cut, and
#   commits that rewrite INSIDE the tag, so a copy taken from tag T is built
#   against T.
#
# Two modes, and they answer different questions:
#
#   (default)  `zig build --fork=../..` — substitute this working tree for the
#              pinned dependency. Answers: did this commit break a published API
#              that a real consumer reaches through the package manager? Cheap,
#              no network, runs on every CI run.
#
#   --pinned   build from the manifest as written: fetch by URL and hash, and
#              compile the exported package. Answers: does the artifact the
#              customer actually downloads build? This is the only check that
#              goes through `.paths`, so it is the only one that can notice the
#              package omitting a file the apps need (`check-package` covers
#              LICENSE and NOTICE by name and nothing else).
#
#              FAIL-CLOSED: refuses to run unless every pinned tag resolves to
#              HEAD. That is true on a tag ref and nowhere else. Off a tag it
#              would silently become a two-version skew check — a comparison we
#              deliberately do not make, because for a standardised protocol the
#              live interop tests against a foreign implementation dominate it,
#              and for anything else our own previous version is a weak oracle.
#
#   scripts/check-apps.sh            # every app, against the tree
#   scripts/check-apps.sh ssh-demo   # just one
#   scripts/check-apps.sh --run      # build, then RUN each app's smoke.sh
#   scripts/check-apps.sh --pinned   # every app, through its pin (tag refs only)
#
# ⭐ `--run` is the difference between "it compiles" and "it works". The gate
# over `modules/<m>/example/` used to only compile too, and the day it started
# running them, one pass found 22 that did not work. These are whole programs
# with sockets and key files, so the same gap is wider here, not narrower.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PINNED=0
RUN=0
ARGS=()
for a in "$@"; do
    case "$a" in
        --pinned) PINNED=1 ;;
        --run) RUN=1 ;;
        -*) echo "check-apps: unknown option '$a'" >&2; exit 2 ;;
        *) ARGS+=("$a") ;;
    esac
done

mapfile -t DECLARED < <(zig build app-list 2>/dev/null)
if [ ${#DECLARED[@]} -eq 0 ]; then
    echo "check-apps: 'zig build app-list' named no apps — refusing to pass vacuously" >&2
    exit 2
fi

# Declaration vs tree, both ways: an app nobody declared is never built, and a
# declaration whose directory is gone is a claim about nothing.
fail=0
for a in "${DECLARED[@]}"; do
    [ -d "example-apps/$a" ] || { echo "check-apps: build.zig declares app '$a' but example-apps/$a does not exist" >&2; fail=1; }
done
for d in example-apps/*/; do
    [ -d "$d" ] || continue
    n="$(basename "$d")"
    found=0
    for a in "${DECLARED[@]}"; do [ "$a" = "$n" ] && found=1; done
    [ $found -eq 1 ] || { echo "check-apps: example-apps/$n exists but build.zig's example_apps does not list it — it would never be built" >&2; fail=1; }
done
[ $fail -eq 0 ] || exit 1

# The collection's own README carries the catalogue of apps, and it is the first
# page anyone reads. It is hand-written, so it drifts in the direction that
# matters: an app nobody listed is an app nobody finds. `http-service` was
# missing from it for its whole first day, and every other check here was green.
for d in example-apps/*/; do
    [ -d "$d" ] || continue
    n="$(basename "$d")"
    grep -q "]($n/)" example-apps/README.md || {
        echo "check-apps: example-apps/README.md's table does not link example-apps/$n/ — an app nobody lists is an app nobody finds" >&2
        fail=1
    }
done
[ $fail -eq 0 ] || exit 1

# Every app ships a `smoke.sh` that runs it. Required unconditionally, not just
# under `--run`: an app whose only proof is that it compiles is exactly the
# state this directory was in before, and a missing script would otherwise be
# discovered as "nothing ran" — which reads identical to "everything passed".
for d in example-apps/*/; do
    [ -d "$d" ] || continue
    n="$(basename "$d")"
    if [ ! -f "$d/smoke.sh" ]; then
        echo "check-apps: example-apps/$n has no smoke.sh — an app that is only compiled is not an app that works" >&2
        fail=1
    elif [ ! -x "$d/smoke.sh" ]; then
        echo "check-apps: example-apps/$n/smoke.sh is not executable" >&2
        fail=1
    fi
done
[ $fail -eq 0 ] || exit 1

# The app README tells a newcomer how to download that one directory, so it
# spells the tag out in a URL -- a second place the same fact lives. Keep the
# two from drifting: every dated tag the README names must be the tag its own
# manifest pins. `scripts/tag.sh` rewrites both together when a tag is cut.
for d in example-apps/*/; do
    [ -d "$d" ] || continue
    n="$(basename "$d")"
    [ -f "$d/README.md" ] || { echo "check-apps: example-apps/$n has no README.md -- the download instructions are the point of the directory" >&2; fail=1; continue; }
    pin="$(sed -n 's|.*zig-libs#\([0-9][0-9-]*\)".*|\1|p' "$d/build.zig.zon" | head -1)"
    [ -n "$pin" ] || continue   # pinned to a commit or a branch, not a tag
    while read -r found; do
        [ "$found" = "$pin" ] && continue
        echo "check-apps: example-apps/$n/README.md names tag '$found' but build.zig.zon pins '$pin'" >&2
        fail=1
    done < <(grep -oE '20[0-9]{2}-[0-9]{2}-[0-9]{2}' "$d/README.md" | sort -u)
done
[ $fail -eq 0 ] || exit 1

WANT=("${ARGS[@]}")
[ ${#WANT[@]} -eq 0 ] && WANT=("${DECLARED[@]}")

# --pinned only says something where the pin and the commit under test are the
# same content. Prove that here rather than trusting the caller's ref: a guard
# over our own build must be fail-closed, or the first thing it does when the
# assumption breaks is pass.
if [ "$PINNED" = 1 ]; then
    head_sha="$(git rev-parse HEAD)"
    for n in "${WANT[@]}"; do
        z="example-apps/$n/build.zig.zon"
        pin="$(sed -n 's|.*zig-libs#\([0-9][0-9-]*\)".*|\1|p' "$z" | head -1)"
        if [ -z "$pin" ]; then
            echo "check-apps: --pinned: example-apps/$n does not pin a dated tag — nothing to verify against" >&2
            exit 2
        fi
        pin_sha="$(git rev-parse -q --verify "refs/tags/$pin^{commit}" 2>/dev/null || true)"
        if [ -z "$pin_sha" ]; then
            echo "check-apps: --pinned: tag '$pin' (pinned by $n) does not exist here — fetch tags, or you are not on a tag ref" >&2
            exit 2
        fi
        if [ "$pin_sha" != "$head_sha" ]; then
            echo "check-apps: --pinned: $n pins '$pin' = $pin_sha, but HEAD is $head_sha." >&2
            echo "            This mode is for a TAG REF, where the pin and the commit under test" >&2
            echo "            are the same content and the build therefore says something about" >&2
            echo "            THIS commit's package export. Anywhere else it compares two" >&2
            echo "            versions, which is a check this repository deliberately does not" >&2
            echo "            make. Refusing rather than reporting on the wrong question." >&2
            exit 2
        fi
    done
fi

for n in "${WANT[@]}"; do
    [ -d "example-apps/$n" ] || { echo "check-apps: no such app '$n'" >&2; exit 2; }
    if [ "$PINNED" = 1 ]; then
        echo "check-apps: building $n through its pin (fetch by URL + hash)"
        ( cd "example-apps/$n" && zig build ) || {
            echo "check-apps: $n FAILED to build through its pin." >&2
            echo "            The pin resolves to this very commit, so the source is not what" >&2
            echo "            broke — the package export is. Suspect build.zig.zon's .paths" >&2
            echo "            omitting something the apps import, or the pinned hash no longer" >&2
            echo "            matching the tag's tree. This is the path a downloader takes, so" >&2
            echo "            red here means a stranger cannot build what we published." >&2
            exit 1
        }
    else
        echo "check-apps: building $n against the working tree"
        ( cd "example-apps/$n" && zig build --fork=../.. ) || {
            echo "check-apps: $n FAILED to build against this commit." >&2
            echo "            This build used --fork, i.e. THIS working tree, not the tag the app" >&2
            echo "            pins — and the app's source is written against the tree, so the pin" >&2
            echo "            is not what failed. What broke is a published API this commit" >&2
            echo "            changed, and a consumer would meet it one release later." >&2
            exit 1
        }
    fi
done
if [ "$PINNED" = 1 ]; then
    echo "check-apps: ${#WANT[@]} app(s) built through their pins"
else
    echo "check-apps: ${#WANT[@]} app(s) built against the working tree"
fi

# ── running them ──────────────────────────────────────────────────────────
#
# Deliberately AFTER every build: a red smoke test on app one should not hide
# a compile error in app three, and the builds are the cheaper half.
#
# Not combined with `--pinned`, which is about the package export rather than
# about behaviour — the binaries are the same content on a tag ref, so running
# them twice would buy nothing.
#
# ⭐ TWICE, in ReleaseSafe and then in ReleaseFast, because the difference
# between them is a defect class this repository has already shipped: a
# `std.debug.assert` is COMPILED OUT of ReleaseFast, so a fail-open guard is
# invisible in every safe-mode run and only lets the bad thing through in the
# mode a consumer is most likely to build. That is not hypothetical here — a
# public `reset` guarded that way put two headers on the wire. The module lanes
# test three optimize modes; until now the apps tested one.
if [ "$RUN" = 1 ]; then
    for n in "${WANT[@]}"; do
        for mode in ReleaseSafe ReleaseFast; do
            # ReleaseSafe is what the app's own build.zig prefers, so the first
            # pass reuses the binary the build stage already produced.
            if [ "$mode" != ReleaseSafe ]; then
                echo "check-apps: rebuilding $n as $mode"
                ( cd "example-apps/$n" && zig build --fork=../.. "-Doptimize=$mode" ) || {
                    echo "check-apps: $n FAILED to build as $mode." >&2
                    exit 1
                }
            fi
            echo "check-apps: running example-apps/$n/smoke.sh ($mode)"
            if ! ( cd "example-apps/$n" && ./smoke.sh ); then
                echo "check-apps: $n's smoke test FAILED in $mode — the app builds but does not work." >&2
                exit 1
            fi
        done
        # Leave the tree as it was found: the last build above is ReleaseFast,
        # and a developer who runs this then runs the binary by hand should get
        # the mode the app's own build.zig chooses.
        ( cd "example-apps/$n" && zig build --fork=../.. >/dev/null ) || true
    done
    echo "check-apps: ${#WANT[@]} app(s) ran their smoke tests in ReleaseSafe and ReleaseFast"
fi
