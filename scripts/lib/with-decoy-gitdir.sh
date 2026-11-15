#!/usr/bin/env bash
# Run a self-test that builds throwaway git repositories as if a git hook had
# started it: with GIT_DIR exported, pointing at a decoy repository. Fails when
# the decoy changed afterwards, i.e. when the self-test's git calls escaped its
# own scratch repo and would have written into the caller's repository.
#
# Why: git exports GIT_DIR to hooks, and the pre-push hook runs checks-fast. On
# 2026-11-15 three self-tests (hooks/test-pre-commit.sh, lib/test-tag.sh,
# lib/release-notes.py --self-test) inherited it from a push made in a worktree:
# core.bare=true and user t@t landed in the real .git/config and their scratch
# commits on main and on the pushed branch. Each now drops the git environment;
# this wrapper is the gate that keeps it that way (the unfixed versions change
# the decoy, the fixed ones do not -- verified 2026-11-15).
#
#   usage: scripts/lib/with-decoy-gitdir.sh <command> [args...]
#   exit = the command's exit status, or 1 when the decoy was touched.
set -u

decoy_root="$(mktemp -d)"
trap 'rm -rf "$decoy_root"' EXIT
git init -q -b main "$decoy_root/decoy" || exit 1
git -C "$decoy_root/decoy" -c user.name=decoy -c user.email=decoy@invalid \
    commit -q --allow-empty -m seed || exit 1
decoy="$decoy_root/decoy/.git"

snapshot() {
    cat "$decoy/config"
    git --git-dir="$decoy" for-each-ref
    find "$decoy/objects" -type f | wc -l
}

before="$(snapshot)"
GIT_DIR="$decoy" "$@"
rc=$?
after="$(snapshot)"

if [[ "$before" != "$after" ]]; then
    echo "with-decoy-gitdir: '$*' wrote into the repository named by an inherited GIT_DIR" >&2
    diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") >&2
    exit 1
fi
exit "$rc"
