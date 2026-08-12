#!/usr/bin/env bash
# Self-test for scripts/hooks/pre-commit — a gate that cannot fail is worthless,
# and a hook is the easiest kind to leave silently broken (edit it wrong and it
# exits 0 forever, which looks exactly like "nothing was ever unformatted").
#
# Runs in a throwaway git repo under a temp dir, so it neither touches this
# repository's index nor depends on its state. Needs `git` and `zig` on PATH.
#
#   usage: scripts/hooks/test-pre-commit.sh
#   exit 0 = every case behaved; exit 1 = a case did not, and says which.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$SCRIPT_DIR/pre-commit"
[[ -x "$HOOK" ]] || { echo "test-pre-commit: $HOOK is not executable" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK" || exit 1
git init -q .
git config user.email t@t
git config user.name t

fails=0
check() { # check <label> <expected-exit> <actual-exit>
    if [[ "$2" == "$3" ]]; then
        printf '  ok   %-52s (exit %s)\n' "$1" "$3"
    else
        printf '  FAIL %-52s expected %s, got %s\n' "$1" "$2" "$3"
        fails=$((fails + 1))
    fi
}

dirty() { printf 'const std   =  @import("std");\npub fn f() void {   }\n' > "$1"; }
clean() { printf 'const std = @import("std");\npub fn f() void {}\n' > "$1"; }

echo "pre-commit hook self-test"

# 1-2: the obvious pair.
dirty a.zig; git add a.zig
"$HOOK" >/dev/null 2>&1; check "staged file is unformatted -> refuse" 1 $?
clean a.zig; git add a.zig
"$HOOK" >/dev/null 2>&1; check "staged file is formatted -> allow" 0 $?

# 3-4: THE reason the hook reads the index rather than the worktree. A
# worktree-reading hook gets both of these backwards: it would refuse a commit
# whose staged content is fine, and allow one whose staged content is not.
dirty a.zig # index still holds the clean blob
"$HOOK" >/dev/null 2>&1; check "index clean, worktree dirty -> allow" 0 $?
git add a.zig; clean a.zig # index now holds the dirty blob
"$HOOK" >/dev/null 2>&1; check "index dirty, worktree clean -> refuse" 1 $?

# 5: nothing staged at all must not fail the commit.
git reset -q; rm -f a.zig
"$HOOK" >/dev/null 2>&1; check "no staged Zig files -> allow" 0 $?

# 6: a deleted file has no content to check and must not trip anything.
clean b.zig; git add b.zig; git commit -qm base
git rm -q b.zig
"$HOOK" >/dev/null 2>&1; check "staged deletion -> allow" 0 $?
git reset -q --hard >/dev/null

# 7: .zon goes through the same path, with --zon.
printf '.{\n    .name   = .x,\n}\n' > c.zon; git add c.zon
"$HOOK" >/dev/null 2>&1; check "staged .zon is unformatted -> refuse" 1 $?
zig fmt c.zon >/dev/null 2>&1; git add c.zon
"$HOOK" >/dev/null 2>&1; check "staged .zon is formatted -> allow" 0 $?

# 8: THE PROPERTY THE HOOK RESTS ON. Trailing whitespace inside a multiline
# string is DATA, and if `zig fmt` ever started tidying it, "formatting is
# behaviour-preserving" would stop being true and this hook would be silently
# rewriting captured vectors. `af6a148` reformatted six files including a
# string expression, and its author verified content by hashing whitespace-
# stripped copies; this pins the same property mechanically. Measured on
# 0.16.0: fmt leaves such a file byte-identical.
git reset -q --hard >/dev/null
printf 'pub const s =\n    \\\\alpha   \n    \\\\beta\t\n;\n' > d.zig
before="$(md5sum d.zig | cut -d' ' -f1)"
zig fmt d.zig >/dev/null 2>&1
after="$(md5sum d.zig | cut -d' ' -f1)"
if [[ "$before" == "$after" ]]; then
    printf '  ok   %-52s\n' "fmt preserves trailing space in a \\\\ string"
else
    printf '  FAIL %-52s zig fmt REWROTE string data\n' "fmt preserves trailing space in a \\\\ string"
    fails=$((fails + 1))
fi

echo
if [[ $fails -eq 0 ]]; then
    echo "pre-commit hook self-test: all cases behaved"
    exit 0
fi
echo "pre-commit hook self-test: $fails case(s) misbehaved" >&2
exit 1
