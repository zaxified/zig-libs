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
CLE="$SCRIPT_DIR/../checks/check-changelog-entry.py"
[[ -x "$CLE" ]] || { echo "test-pre-commit: $CLE is not executable" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK" || exit 1
git init -q .
git config user.email t@t
git config user.name t
# The hook resolves its sibling checks from `git rev-parse --show-toplevel`, so
# the throwaway repo gets a real copy of the changelog gate. Cases 1-8 below
# therefore run the WHOLE hook, not the fmt half of it.
mkdir -p scripts/checks
cp "$CLE" scripts/checks/check-changelog-entry.py

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

# --------------------------------------------------------------------------
# 9-17: the changelog half. Same construction: a throwaway module, staged
# content only, and every case stated as the pair "this shape must / must not
# be refused" rather than as one green run.
# --------------------------------------------------------------------------
git reset -q --hard >/dev/null
mkdir -p modules/demo/src modules/demo/example

changelog() { # changelog [extra-entry-text]
    {
        printf '# demo — changelog\n\n## Unreleased\n\n'
        [[ -n "${1:-}" ]] && printf -- "- **2026-09-06** — %s\n" "$1"
        printf -- '- **2026-01-01** — New module: a fixture.\n'
    } > modules/demo/CHANGELOG.md
}

# `n` code lines, deliberately none of them starting with `pub`, so each case
# isolates ONE trigger.
body() { # body <n> <marker>
    { echo 'const std = @import("std");'
      echo 'fn helper(x: u32) u32 {'
      echo '    var a: u32 = x;'
      for ((i = 0; i < $1; i++)); do echo "    a = a +% $2 + $i;"; done
      echo '    return a;'
      echo '}'
    } > modules/demo/src/root.zig
}

body 5 1; changelog; git add modules; git commit -qm "demo base"

# 9: THE POSITIVE CONTROL. Well over the threshold, no entry -> refuse.
body 60 2; git add modules
"$HOOK" >/dev/null 2>&1; check "src moves 60 code lines, no entry -> refuse" 1 $?

# 10: the same change WITH a dated bullet -> allow. Nothing else differs, so
# this pins that it is the ENTRY that flips the verdict and not the diff.
changelog "the helper now folds a different constant."; git add modules
"$HOOK" >/dev/null 2>&1; check "same change, dated entry added -> allow" 0 $?

# 11: the escape. Also an entry, so it passes for the same reason -- what is
# being pinned is that the documented wording is not accidentally special-cased
# into a refusal.
changelog "**NO CONSUMER-VISIBLE CHANGE:** helper split, identical output."
git add modules
"$HOOK" >/dev/null 2>&1; check "escape entry -> allow" 0 $?

# 12: an entry that already existed and did NOT move must not satisfy the rule.
# This is the difference between this gate and `zig build check-changelog`,
# which only asks whether the file is there.
git commit -qm "demo entry"
body 130 3; git add modules
"$HOOK" >/dev/null 2>&1; check "changelog present but unchanged -> refuse" 1 $?

# 13: THE EXCLUSION THAT MATTERS. Tests live in `test` blocks inside src/ in
# this collection, so the same 60 lines added as a test must NOT trip it.
git reset -q --hard >/dev/null
{ cat modules/demo/src/root.zig
  echo 'test "a large regression test" {'
  for ((i = 0; i < 60; i++)); do echo "    _ = helper($i);"; done
  echo '}'
} > ./.scratch && mv ./.scratch modules/demo/src/root.zig
git add modules
"$HOOK" >/dev/null 2>&1; check "60 lines added inside a test block -> allow" 0 $?

# 14: one line, and it is a published declaration -> refuse. The case a line
# threshold alone gets backwards.
git reset -q --hard >/dev/null
sed -i 's/^fn helper(x: u32) u32 {/pub fn helper(x: u32, y: u32) u32 {/' modules/demo/src/root.zig
sed -i 's/^    var a: u32 = x;/    var a: u32 = x +% y;/' modules/demo/src/root.zig
git add modules
"$HOOK" >/dev/null 2>&1; check "one changed \`pub fn\` line, no volume -> refuse" 1 $?

# 15: comments are not code. A doc pass over src/ must not demand an entry.
git reset -q --hard >/dev/null
{ for ((i = 0; i < 80; i++)); do echo "// a documentation line $i"; done
  cat modules/demo/src/root.zig
} > ./.scratch && mv ./.scratch modules/demo/src/root.zig
git add modules
"$HOOK" >/dev/null 2>&1; check "80 comment lines added to src -> allow" 0 $?

# 16: only `example/` moved. An example is a consumer of the module, not the
# module, and the rule says so.
git reset -q --hard >/dev/null
for ((i = 0; i < 200; i++)); do echo "const x$i = $i;"; done > modules/demo/example/main.zig
git add modules
"$HOOK" >/dev/null 2>&1; check "200 lines in example/ only -> allow" 0 $?

# 17: VACUITY GUARD. Every "-> allow" case above would also pass if the
# changelog check were never reached at all -- a typo in the path, a
# non-executable bit, a python3 that is not there. Remove the script and the
# one case that MUST be refused stops being refused; if it does not, cases
# 9-16 were proving nothing.
git reset -q --hard >/dev/null
body 60 4; git add modules
"$HOOK" >/dev/null 2>&1; before=$?
mv scripts/checks/check-changelog-entry.py scripts/check-changelog-entry.py.off
"$HOOK" >/dev/null 2>&1; after=$?
mv scripts/check-changelog-entry.py.off scripts/checks/check-changelog-entry.py
if [[ "$before" == 1 && "$after" == 0 ]]; then
    printf '  ok   %-52s\n' "removing the script flips refuse -> allow"
else
    printf '  FAIL %-52s with=%s without=%s\n' "the changelog check is not being reached" "$before" "$after"
    fails=$((fails + 1))
fi

# 18: a staged file git calls TEXT but that is not UTF-8 must not CRASH the
# gate. git decides text-vs-binary by looking for a NUL in the first 8000
# bytes, so a DER certificate or a raw key under `src/testdata/` reaches
# `git diff` and `git show :<path>` as raw bytes. On 2026-09-06 both decoded
# strictly and the gate died with UnicodeDecodeError instead of answering --
# in the diff for `HEAD`, and one call earlier, in the index, for `--staged`,
# which is the mode this hook runs. A crash is worse than a wrong verdict: it
# takes the commit down and says nothing about the question it was asked.
# Found by a peer session, not by this self-test, which is why it is here now.
git reset -q --hard >/dev/null
mkdir -p modules/otp/src/testdata
python3 -c "import sys; sys.stdout.buffer.write(b'0\x82\x01\xf8' + b'A'*200)" \
    > modules/otp/src/testdata/not-utf8.bin
body 30 2; git add modules
out=$("$HOOK" 2>&1); rc=$?
git reset -q --hard >/dev/null; rm -f modules/otp/src/testdata/not-utf8.bin
rmdir modules/otp/src/testdata 2>/dev/null
if [[ "$out" == *UnicodeDecodeError* || "$out" == *Traceback* ]]; then
    printf '  FAIL %-52s\n' "non-UTF-8 staged file crashes the gate"
    fails=$((fails + 1))
else
    printf '  ok   %-52s (exit %s)\n' "non-UTF-8 staged file does not crash" "$rc"
fi

echo
if [[ $fails -eq 0 ]]; then
    echo "pre-commit hook self-test: all cases behaved"
    exit 0
fi
echo "pre-commit hook self-test: $fails case(s) misbehaved" >&2
exit 1
