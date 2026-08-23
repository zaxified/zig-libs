#!/usr/bin/env bash
# Build every example-apps/ project against THIS working tree.
#
# The apps pin a dated tag in their own build.zig.zon, because that is what a
# person who downloads one needs. `--fork` overrides that pin without touching
# the file, so the same directory serves the customer and serves us: this is
# the only check in the repository that compiles the published API through the
# real package machinery, the way a consumer reaches it.
#
#   scripts/check-apps.sh            # every app
#   scripts/check-apps.sh ssh-demo   # just one
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

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

WANT=("$@")
[ ${#WANT[@]} -eq 0 ] && WANT=("${DECLARED[@]}")

for n in "${WANT[@]}"; do
    [ -d "example-apps/$n" ] || { echo "check-apps: no such app '$n'" >&2; exit 2; }
    echo "check-apps: building $n against the working tree"
    ( cd "example-apps/$n" && zig build --fork=../.. ) || {
        echo "check-apps: $n FAILED to build against this commit." >&2
        echo "            It builds against its pinned tag, so this is a published API this" >&2
        echo "            commit broke — the signal a consumer would get, one release later." >&2
        exit 1
    }
done
echo "check-apps: ${#WANT[@]} app(s) built against the working tree"
