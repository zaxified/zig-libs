#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Consistency of the consumer build options (CONVENTIONS.md §4.2).

Every module whose sources import `zl_options` must have:
  * a `## Build options` section in its SPEC.md naming each of its knobs by
    its command-line name (`<module>-<knob>`, declared in build.zig);
  * a size probe, `modules/<m>/tools/sizeprobe.zig` (the `small` lane builds it);
  * a floor row in scripts/checks/small-size-expected.tsv.
And every build.zig knob `<module>-<knob>` must belong to such a module, every
floor row too. Silent on success (scripts/test.sh's `step` treats stderr as a
failure). The `small` lane's module set is computed from the same import
(`scripts/test.sh small`), so a module that reads options cannot be left out
of it, and this check makes sure it cannot be left undocumented either.
"""
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parents[2]
errors = []

readers = set()
for src in (root / "modules").glob("*/src/**/*.zig"):
    if '@import("zl_options")' in src.read_text(encoding="utf-8", errors="replace"):
        readers.add(src.relative_to(root / "modules").parts[0])

build = (root / "build.zig").read_text(encoding="utf-8")
knobs = {}  # module -> [cli names]
for name in re.findall(r'b\.option\(\s*[^,]+,\s*"([a-z0-9]+-[a-z0-9-]+)"', build):
    if name in ("strict-debug", "test-filter"):
        continue
    mod = next((m for m in sorted(readers, key=len, reverse=True) if name.startswith(m + "-")), None)
    if mod is None:
        # Only the knobs of the zl_options block are in scope: they follow
        # the `zl_options.addOption` that carries them.
        if re.search(r'zl_options\.addOption\([^;]*"' + re.escape(name) + '"', build, re.S):
            errors.append(f"build.zig: knob '{name}' belongs to no module that imports zl_options")
        continue
    knobs.setdefault(mod, []).append(name)

floors = set()
tsv = root / "scripts/checks/small-size-expected.tsv"
for line in tsv.read_text(encoding="utf-8").splitlines():
    if line and not line.startswith("#"):
        floors.add(line.split("\t")[0])

for m in sorted(readers):
    spec = (root / "modules" / m / "SPEC.md").read_text(encoding="utf-8")
    if not re.search(r"^## Build options$", spec, re.M):
        errors.append(f"modules/{m}: imports zl_options but SPEC.md has no '## Build options' section")
    else:
        section = spec.split("## Build options", 1)[1].split("\n## ", 1)[0]
        for k in knobs.get(m, []):
            if k not in section:
                errors.append(f"modules/{m}/SPEC.md § Build options does not name its knob '{k}'")
    if not knobs.get(m):
        errors.append(f"modules/{m}: imports zl_options but build.zig declares no '{m}-<knob>' option")
    if not (root / "modules" / m / "tools/sizeprobe.zig").exists():
        errors.append(f"modules/{m}: imports zl_options but has no tools/sizeprobe.zig")
    if m not in floors:
        errors.append(f"modules/{m}: imports zl_options but has no row in {tsv.relative_to(root)}")
for m in sorted(floors - readers):
    errors.append(f"{tsv.relative_to(root)}: row '{m}' for a module that does not import zl_options")

for e in errors:
    print(f"check-build-options: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
