#!/usr/bin/env bash
# Build tools/ks_peer.zig against karlseguin/websocket.zig (MIT) outside the repository
# and print the binary's path. Usage (from the repository root):
#
#   modules/websocket/tools/ks_build.sh [WORK_DIR]      # default: .zig-cache/ks-work
#
# The library is cloned once (a shallow clone of the Zig 0.17 default branch; set
# KS_REV to check out another commit) and read before its first build: its build.zig
# has no dependency, no network access and no step outside the package. The output is
# a scratch package (build.zig + build.zig.zon) that depends on the clone by path.
set -euo pipefail
work="${1:-.zig-cache/ks-work}"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$work"
work="$(cd "$work" && pwd)"
if [ ! -d "$work/ks/.git" ]; then
    git clone --depth 1 https://github.com/karlseguin/websocket.zig "$work/ks" >&2
fi
if [ -n "${KS_REV:-}" ]; then git -C "$work/ks" fetch --depth 1 origin "$KS_REV" >&2 && git -C "$work/ks" checkout -q FETCH_HEAD >&2; fi
mkdir -p "$work/app"
cp "$here/ks_peer.zig" "$work/app/main.zig"
cat > "$work/app/build.zig" <<'ZIG'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const dep = b.dependency("websocket", .{ .target = b.graph.host, .optimize = optimize });
    const exe = b.addExecutable(.{
        .name = "ks_peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{.{ .name = "websocket", .module = dep.module("websocket") }},
        }),
    });
    b.installArtifact(exe);
}
ZIG
cat > "$work/app/build.zig.zon" <<'ZON'
.{
    .name = .ks_peer,
    .version = "0.0.0",
    .fingerprint = 0xa08ac6b138cb61c4,
    .dependencies = .{ .websocket = .{ .path = "../ks" } },
    .paths = .{ "build.zig", "build.zig.zon", "main.zig" },
}
ZON
(cd "$work/app" && zig build -Doptimize=ReleaseSafe --prefix "$work/bin" >&2)
echo "$work/bin/bin/ks_peer"
echo "ks commit: $(git -C "$work/ks" rev-parse --short HEAD)" >&2
