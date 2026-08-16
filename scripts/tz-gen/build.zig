// SPDX-License-Identifier: MIT
const std = @import("std");

// Build-time tool: parses the IANA tzdata TZif files (via std.Tz) and emits
// modules/tz/src/tz_data.zig — a compact, committed table of per-zone
// UTC-offset transitions (>= 1970) plus each zone's POSIX-TZ footer rule for
// dates past the last explicit transition. The generated file IS the pin
// (the tzdata version is recorded in its header); regenerate on a tzdata bump.
//
// Lives under scripts/ rather than modules/ because it is host tooling, not a
// shipped module: it reads the local /usr/share/zoneinfo and is the one place
// `std.Tz` is used. `scripts/` is outside build.zig.zon's `.paths`, so none of
// this reaches a consumer — the `tz` module carries only the generated table.
//
//   zig build run                         # default paths
//   zig build run -- <out.zig> <zoneinfo> # explicit
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "tz-gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run = b.addRunArtifact(exe);
    if (b.args) |a| run.addArgs(a);
    b.step("run", "Generate modules/tz/src/tz_data.zig from IANA tzdata").dependOn(&run.step);
}
