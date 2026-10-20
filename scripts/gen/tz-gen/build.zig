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
//   zig build run -- <out.zig> <zoneinfo> [<full-out.zig>] # explicit; a third path also writes the pre-1970 variant
pub fn build(b: *std.Build) void {
    // LLVM unless -Dselfhosted: the self-hosted backend is for the edit loop only.
    const selfhosted = b.option(bool, "selfhosted", "Use Zig's self-hosted backend in Debug (edit loop only)") orelse false;
    const use_llvm: ?bool = if (selfhosted) null else true;
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The POSIX footer parser is the module's own file (std-only), so the
    // footers stored in the table are parsed by exactly the code that parses
    // a hand-built zone's footer at run time.
    const posix = b.createModule(.{
        .root_source_file = b.path("../../../modules/tz/src/posix.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .use_llvm = use_llvm,
        .name = "tz-gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "posix", .module = posix }},
        }),
    });

    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();
    b.step("run", "Generate modules/tz/src/tz_data.zig from IANA tzdata").dependOn(&run.step);
}
