const std = @import("std");

// A consumer's build.zig, written the way a consumer writes one: zig-libs is a
// package dependency, and `ssh` is taken from it by name. Nothing here reaches
// into the collection's own build — that is the point of this directory.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // ReleaseSafe by default. Every safety check stays on, which is what you
    // want from a network-facing binary; `-Doptimize=ReleaseFast` if you have
    // measured that you need it.
    //
    // ⚠ NOT `standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe })`,
    // which is what this was and which does neither of the two things the
    // sentence above promises. Read std's implementation: given a preferred
    // mode it registers `-Drelease=[bool]` and NOT `-Doptimize` at all, and
    // with no flag it returns `.Debug` — so every build of this app was a Debug
    // build, and the documented `-Doptimize=ReleaseFast` was rejected as an
    // invalid option. Found by trying to build the app in a second optimize
    // mode for the smoke gate.
    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size (default: ReleaseSafe)",
    ) orelse .ReleaseSafe;

    const zig_libs = b.dependency("zig_libs", .{ .target = target, .optimize = optimize });

    const exe = b.addExecutable(.{
        .name = "ssh-demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ssh", .module = zig_libs.module("ssh") },
            },
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Build and run (pass args after --, e.g. -- server --port 2222)").dependOn(&run.step);
}
