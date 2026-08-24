const std = @import("std");

// A consumer's build.zig, written the way a consumer writes one: zig-libs is a
// package dependency, and every module this binary needs is taken from it by
// name. Nothing here reaches into the collection's own build — that is the
// point of this directory.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // ReleaseSafe by default. Every safety check stays on, which is what you
    // want from a network-facing binary; `-Doptimize=ReleaseFast` if you have
    // measured that you need it.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const zig_libs = b.dependency("zig_libs", .{ .target = target, .optimize = optimize });

    const exe = b.addExecutable(.{
        .name = "mls-chat",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "mls", .module = zig_libs.module("mls") },
                .{ .name = "framing", .module = zig_libs.module("framing") },
                .{ .name = "lockfree", .module = zig_libs.module("lockfree") },
            },
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Build and run (pass args after --, e.g. -- relay --port 7711)").dependOn(&run.step);
}
