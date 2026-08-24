const std = @import("std");

// A consumer's build.zig, written the way a consumer writes one: zig-libs is a
// package dependency, and every module this binary needs is taken from it by
// name. Nothing here reaches into the collection's own build — that is the
// point of this directory.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // ReleaseSafe by default. Every safety check stays on, which is what you
    // want from a binary handling keys; `-Doptimize=ReleaseFast` if you have
    // measured that you need it.
    //
    // ⚠ NOT `standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe })`,
    // which is what the sibling apps started as and which does neither of the
    // two things the sentence above promises. Read std's implementation: given
    // a preferred mode it registers `-Drelease=[bool]` and NOT `-Doptimize` at
    // all, and with no flag it returns `.Debug`.
    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size (default: ReleaseSafe)",
    ) orelse .ReleaseSafe;

    const zig_libs = b.dependency("zig_libs", .{ .target = target, .optimize = optimize });

    const exe = b.addExecutable(.{
        .name = "timecapsule",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "timelock_envelope", .module = zig_libs.module("timelock_envelope") },
                .{ .name = "drand", .module = zig_libs.module("drand") },
                .{ .name = "hqc", .module = zig_libs.module("hqc") },
                .{ .name = "http", .module = zig_libs.module("http") },
                .{ .name = "datefmt", .module = zig_libs.module("datefmt") },
            },
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Build and run (pass args after --, e.g. -- info --in msg.tc)").dependOn(&run.step);
}
