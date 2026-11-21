// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const mqttz = b.dependency("mqttz", .{ .target = target, .optimize = optimize }).module("mqttz");
    const exe = b.addExecutable(.{
        .name = "mqttz-driver",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "mqttz", .module = mqttz }},
        }),
    });
    b.installArtifact(exe);
}
