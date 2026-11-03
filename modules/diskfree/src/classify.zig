// SPDX-License-Identifier: MIT
//! Filesystem-type classification over the type NAME a mount table carries
//! (`/proc/self/mounts` column 3, `mountinfo`'s `fs_type`): which mounts a
//! `df`-style listing hides by default (kernel-virtual filesystems with no
//! backing storage, `df` without `-a`) and which are network filesystems
//! (`df -l` drops them).
//!
//! By NAME, not by the kernel's `f_type` magic number: that table is long and
//! grows, and the mount table already carries the name (see SPEC "deliberately
//! not done"). The lists are short, conservative and written from the kernel
//! documentation and `mount(8)`/`filesystems(5)` pages (no foreign source was
//! read): a type missing from them is treated as a real, local filesystem, so
//! the failure mode of an unknown name is "listed", never "silently hidden".
//! `tmpfs`, `devtmpfs`, `ramfs`, `hugetlbfs`, `overlay` and `squashfs` hold
//! real blocks and are NOT classed as pseudo.

const std = @import("std");

/// Kernel-virtual filesystems: no backing storage, their "space" is not disk
/// space. Exact names (a `.subtype` suffix is stripped by `isPseudo`).
const pseudo_types = [_][]const u8{
    "proc",    "sysfs",       "devpts",   "cgroup",       "cgroup2",    "debugfs",
    "tracefs", "securityfs",  "configfs", "fusectl",      "pstore",     "bpf",
    "mqueue",  "binfmt_misc", "autofs",   "rpc_pipefs",   "nfsd",       "selinuxfs",
    "nsfs",    "devfs",       "cpuset",   "resctrl",      "functionfs", "binder",
    "smackfs", "sockfs",      "pipefs",   "anon_inodefs", "rdtgroup",
};

/// Network and distributed filesystems, exact names.
const remote_types = [_][]const u8{
    "nfs",    "nfs4",  "cifs",   "smb3",     "smbfs", "ncpfs",
    "ncp",    "afs",   "coda",   "9p",       "ceph",  "glusterfs",
    "lustre", "panfs", "beegfs", "orangefs", "gpfs",
};

/// `fuse.<subtype>` subtypes that are network clients.
const remote_fuse_subtypes = [_][]const u8{
    "sshfs",  "glusterfs", "cephfs", "davfs", "davfs2",   "s3fs", "gcsfuse",
    "rclone", "curlftpfs", "nfs",    "cifs",  "smbnetfs", "mfs",  "moosefs",
};

fn inList(list: []const []const u8, name: []const u8) bool {
    for (list) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

/// The part of `fs_type` before the first `.` (`fuse.sshfs` -> `fuse`,
/// `ext4` -> `ext4`).
fn base(fs_type: []const u8) []const u8 {
    return fs_type[0 .. std.mem.findScalar(u8, fs_type, '.') orelse fs_type.len];
}

/// True for a kernel-virtual filesystem a default `df` listing hides. A
/// `type.subtype` name is judged by its base (`fuse.portal` is judged by
/// `fuse`, which is not pseudo: FUSE mounts are userspace filesystems and
/// carry their own numbers).
pub fn isPseudo(fs_type: []const u8) bool {
    return inList(&pseudo_types, base(fs_type));
}

/// True for a network or distributed filesystem (`df -l` drops these).
/// `device` is the mount source: the `host:/export` (NFS) and `//host/share`
/// (CIFS) spellings identify a network mount even under a type name this list
/// does not know. A device that merely contains a colon later in a path
/// (`/dev/disk/by-id/usb-a:b`) is not mistaken for one: the colon must come
/// before any `/` and the part after it must start with `/`.
pub fn isRemote(fs_type: []const u8, device: []const u8) bool {
    if (inList(&remote_types, fs_type)) return true;
    if (std.mem.startsWith(u8, fs_type, "fuse.") and inList(&remote_fuse_subtypes, fs_type["fuse.".len..])) return true;
    if (std.mem.startsWith(u8, device, "//") and device.len > 2) return true;
    if (std.mem.findScalar(u8, device, ':')) |c| {
        if (c > 0 and std.mem.findScalar(u8, device[0..c], '/') == null and c + 1 < device.len and device[c + 1] == '/') return true;
    }
    return false;
}

const testing = std.testing;

test "isPseudo: the kernel-virtual names, subtype-stripped; real filesystems untouched" {
    for ([_][]const u8{ "proc", "sysfs", "cgroup2", "devpts", "debugfs", "tracefs", "securityfs", "pstore", "bpf", "mqueue", "binfmt_misc", "autofs", "rpc_pipefs", "fusectl", "nsfs", "configfs" }) |t|
        try testing.expect(isPseudo(t));
    for ([_][]const u8{ "ext4", "xfs", "btrfs", "vfat", "tmpfs", "devtmpfs", "ramfs", "hugetlbfs", "overlay", "squashfs", "f2fs", "ubifs", "jffs2", "efivarfs", "fuse.portal", "fuse", "nfs4", "", "pro", "procfs", "cgroup3" }) |t|
        try testing.expect(!isPseudo(t));
    // A subtype never turns a real base into a pseudo one, nor the reverse.
    try testing.expect(isPseudo("cgroup.legacy"));
    try testing.expect(!isPseudo("ext4.x"));
}

test "isRemote: network type names, fuse subtypes, and the host:/ and // device spellings" {
    for ([_][]const u8{ "nfs", "nfs4", "cifs", "smb3", "9p", "ceph", "glusterfs", "fuse.sshfs", "fuse.rclone" }) |t|
        try testing.expect(isRemote(t, "x"));
    for ([_][]const u8{ "ext4", "tmpfs", "fuse.portal", "fuse.gvfsd-fuse", "fuse", "fuse.", "overlay", "" }) |t|
        try testing.expect(!isRemote(t, "/dev/sda1"));
    // Unknown type name, network-shaped device.
    try testing.expect(isRemote("weirdfs", "server:/export"));
    try testing.expect(isRemote("weirdfs", "//server/share"));
    try testing.expect(isRemote("weirdfs", "10.0.0.1:/vol"));
    // Not network-shaped.
    try testing.expect(!isRemote("ext4", "/dev/disk/by-id/usb-a:/b"));
    try testing.expect(!isRemote("ext4", ":/x"));
    try testing.expect(!isRemote("ext4", "host:"));
    try testing.expect(!isRemote("ext4", "host:rel"));
    try testing.expect(!isRemote("ext4", "//"));
    try testing.expect(!isRemote("ext4", "none"));
}
