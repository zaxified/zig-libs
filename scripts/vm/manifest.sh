# VM image manifest. Sourced by fetch-images.sh and run.sh — not executable
# on its own.
#
# Style note: no `declare -A` (see scripts/test-lib.sh's header comment —
# macOS ships bash 3.2). Each image is one row of parallel arrays instead.
#
# Two images, one per libc/platform the netns-gated modules need:
#   openwrt  — musl/busybox, x86-64. Has nftables (nf_tables.ko + friends)
#              and a real kernel, but this build's kmod set has NO tc
#              qdisc/action modules at all (verified empirically, see
#              scripts/vm/README.md) — route tc-needing tests to debian.
#   debian   — glibc, Debian 13 (trixie) "nocloud" cloud image. Full distro
#              kernel; verified to have sch_netem/sch_htb/sch_tbf/act_gact/
#              cls_u32/cls_flower all loadable and tc/iproute2 installed.
#              Needs a real user+password bootstrapped via QEMU fw_cfg
#              credentials (see fetch-images.sh's sibling, run.sh) because
#              "nocloud" only means "no cloud-init datasource", NOT "no
#              systemd-firstboot" — an unseeded image hangs at an
#              interactive locale/timezone/root-password wizard otherwise.
#
# Exact versions, not "latest": reproducibility. The sha256 is checked after
# every download (see fetch-images.sh verify_sha256) and a mismatch deletes
# the partial file and aborts loudly — never run an unverified image.

VM_IMAGE_NAMES=(openwrt debian)

# openwrt
VM_OPENWRT_FILE="openwrt-25.12.4-x86-64-ext4.img"
VM_OPENWRT_URL="https://downloads.openwrt.org/releases/25.12.4/targets/x86/64/openwrt-25.12.4-x86-64-generic-ext4-combined.img.gz"
VM_OPENWRT_GZ=1  # fetched file is gzip-compressed; decompress after verifying the .gz's own sha256
VM_OPENWRT_GZ_SHA256="9d080bcae28d7cdf86dabb4b29c10d36d89e0bd79e20a4799454380bc1619695"
# Of a *pristine* decompression of the .gz above — computed directly from a
# fresh download, NOT from axp's local copy. Those two turned out to
# DIFFER (same 126353408 byte size, different sha256): axp's copy has
# apparently been booted without -snapshot at some point in its own history
# and picked up real state. Pinning the checksum from the local copy would
# have been circular (it'd "verify" a possibly-modified image against
# itself) — exactly the supply-chain hole this manifest exists to close.
# Verified by fetching+decompressing independently and diffing both sha256s.
VM_OPENWRT_SHA256="0a9ef9a7364d5a45ad495529af06aa17b14b6fa41cba4f7d0114b48dd9cb396b"
# A fresh clone has no axp checkout; this is just a fast-path so the common
# case (this dev machine) doesn't re-download 126 MB it already has — BUT
# fetch-images.sh verifies it against VM_OPENWRT_SHA256 above before trusting
# it, and falls back to a real download on a mismatch (which, per the note
# above, is exactly what happens with this specific local copy today).
VM_OPENWRT_LOCAL_REUSE="$HOME/workspace/axp/DEV/vm-openwrt/openwrt-25.12.4-x86-64-ext4.img"

# debian
VM_DEBIAN_FILE="debian-13-nocloud-amd64.qcow2"
VM_DEBIAN_URL="https://cloud.debian.org/images/cloud/trixie/20260722-2547/debian-13-nocloud-amd64-20260722-2547.qcow2"
VM_DEBIAN_GZ=0
VM_DEBIAN_SHA256_ALGO="sha512"  # Debian only publishes SHA512SUMS for cloud images
VM_DEBIAN_SHA512="cb22bf0acb0718a2d9a8c88534f950937bb8439116c0bf8eff52792e88da982a8e2930b6ae25c175db0bce4db6a1c3be5a2f05aa1960e5fc442a3e0a70f8a042"
VM_DEBIAN_LOCAL_REUSE=""
