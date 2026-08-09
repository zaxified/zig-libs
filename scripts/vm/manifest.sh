# VM image manifest. Sourced by fetch-images.sh and run.sh — not executable
# on its own.
#
# Style note: no `declare -A` (see scripts/test-lib.sh's header comment —
# macOS ships bash 3.2). Each image is one row of parallel arrays instead.
#
# Two images, one per libc/platform the netns-gated modules need:
#   openwrt  — musl/busybox, x86-64. Has nftables (nf_tables.ko + friends)
#              and a real kernel. The *stock* build's kmod set has NO tc
#              qdisc/action modules at all and no `tc` binary (verified
#              empirically, see scripts/vm/README.md); the PROVISIONED build
#              (scripts/vm/provision.sh, official ImageBuilder) adds both —
#              see VM_OPENWRT_PACKAGES below.
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

# ── two-stage trust model ────────────────────────────────────────────────
#
# Stage 1 — UPSTREAM, cryptographically pinned. Everything below with a
# *_SHA256 / *_SHA512 next to a *_URL is an artifact somebody else built and
# published; fetch-images.sh verifies every one of them after download and
# refuses to leave an unverified file behind. That is a real supply-chain
# guarantee and it does not change.
#
# Stage 2 — DERIVED, not upstream-verifiable. provision.sh takes a stage-1
# artifact and *changes* it (installs packages). The resulting image's own
# SHA-256 is a fact about this machine's build, not a signature from anyone.
# It cannot be pinned here: it would differ per host/date/mirror state, and
# writing it down as if it were an upstream checksum would be a lie about
# where the trust comes from.
#
# What IS reproducible about a provisioned image is its RECIPE:
#     (upstream artifact checksum, package list, platform, recipe version)
# — the tuple hashed by scripts/vm/recipe.sh. Provisioned images are named
# and cached by that recipe hash, and each carries a `.provenance` sidecar
# recording both the recipe hash (the reproducible part) and the derived
# image's own sha256 (labelled "locally derived, change-detection only").
#
# So: to add a prerequisite to a guest, edit VM_OPENWRT_PACKAGES /
# VM_DEBIAN_PACKAGES below — nothing else. The hash changes, the cache
# misses, the image is rebuilt.

# Bumped by hand when provision.sh's *procedure* changes in a way that makes
# previously-built images non-equivalent (not for cosmetic edits). Part of
# the recipe, so bumping it invalidates every cached provisioned image.
VM_RECIPE_VERSION=1

VM_IMAGE_NAMES=(openwrt debian imagebuilder)

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

# ── openwrt provisioning: the official ImageBuilder ──────────────────────
# Same pinned release as the stock image above, from the same target
# directory and the same published `sha256sums` file — so this is verified
# exactly the way the stock image is (stage 1). ImageBuilder is fully
# self-contained (it ships its own host toolchain in staging_dir/host/bin)
# and runs unprivileged: no sudo, no loop mounts, no new host packages.
VM_OPENWRT_IB_FILE="openwrt-imagebuilder-25.12.4-x86-64.Linux-x86_64.tar.zst"
VM_OPENWRT_IB_URL="https://downloads.openwrt.org/releases/25.12.4/targets/x86/64/openwrt-imagebuilder-25.12.4-x86-64.Linux-x86_64.tar.zst"
VM_OPENWRT_IB_SHA256="53c061b15aef20173c1f938b014103785fb2370f19693518de9c8a29d840ee9d"
# `make info` in the ImageBuilder lists exactly one profile for x86/64.
VM_OPENWRT_IB_PROFILE="generic"
# Which of the ~10 artifacts `make image` drops in bin/targets/x86/64/ we
# take: the same ext4-combined variant the stock image is, so the boot path
# (BIOS grub, /dev/sda1+sda2, if=ide) is byte-for-byte the same shape and
# boot-openwrt.exp needs no changes.
VM_OPENWRT_IB_ARTIFACT="openwrt-25.12.4-x86-64-generic-ext4-combined.img.gz"

# DECLARATIVE package list for the provisioned OpenWRT image. Add a line to
# gain a prerequisite; that changes the recipe hash and forces a rebuild.
#
# Every name below was read out of the ImageBuilder's OWN apk index
# (`apk adbdump packages.adb` over the repositories in the IB's
# `repositories` file), not guessed, and the .ko payload of each kmod was
# read out of the .apk itself. What that turned up:
#
#   tc-full               — OpenWRT splits iproute2's tc into tc-tiny (the
#                           default `provides: tc`, provider-priority 100),
#                           tc-full and tc-bpf. tc-full is the one with the
#                           complete qdisc/filter/action module set
#                           (installed-size 460329 vs tc-tiny's 365697, and
#                           it alone pulls libxtables12). iproute2 6.18.0.
#   kmod-sched-core       — act_gact, act_mirred, act_skbedit, cls_basic,
#                           cls_flow, cls_fw, cls_matchall, cls_route,
#                           cls_u32, em_u32, sch_hfsc, sch_htb, sch_ingress,
#                           sch_tbf. (So htb/tbf/u32/gact all come from here,
#                           and tc-full depends on it anyway.)
#   kmod-sched            — act_csum, act_pedit, act_simple, act_skbmod,
#                           em_*, sch_codel, sch_ets, sch_fq, sch_gred,
#                           sch_multiq, sch_sfq, sch_teql. Needed as
#                           kmod-netem's declared dependency.
#   kmod-netem            — sch_netem. NOT called kmod-sched-netem: netem is
#                           its own top-level package ("Kernel modules for
#                           emulating the properties of wide area networks"),
#                           outside the kmod-sched-* namespace entirely.
#   kmod-sched-flower     — cls_flower (its only .ko).
#   kmod-sched-act-police — act_police. Not in kmod-sched-core; the tc suite
#                           builds a two-action u32 PIPE chain ending in a
#                           policer (modules/tc/src/root.zig, "filter action
#                           list" test), so it is required, and no amount of
#                           kmod-sched* guessing would have produced it.
#   kmod-ifb              — ifb.ko (ingress redirect target; wanted by the
#                           planned S2 edge-shaper work).
#   kmod-veth             — veth.ko (pairs for netns-style topologies).
#
# Not listed and not needed: sch_fq_codel is built into this kernel
# (`modprobe sch_fq_codel` succeeds on the stock image too).
VM_OPENWRT_PACKAGES=(
    tc-full
    kmod-sched-core
    kmod-sched
    kmod-netem
    kmod-sched-flower
    kmod-sched-act-police
    kmod-ifb
    kmod-veth
)

# debian
VM_DEBIAN_FILE="debian-13-nocloud-amd64.qcow2"
VM_DEBIAN_URL="https://cloud.debian.org/images/cloud/trixie/20260722-2547/debian-13-nocloud-amd64-20260722-2547.qcow2"
VM_DEBIAN_GZ=0
VM_DEBIAN_SHA256_ALGO="sha512"  # Debian only publishes SHA512SUMS for cloud images
VM_DEBIAN_SHA512="cb22bf0acb0718a2d9a8c88534f950937bb8439116c0bf8eff52792e88da982a8e2930b6ae25c175db0bce4db6a1c3be5a2f05aa1960e5fc442a3e0a70f8a042"
VM_DEBIAN_LOCAL_REUSE=""

# DECLARATIVE package list for the provisioned Debian image, installed by
# booting the guest for real and running apt-get inside it (provision.sh /
# provision-debian.exp). Deliberately NOT libguestfs/virt-customize: that
# needs /boot/vmlinuz-* readable, which is root-only on this host, and
# widening that is out of scope.
#
# Verified reachable over plain `-netdev user` (QEMU slirp) before relying on
# it: the nocloud image's sources.list points at deb.debian.org via
# /etc/apt/mirrors/*.list, systemd-resolved's stub resolves through slirp's
# DNS at 10.0.2.3, and `apt-get update` fetched 28.4 MB in 38 s. No proxy, no
# extra resolver config needed.
#
# iproute2 is already present on the stock image; it is listed anyway so the
# guarantee is declared rather than assumed (apt makes that a no-op).
VM_DEBIAN_PACKAGES=(
    iproute2
    ethtool
    kmod
    bpftool
    # isis-spf's anchor: a real IS-IS speaker whose SPF result we capture
    # ourselves. FRR is GPL, but GPLv2 §0 restricts only the program, not its
    # output — a routing table computed from our topology is not a work based
    # on FRR, so capturing here is licence-clean where vendoring their
    # GPL-licensed topotest fixtures would not be.
    frr
    # nl80211's anchor for the WPA2 half of NL80211_CMD_CONNECT (wave-2 F7).
    # `iw` has no WPA mode, so the only tool that emits a real WPA2-PSK
    # CONNECT is a supplicant, and it needs an AP to connect to. The kernel
    # supplies both radios: mac80211_hwsim IS present in this image's stock
    # cloud kernel (verified: `modprobe mac80211_hwsim` -> phy0/phy1,
    # wlan0/wlan1), so hostapd runs the AP on one and wpa_supplicant the STA
    # on the other, entirely inside the guest, touching no real radio.
    # strace is the same capture mechanism every other golden in this repo was
    # taken with. All three are capture-time-only: what lands in the tree is
    # frozen bytes, and no committed test needs this image to run.
    wpasupplicant
    hostapd
    strace
    # fleetsim's live lane needs a real third-party SCADA master to point at a
    # simulated device. Every one of them is a Python library (see
    # VM_DEBIAN_PIP below), so the interpreter and pip come from apt and the
    # masters themselves from PyPI at their pinned versions.
    python3
    python3-pip
)

# DECLARATIVE pip list for the provisioned Debian image, installed inside the
# same provisioning boot, right after apt.
#
# Why pip at all, when everything else here is apt: the third-party SCADA
# masters `fleetsim`'s live tests need are pip-only. No Debian package exists
# for pycomm3/bacpypes3/python-snap7/asyncua/c104, and `python3-pymodbus` in
# trixie is 3.8.6 — years behind the 3.14.0 the module's SPEC.md transcripts
# were recorded against. A master's own defaults are part of the oracle, so
# the version is pinned exactly, not floated.
#
# `--break-system-packages` is correct here and nowhere else: this is a
# throwaway guest built from a recipe, PEP 668's "don't fight the distro
# package manager" hazard has no owner to hurt, and a venv would have to be
# re-activated by every consumer of the image. The HOST never runs any of
# this — that is the entire point of routing fleetsim's live lane here.
#
# Every entry MUST be `name==version`. An unpinned spec would make the recipe
# hash lie: the same recipe text would resolve to a different image on a
# different day, which is exactly what the hash exists to prevent.
VM_DEBIAN_PIP=(
    # The five third-party SCADA masters `fleetsim`'s live tests are written
    # against (modules/fleetsim/README.md "Installing the masters"). One image
    # carries all of them, so one boot can drive every protocol in sequence.
    pymodbus==3.14.0
    pycomm3==1.2.16
    bacpypes3==0.0.106
    # python-snap7 3.x is PURE PYTHON — 3.1.0 speaks TPKT/COTP/S7 over an
    # ordinary socket and needs no libsnap7.so, so no apt package goes with it.
    # Checked, not assumed: the wheel is `py3-none-any`, and the client
    # connects and reads with no `lib_location` argument.
    python-snap7==3.1.0
    # asyncua is LGPL-3.0-or-later, unlike the MIT four above. It is used as a
    # separate process in a disposable guest — nothing is linked against it and
    # nothing from it is redistributed — which is the reasoning recorded in
    # modules/fleetsim/NOTICE rather than only here.
    asyncua==2.0.1
)

# ── what this image CANNOT provide, so nobody re-derives it ──────────────
#
# `netdevsim` — the kernel's simulated devlink device, and the only way to
# give the `devlink` module's reply decoders a live counterpart (wave-2
# devlink F1) — is NOT reachable from this lane, and no package list change
# fixes it:
#
#   * Debian's cloud kernel (6.12.96+deb13-amd64) has no netdevsim.ko:
#     `modprobe netdevsim` -> "Module netdevsim not found", and
#     /sys/bus/netdevsim/ does not exist, so it is not built in either.
#   * Debian's GENERIC kernel is no better — verified empirically by
#     installing linux-image-amd64 (6.12.101+deb13-amd64) in a throwaway
#     -snapshot boot: `modinfo -k 6.12.101+deb13-amd64 netdevsim` fails too.
#     So `linux-image-amd64` is deliberately NOT in the list above; it costs
#     ~400 MB of guest disk and buys nothing.
#   * No Debian trixie/amd64 package ships netdevsim.ko at all (packages.
#     debian.org contents search, exact filename, all sections: no results).
#     Debian does not set CONFIG_NETDEVSIM.
#   * OpenWRT 25.12.4 x86/64 has no kmod-netdevsim either (all 1173 kmods in
#     the release's kmods/ index were listed; the only DSA-family devlink
#     drivers there — b53, mv88e6xxx, qca8k, vsc73xx — all need real silicon).
#
# Closing that row therefore needs a kernel with CONFIG_NETDEVSIM=m, which
# means a new platform in this manifest (an Ubuntu cloud image, whose
# linux-modules-*-generic does ship netdevsim.ko) or building
# drivers/net/netdevsim out of tree against the guest's own kernel headers.
# Either is a lane change, not a package change.
