#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# The host half of a stamp's lane key, shared by scripts/test.sh (module
# stamps) and scripts/check-apps.sh (example-app stamps). Sourced, not run.
# See scripts/README.md, "Which modules run: stamps".

# What `native` resolves to on this machine, as Zig sees it: the triple (OS
# and glibc versions included) plus the CPU model and its feature list, hashed.
# In the lane key because code picks paths by CPU feature (poly1305 AVX-512 /
# AVX2 lanes; montint, k256, p256 asm on adx+bmi2), and GitHub's amd64 pool
# mixes an EPYC without AVX-512 and a Xeon with it -- a stamp from one must not
# stand in for the other (audit 2026-09-18). Read once per run.
_ZL_NATIVE_ID=""
native_target_id() {
    if [[ -z "$_ZL_NATIVE_ID" ]]; then
        local sec
        sec="$(zig targets 2>/dev/null | awk '/^    \.native = \.\{/{on=1} on')"
        if [[ -z "$sec" ]]; then
            echo "stamps-key: 'zig targets' gave no native section -- cannot key stamps to this CPU" >&2
            exit 1
        fi
        _ZL_NATIVE_ID="native:$(printf '%s' "$sec" | sha256sum | cut -c1-12)"
    fi
    printf '%s' "$_ZL_NATIVE_ID"
}

# The triple alone (OS and glibc versions), for a lane with a pinned `-Dcpu`.
native_os_id() {
    local triple
    triple="$(zig targets 2>/dev/null | awk '/^    \.native = \.\{/{on=1} on && /^        \.triple = /{print; exit}')"
    if [[ -z "$triple" ]]; then
        echo "stamps-key: 'zig targets' gave no native triple -- cannot key stamps to this host" >&2
        exit 1
    fi
    printf 'os:%s' "$(printf '%s' "$triple" | sha256sum | cut -c1-12)"
}

# The key for a lane built with zig arguments "$@": a pinned `-Dcpu` (CI's
# push lane) makes the code paths independent of the runner's CPU, so only the
# triple -- kernel and glibc versions -- keys it; otherwise the whole native
# target does.
host_key() {
    case " $* " in
        *" -Dcpu="*) native_os_id ;;
        *) native_target_id ;;
    esac
}

# The CPU model behind that hash, for the log: the hash alone does not say
# which of the pool's machines a CI run landed on.
native_cpu_name() {
    zig targets 2>/dev/null | awk '/^    \.native = \.\{/{on=1} on && /^            \.name = /{gsub(/[",]/,"",$3); print $3; exit}'
}
