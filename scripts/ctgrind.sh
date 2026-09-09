#!/usr/bin/env bash
# ctgrind.sh — run every committed constant-time harness under
# valgrind/memcheck and print the full control table, instead of asserting a
# single number.
#
# Usage:
#     scripts/ctgrind.sh                    # every module with a harness
#     scripts/ctgrind.sh ct25519 ed448      # just these
#     scripts/ctgrind.sh --stacks ecvrf     # …and dump each row's memcheck log
#     scripts/ctgrind.sh --pattern 'root[.]zig' ecvrf
#                                           # …re-attribute the in-file column
#     scripts/ctgrind.sh --check            # compare against the expected table
#     scripts/ctgrind.sh -j 4 --check       # …at 4 parallel runs instead of nproc
#
# Runs go through a pool one memcheck process wide per job (valgrind serialises
# threads inside a process, so a single run can never use a second core). The
# table prints a `secs` column and a per-module total, so how long this takes is
# recorded rather than rediscovered. Counts do not depend on the job count; the
# times do, which is why the summary names it.
#
# Needs `valgrind` on PATH; builds go through `scripts/capped`. Not part of
# `zig build test` — memcheck's context count is valgrind's own verdict, not
# something a Zig test can observe. What the gate DOES run is `zig build
# check-ctgrind`, which only compiles the harnesses so they cannot rot into
# unbuildable recipes. See `scripts/README.md` § Constant-time harnesses.
#
# ── the trap this script exists to not fall into ───────────────────────────
# `std.valgrind.doClientRequest` opens with
# `if (!builtin.valgrind_support) return default;`, and that flag is off by
# default outside Debug. A ReleaseFast binary built WITHOUT `-fvalgrind` is
# therefore a SILENT NO-OP under valgrind: `MAKE_MEM_UNDEFINED` never fires,
# so every row reads zero regardless of what the code does. Every (mode,
# target) triple below is printed as three rows — the claim, an UNTAINTED
# negative control, and a no-`-fvalgrind` trap — so a zero is only ever read
# next to the two rows that give it meaning.
#
# ── the SECOND trap: a counting rule that drops what it cannot name ─────────
# Until 2026-08-13 this script computed exactly one number per row, "contexts
# whose stack matches PATTERN", and threw the rest away. That rule is
# FAIL-OPEN: a secret-dependent branch that memcheck attributes to a file the
# pattern does not list simply vanishes, and the row it belongs to reads the
# same as if the branch did not exist. Measured on k256: deleting the
# `blackBox` barrier from `Fe.cMov` adds exactly one `Conditional jump …
# depends on uninitialised value(s)` context, memcheck attributes it to the
# inlined-into-`main` frame `ctgrind_harness.zig:0`, `k256/field`'s pattern
# does not match that, and the row stayed at 0 in-file while its total went
# DOWN (6 → 5) — neither column nor the exit code distinguished the leak.
#
# So every context is now classified into exactly one of three buckets, and
# the third one is fatal:
#
#   in-file    — the stack matches PATTERN: a branch in the code the claim is
#                about. Pinned to an exact count in ctgrind-expected.tsv.
#   witness    — the stack matches WITNESS and not PATTERN: the harness's own
#                result formatting (`std.debug.print` is not constant-time by
#                design, and a tainted byte reaching it is the propagation
#                witness that makes an in-file zero mean "no branch found"
#                rather than "the taint never arrived").
#   unattr     — everything else. ALWAYS a `--check` failure, for every module,
#                with no per-module opt-out: an unattributed context is either
#                a leak the pattern cannot see or a pattern that has gone
#                stale, and both need a human. The offending stacks are
#                printed by `--check` so it is diagnosable without a re-run.
#
# `--check` additionally requires in-file + witness + unattr to account for
# valgrind's OWN context count, so a block the classifier fails to recognise
# as an error cannot silently reduce the total either. The one documented
# exception is a log where memcheck hit its 1000-context reporting limit and
# stopped printing (chachapoly's ReleaseSafe/Debug positive controls do);
# there the accounting is skipped and the row says so.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

EXPECTED_FILE="$SCRIPT_DIR/ctgrind-expected.tsv"

# ── per-module configuration ───────────────────────────────────────────────
#
# TARGETS  — the harness's first argv, one entry per code path it can drive.
# MODES    — optimize modes worth measuring. ReleaseFast only, except
#            `chachapoly`, whose whole claim is that the property holds at
#            ReleaseFast and measurably NOT below it (its lane-parallel MAC
#            uses checked `*`/`+`, which ReleaseSafe lowers to overflow
#            branches on secret-derived values). Everywhere else those same
#            safety checks merely flood the report — `ct25519` measured 89 956
#            errors from 1000 contexts at ReleaseSafe, valgrind's own
#            --error-limit cutoff — so the claim is stated for ReleaseFast.
#
#            ⛔ DEBUG IS NOT MEASURABLE HERE, and the reason is the compiler,
#            not this script. Zig 0.16 builds Debug with the self-hosted
#            x86_64 backend (Debug is the only mode where that backend is the
#            default), and valgrind's DWARF reader cannot parse the
#            `.debug_line` it emits: 35 159 `Badly formed extended line op`
#            warnings on a ten-line program with no inline asm and no
#            `std.valgrind` call at all, and 0 for the same program built
#            `-fllvm`. It is a property of the BACKEND, not of the mode —
#            forced with `-fno-llvm` the release modes break identically
#            (ReleaseSafe 48 395, ReleaseFast 37 369) and are clean only
#            because LLVM is their default.
#
#            What that does to a measurement, per mode, same harness and
#            target, frames carrying `(file:line)`:
#              ReleaseFast 36/36 (100 %) · ReleaseSafe 2054/2054 (100 %) ·
#              Debug 904/2130 (42.4 %)
#            and of the Debug frames that DO resolve, 51 of 60 carry the WRONG
#            line (checked against llvm-symbolizer; the file is right 60/60).
#            A context all of whose pattern-bearing frames lost their line info
#            is unattributable by ANY pattern, so it lands in `unattr` and the
#            row fails — for a reason that has nothing to do with the module.
#            That is why the `aead` Debug row sat in ctgrind-expected.tsv as
#            KNOWN RED from 2026-09-02 and then passed on 2026-09-08 with the
#            same expectation: the verdict moves with the build, not the code.
#
#            ⭐ Removed rather than worked around with `-fllvm`, because the
#            row bought nothing that survives its own removal: the SPEC calls
#            ReleaseSafe and Debug ONE positive control (210 and 281 contexts
#            inside `poly1305.zig`, same checked operators, same reason), and
#            nothing in this collection is consumed in Debug — CONVENTIONS §7.1
#            already narrowed the Debug CI lane to compile-only in 2026-08-15,
#            on the measurement that Debug proves nothing ReleaseSafe does not.
#            This row was the last place anything was RUN in Debug.
# PATTERN  — regex selecting the frames whose file the claim is ABOUT. The
#            `--pattern` flag overrides it, which is how any attribution in a
#            SPEC.md can be re-checked rather than believed.
# WITNESS  — the ONE allowlist, deliberately global and deliberately tiny:
#            std's formatting path, which every harness reaches on purpose
#            (see "the SECOND trap" above). It is not per-module, because a
#            per-module allowlist is how a fail-open rule grows back one
#            pattern at a time. Widen it only with a measured log showing the
#            frame belongs to result formatting and to nothing else.
# DERIVED from the tree via `zig build module-graph` (column 5), whose own
# source is `modules/<m>/src/ctgrind_harness.zig` existing. This was a literal
# list here AND in build.zig AND implicitly in TARGETS below, so a harness added
# without editing all three was never measured and nothing went red.
mapfile -t ALL_MODULES < <(zig build module-graph 2>/dev/null | awk -F'\t' '$5=="ct"{print $1}')
if [[ ${#ALL_MODULES[@]} -eq 0 ]]; then
    echo "ctgrind: module-graph reported no harnesses — refusing to pass vacuously" >&2
    exit 2
fi

declare -A TARGETS=(
    # ⚠ `act1` is deliberately NOT a target. The initiator's Act One never
    # touches the static key -- it draws its ephemeral inside -- so the taint
    # has no path into it and the row would read 0 for a reason that has
    # nothing to do with constant time. A row that cannot fail is not
    # evidence; see modules/bolt8/src/ctgrind_harness.zig.
    [bolt8]="dh keygen act3 transport"
    [chachapoly]="poly1305 aead"
    [hqc]="decaps keygen encaps sampler"
    [oscore]="derive protect unprotect"
    [ct25519]="ct25519 std"
    [decaf448]="scalarmul"
    [bn254]="field scalarmul"
    [ecvrf]="prove"
    [ed448]="full ladder"
    [k256]="field mul comb sign ecdsa"
    [montint]="small portable asmcore"
    # ── added 2026-09-09, A1 R2's first four ────────────────────────────────
    [p256]="comb sign"
    [rsa]="crt noncrt"
    [slhdsa]="seed prf"
    # ⚠ `falcon` is here against its own SPEC.md, which argued it should NOT
    # have a row because the red would only measure the sampler's deliberate
    # reject loop. The measurement says otherwise: 16 of 133 contexts are the
    # sampler and 112 are `fpr.zig`, which the same SPEC calls branchless.
    # See modules/falcon/SPEC.md, rewritten in the same commit.
    [falcon]="sign"
    # ── round 2, 2026-09-09 ────────────────────────────────────────────────
    [bls12_381]="field g1_scalarmul g2_scalarmul"
    [bip340]="sign"
    [blindrsa]="blind sign"
    # ⚠ COST: each threshold_ecdsa row runs the full t=n=2 GG20 protocol with
    # two real 2048-bit Paillier keys -- ~5 s native, 2-9 MINUTES under
    # memcheck. Six rows. It is by far the heaviest entry in this table; know
    # that before putting `--check` on a timer.
    [threshold_ecdsa]="share nonce"
    # ── round 3, 2026-09-09 ────────────────────────────────────────────────
    [bulletproofs]="rangeproof ipa"
    [paillier]="crt noncrt mul addm"
    [tlock]="fp12pow decrypt"
    [ibe]="extract decrypt fp12pow"
    # ── round 4, 2026-09-09: the secp256k1 signing family ──────────────────
    # ⭐ All three of bip340/musig2/adaptor spend ~79% of their contexts in a
    # MANDATORY SELF-VERIFY that re-runs a documented variable-time equation on
    # the signature about to be returned. bip340 63/80, musig2 81/103, adaptor
    # 74/90. That ratio is a property of the family, not of any one module, and
    # it is why these rows are pinned as bounds.
    [frost]="commit sign"
    [musig2]="sign"
    [taproot]="secret"
    [adaptor]="presign adapt extract"
    # ── rounds 5-7, 2026-09-09: the queue completes at 28 ──────────────────
    [spake2plus]="w0w1 computel proverstart verifierstart proverfinish verifierfinish"
    [bbs]="sign proofgen"
    [coconut]="authority_sign user_issue user_show"
    [hpke]="x25519_decap x25519_authdecap p256_decap p256_authdecap p384_decap p384_authdecap open"
    [signal]="sign ratchet"
    [sphinx]="construct process"
    [bolt3]="derive revocation shachain shachain_index"
    [ctap2pin]="ecdh one two token"
    [fss]="gen eval"
    [bfv]="keygen encrypt decrypt"
    [tfhe]="keygen encrypt decrypt bootstrap"
    [dkg]="coeffs combine"
)
declare -A MODES=(
    [bolt8]="ReleaseFast"
    [chachapoly]="ReleaseFast ReleaseSafe"
    [hqc]="ReleaseFast"
    [oscore]="ReleaseFast"
    [ct25519]="ReleaseFast"
    [decaf448]="ReleaseFast"
    [bn254]="ReleaseFast"
    [ecvrf]="ReleaseFast"
    [ed448]="ReleaseFast"
    [k256]="ReleaseFast"
    [montint]="ReleaseFast"
    [p256]="ReleaseFast"
    [rsa]="ReleaseFast"
    [slhdsa]="ReleaseFast"
    [falcon]="ReleaseFast"
    [bls12_381]="ReleaseFast"
    [bip340]="ReleaseFast"
    [blindrsa]="ReleaseFast"
    [threshold_ecdsa]="ReleaseFast"
    [bulletproofs]="ReleaseFast"
    [paillier]="ReleaseFast"
    [tlock]="ReleaseFast"
    [ibe]="ReleaseFast"
    [frost]="ReleaseFast"
    [musig2]="ReleaseFast"
    [taproot]="ReleaseFast"
    [adaptor]="ReleaseFast"
    [spake2plus]="ReleaseFast"
    [bbs]="ReleaseFast"
    [coconut]="ReleaseFast"
    [hpke]="ReleaseFast"
    [signal]="ReleaseFast"
    [sphinx]="ReleaseFast"
    [bolt3]="ReleaseFast"
    [ctap2pin]="ReleaseFast"
    [fss]="ReleaseFast"
    [bfv]="ReleaseFast"
    [tfhe]="ReleaseFast"
    [dkg]="ReleaseFast"
)
# Keyed "<module>/<target>".
declare -A PATTERN=(
    # bolt8 delegates its scalar multiplication to `k256` and its AEAD to std's
    # ChaCha20-Poly1305, so those files are named here for the same reason
    # chachapoly/aead names std's: their constant-time property IS this
    # module's property for every byte that flows through them, and attributing
    # the contexts to someone else would be the evasion this gate exists to
    # refuse. Every expected non-zero is itemised in modules/bolt8/SPEC.md.
    [bolt8/dh]='dh[.]zig|group[.]zig|field[.]zig|common[.]zig|fast_core[.]zig'
    [bolt8/keygen]='dh[.]zig|group[.]zig|field[.]zig|common[.]zig|fast_core[.]zig'
    [bolt8/act3]='act[.]zig|handshake[.]zig|dh[.]zig|group[.]zig|field[.]zig|common[.]zig|fast_core[.]zig|chacha20[.]zig|poly1305[.]zig'
    [bolt8/transport]='transport[.]zig|chacha20[.]zig|poly1305[.]zig'
    [chachapoly/poly1305]='poly1305[.]zig'
    # oscore's own code is one file (`root.zig`), and the claim SPEC.md makes is
    # that the key material is routed ONLY through std's constant-time HMAC/
    # AES-CCM. Both sides of that sentence have to be in the pattern, or the
    # half that matters most -- what std does with our key -- lands in `unattr`
    # and the row fails for the wrong reason.
    # ⛔ hqc's rows are a RECORDED DEFECT, not a clean claim -- see the harness.
    # The pattern is the module's own files only: the branches LLVM reintroduces
    # are in hqc's code, so there is nothing to delegate and nothing to blame on
    # std. `prng.zig` carries the fixed-weight sampler and the scatter.
    [hqc/decaps]='prng[.]zig|gf256[.]zig|gf2x[.]zig|reedsolomon[.]zig|reedmuller[.]zig|pke[.]zig|kem[.]zig|code[.]zig'
    [hqc/keygen]='prng[.]zig|gf256[.]zig|gf2x[.]zig|reedsolomon[.]zig|reedmuller[.]zig|pke[.]zig|kem[.]zig|code[.]zig'
    [hqc/encaps]='prng[.]zig|gf256[.]zig|gf2x[.]zig|reedsolomon[.]zig|reedmuller[.]zig|pke[.]zig|kem[.]zig|code[.]zig'
    [hqc/sampler]='prng[.]zig'
    [oscore/derive]='root[.]zig|hmac[.]zig|hkdf[.]zig|sha2[.]zig'
    [oscore/protect]='root[.]zig|aes_ccm[.]zig|aes[.]zig|aes_gcm[.]zig|modes[.]zig'
    [oscore/unprotect]='root[.]zig|aes_ccm[.]zig|aes[.]zig|aes_gcm[.]zig|modes[.]zig'
    # The AEAD's own claim: the tag comparison and the cipher/MAC glue in
    # `root.zig`. Added 2026-09-02 -- the module was listed with the poly1305
    # target alone, so `SPEC.md`'s constant-time sentence about the tag
    # compare had no measurement behind it at all.
    # ⚠ The pattern names std's files too, and that is deliberate: this module
    # DELEGATES short AEAD calls to `std.crypto.aead.chacha_poly`, so std's
    # constant-time property is this module's property for every message at or
    # below `aead_delegate_max`. Attributing those contexts to std and calling
    # them someone else's problem would be the same evasion as widening a
    # pattern to make a count go away. The expected non-zero is named in
    # ctgrind-expected.tsv.
    [chachapoly/aead]='root[.]zig|chacha20[.]zig|poly1305[.]zig'
    # bn254's own hand-written Montgomery field (commit 1892c814 replaced the
    # `std.crypto.ff` backend with it). `fp.zig` carries montMul/montSqr,
    # condSubP, subLimbs, ctSelect and the `blackBox` barrier; `g1.zig` the
    # ladder the tainted scalar drives. `scalar.zig` is listed for the
    # scalarmul target because `Fr` IS the secret there.
    [bn254/field]='fp[.]zig'
    [bn254/scalarmul]='g1[.]zig|fp[.]zig|scalar[.]zig'
    [ct25519/ct25519]='root[.]zig'
    [ct25519/std]='edwards25519[.]zig|ristretto255[.]zig|curve25519[.]zig'
    [decaf448/scalarmul]='element[.]zig|ed448[.]zig|field[.]zig|scalar[.]zig'
    [ecvrf/prove]='ecvrf[.]zig'
    [ed448/full]='ed448[.]zig|field[.]zig|x448[.]zig|scalar[.]zig'
    [ed448/ladder]='ed448[.]zig|field[.]zig|scalar[.]zig'
    # k256's own sources. `fast_core.zig` is in the field/mul/comb/sign
    # patterns because `field_asm_active` routes every `Fe.mul`/`Fe.sq` into
    # its inline asm on amd64 — memcheck sees that block as ordinary machine
    # code, so its "zero branches" contract is measured, not assumed. `sign`
    # deliberately does NOT list `scalar[.]zig`: k256's scalar.zig is a bare
    # re-export of std's, whose file has the same basename, and lumping them
    # together would attribute std's secret-key canonicality check to k256.
    [k256/field]='field[.]zig|fast_core[.]zig'
    [k256/mul]='group[.]zig|field[.]zig|fast_core[.]zig'
    [k256/comb]='group[.]zig|field[.]zig|fast_core[.]zig'
    [k256/sign]='sign[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
    [k256/ecdsa]='ecdsa_recover[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
    # montint: `montint.zig` is the portable CIOS + powMont, `asm_core.zig` the
    # gated amd64 core, `limbs.zig` the add/sub/select primitives underneath
    # both. All three are montint's own files; nothing in std shares a basename
    # with them.
    [montint/small]='montint[.]zig|limbs[.]zig|asm_core[.]zig'
    [montint/portable]='montint[.]zig|limbs[.]zig|asm_core[.]zig'
    [montint/asmcore]='montint[.]zig|limbs[.]zig|asm_core[.]zig'
    # ── added 2026-09-09 ───────────────────────────────────────────────────
    [p256/comb]='group[.]zig|field[.]zig|fast_core[.]zig'
    # `sign` names std's ecdsa/common/scalar for the same reason chachapoly's
    # pattern names std's AEAD: the shipped ES256 surface is std's generic
    # signer over THIS module's group, so attributing that arithmetic to
    # someone else would be the evasion this gate exists to refuse.
    [p256/sign]='ecdsa[.]zig|common[.]zig|scalar[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
    [rsa/crt]='root[.]zig|ff[.]zig'
    [rsa/noncrt]='root[.]zig|ff[.]zig'
    [slhdsa/seed]='engine[.]zig|address[.]zig'
    [slhdsa/prf]='engine[.]zig|address[.]zig'
    [falcon/sign]='fpr[.]zig|gaussian[.]zig|sign[.]zig|codec[.]zig'
    # ── round 2, 2026-09-09 ────────────────────────────────────────────────
    [bls12_381/field]='fp[.]zig'
    [bls12_381/g1_scalarmul]='g1[.]zig|fp[.]zig|scalar[.]zig'
    [bls12_381/g2_scalarmul]='g2[.]zig|fp2[.]zig|fp[.]zig|scalar[.]zig'
    [bip340/sign]='root[.]zig|hash[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig'
    # ⛔⛔ THIS PATTERN CANNOT TELL TWO FILES APART, and the harness's author
    # found it the hard way. `modules/blindrsa/src/root.zig` and
    # `modules/rsa/src/root.zig` are different files with the same BASENAME,
    # both appear in every stack here, and this classifier matches regex text
    # against the whole paragraph -- so `root[.]zig` buckets rsa's
    # `bigModInverse` as blindrsa's own code. The first pass mis-attributed
    # several lines that way and was corrected by reading valgrind's QUALIFIED
    # SYMBOL names (`root.bigModInverse` vs `blindSign`) instead. The in-file
    # column for these two rows is therefore "this module plus rsa", not "this
    # module" -- stated here rather than papered over, because the same trap
    # waits for every module whose dependency also has a root.zig.
    [blindrsa/blind]='root[.]zig|ff[.]zig'
    [blindrsa/sign]='root[.]zig|ff[.]zig'
    # `root[.]zig` here matches this module's own AND paillier's, deliberately
    # -- every hit was traced individually by the harness's author.
    [threshold_ecdsa/share]='signing[.]zig|root[.]zig|mta[.]zig|zkproofs[.]zig|montint[.]zig|asm_core[.]zig|limbs[.]zig|ff[.]zig|secp256k1[.]zig|secp256k1_64[.]zig|secp256k1_scalar_64[.]zig|common[.]zig|ecdsa[.]zig|scalar[.]zig|mem[.]zig|int[.]zig|math[.]zig|memcpy[.]zig|memmove[.]zig|compiler_rt[.]zig'
    # ── round 3, 2026-09-09 ────────────────────────────────────────────────
    [bulletproofs/rangeproof]='rangeproof[.]zig|ipa[.]zig|scalarvec[.]zig|generators[.]zig|transcript[.]zig|root[.]zig'
    [bulletproofs/ipa]='ipa[.]zig|scalarvec[.]zig|transcript[.]zig|root[.]zig'
    # ⚠ `root[.]zig` alone would have MISSED over half of paillier's crt total:
    # std's schoolbook big-int division under `divFloor` lives in int.zig, and
    # the Montgomery machinery in ff.zig. Naming only the module's own file is
    # the shape of under-measurement this gate exists to refuse.
    [paillier/crt]='root[.]zig|ff[.]zig|int[.]zig|math[.]zig|mem[.]zig|memcpy[.]zig|memmove[.]zig|compiler_rt[.]zig'
    [paillier/noncrt]='root[.]zig|ff[.]zig|int[.]zig|math[.]zig|mem[.]zig|memcpy[.]zig|memmove[.]zig|compiler_rt[.]zig'
    [paillier/mul]='root[.]zig|ff[.]zig'
    [paillier/addm]='root[.]zig|ff[.]zig'
    [tlock/fp12pow]='tlock[.]zig|ciphersuite[.]zig|fp12[.]zig|fp6[.]zig|fp2[.]zig|fp[.]zig|g2[.]zig|scalar[.]zig'
    [tlock/decrypt]='tlock[.]zig|ciphersuite[.]zig|pairing[.]zig|fp12[.]zig|fp6[.]zig|fp2[.]zig|fp[.]zig|g2[.]zig|g1[.]zig|scalar[.]zig|mem[.]zig'
    [ibe/extract]='ibe[.]zig|g1[.]zig|fp[.]zig|scalar[.]zig'
    [ibe/decrypt]='ibe[.]zig|ciphersuite[.]zig|pairing[.]zig|fp[.]zig|fp2[.]zig|fp6[.]zig|fp12[.]zig|g1[.]zig|g2[.]zig|scalar[.]zig|sha2[.]zig'
    [ibe/fp12pow]='ibe[.]zig|fp12[.]zig|fp6[.]zig|fp2[.]zig|fp[.]zig'
    # ── round 4, 2026-09-09 ────────────────────────────────────────────────
    [frost/commit]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
    [frost/sign]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
    # `scalar[.]zig`/`mem[.]zig` beyond bip340's pattern are EMPIRICALLY needed
    # (GLV splitScalar, findPubkeyIndex's mem.eql) -- without them those
    # contexts fall into `unattr`, which is always a --check failure.
    [musig2/sign]='root[.]zig|hash[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig|scalar[.]zig|mem[.]zig'
    [taproot/secret]='root[.]zig|hash[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig'
    [adaptor/presign]='root[.]zig|hash[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig'
    [adaptor/adapt]='root[.]zig|common[.]zig'
    # ── rounds 5-7, 2026-09-09 ─────────────────────────────────────────────
    [spake2plus/w0w1]='root[.]zig|common[.]zig'
    [spake2plus/computel]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
    [spake2plus/proverstart]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
    [spake2plus/verifierstart]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
    [spake2plus/proverfinish]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|sha2[.]zig|hmac[.]zig|hkdf[.]zig|timing_safe[.]zig'
    [spake2plus/verifierfinish]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|sha2[.]zig|hmac[.]zig|hkdf[.]zig|timing_safe[.]zig'
    [bbs/sign]='bbs[.]zig|ciphersuite[.]zig|keys[.]zig|fp[.]zig|g1[.]zig|scalar[.]zig|hash_to_curve[.]zig'
    [bbs/proofgen]='bbs[.]zig|ciphersuite[.]zig|keys[.]zig|fp[.]zig|g1[.]zig|scalar[.]zig|hash_to_curve[.]zig'
    [coconut/authority_sign]='credential[.]zig|fp[.]zig|g1[.]zig|scalar[.]zig'
    [coconut/user_issue]='params[.]zig|fp[.]zig|g1[.]zig|scalar[.]zig|hash_to_curve[.]zig'
    [coconut/user_show]='credential[.]zig|g1[.]zig|g2[.]zig|fp[.]zig|fp2[.]zig|scalar[.]zig'
    [hpke/x25519_decap]='dhkem[.]zig|suite[.]zig|x25519[.]zig|curve25519[.]zig|field[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig'
    [hpke/x25519_authdecap]='dhkem[.]zig|suite[.]zig|x25519[.]zig|curve25519[.]zig|field[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig'
    [hpke/p256_decap]='dhkem[.]zig|suite[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig'
    [hpke/p256_authdecap]='dhkem[.]zig|suite[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig'
    [hpke/p384_decap]='dhkem[.]zig|suite[.]zig|p384[.]zig|field[.]zig|common[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig'
    [hpke/p384_authdecap]='dhkem[.]zig|suite[.]zig|p384[.]zig|field[.]zig|common[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig'
    [hpke/open]='schedule[.]zig|root[.]zig|chacha20[.]zig|poly1305[.]zig'
    [signal/sign]='xeddsa[.]zig|root[.]zig|scalar[.]zig'
    [signal/ratchet]='ratchet[.]zig|x3dh[.]zig|x25519[.]zig|curve25519[.]zig|scalar[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig|root[.]zig|chacha20[.]zig|poly1305[.]zig'
    [sphinx/construct]='core[.]zig|keyderive[.]zig|hopframe[.]zig|bigsize[.]zig|group[.]zig|field[.]zig|scalar[.]zig|common[.]zig'
    [sphinx/process]='core[.]zig|keyderive[.]zig|hopframe[.]zig|bigsize[.]zig|group[.]zig|field[.]zig|common[.]zig'
    [bolt3/derive]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig'
    [bolt3/revocation]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig'
    # ⛔⛔ `:[1-9]` IS LOad-BEARING, not tidiness. A fully-inlined callee gets
    # its merged frame reported at `root.zig:0` -- never a real source line --
    # and this classifier matches PATTERN anywhere in the paragraph, BEFORE
    # WITNESS. Bare `root[.]zig` therefore filed two genuine propagation
    # witnesses as in-file and reported 2 where the honest count is 0. It lies
    # in the other direction too: it can launder a foreign leak into this
    # module's column. See CTGRIND-OPEN-QUESTIONS.md.
    [bolt3/shachain]='root[.]zig:[1-9]'
    [bolt3/shachain_index]='root[.]zig:[1-9]'
    [ctap2pin/ecdh]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig|scalar[.]zig'
    [ctap2pin/one]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig|scalar[.]zig|sha2[.]zig'
    [ctap2pin/two]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig|scalar[.]zig|hkdf[.]zig|sha2[.]zig'
    [ctap2pin/token]='root[.]zig|hmac[.]zig|sha2[.]zig'
    [fss/gen]='dpf[.]zig|group[.]zig'
    [fss/eval]='dpf[.]zig|group[.]zig'
    [bfv/keygen]='bfv[.]zig|modarith[.]zig|ntt[.]zig|ring[.]zig|Random[.]zig'
    [bfv/encrypt]='bfv[.]zig|modarith[.]zig|ntt[.]zig|ring[.]zig'
    [bfv/decrypt]='bfv[.]zig|modarith[.]zig|ntt[.]zig|ring[.]zig|udivmod[.]zig'
    [tfhe/keygen]='tfhe[.]zig'
    [tfhe/encrypt]='tfhe[.]zig'
    [tfhe/decrypt]='tfhe[.]zig|torus[.]zig|poly[.]zig|ntt[.]zig'
    [tfhe/bootstrap]='tfhe[.]zig|gadget[.]zig|poly[.]zig|torus[.]zig|ntt[.]zig'
    [dkg/coeffs]='protocol[.]zig|commit[.]zig|core[.]zig|root[.]zig|secp256k1[.]zig|common[.]zig|scalar[.]zig'
    [dkg/combine]='core[.]zig|root[.]zig|secp256k1[.]zig'
    [adaptor/extract]='root[.]zig|common[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
    [threshold_ecdsa/nonce]='signing[.]zig|root[.]zig|mta[.]zig|zkproofs[.]zig|montint[.]zig|asm_core[.]zig|limbs[.]zig|ff[.]zig|secp256k1[.]zig|secp256k1_64[.]zig|secp256k1_scalar_64[.]zig|common[.]zig|ecdsa[.]zig|scalar[.]zig|mem[.]zig|int[.]zig|math[.]zig|memcpy[.]zig|memmove[.]zig|compiler_rt[.]zig'
)
WITNESS='Writer[.]zig|Format[.]zig|fmt[.]zig'
declare -A LABEL=(
    [frost/commit]='frost round1Commit+k256'
    [frost/sign]='frost round2Sign+k256'
    [musig2/sign]='musig2 sign (d,k1,k2)+bip340+k256'
    [taproot/secret]='taproot tweakSecretKey+bip340+k256'
    [adaptor/presign]='adaptor preSign (sk+nonce)+bip340+k256'
    [adaptor/adapt]='adaptor adapt (t)'
    [adaptor/extract]='adaptor extract (t out)+k256'
    [bulletproofs/rangeproof]='bulletproofs prove (v,gamma)+ct25519'
    [bulletproofs/ipa]='bulletproofs ipa witness+ct25519'
    [paillier/crt]='paillier decrypt CRT+std bigint'
    [paillier/noncrt]='paillier decrypt non-CRT+std bigint'
    [paillier/mul]='paillier mulPlaintext (k)'
    [paillier/addm]='paillier addPlaintext (m)'
    [tlock/fp12pow]='tlock encrypt r->fp12Pow (F3)'
    [tlock/decrypt]='tlock decrypt+bls12_381 pairing'
    [ibe/extract]='ibe extract (msk -> G1)'
    [ibe/decrypt]='ibe decrypt (d_id -> pairing+FO)'
    [ibe/fp12pow]='ibe fp12Pow (Gt windowed, F4)'
    [bls12_381/field]='bls12_381 fp.zig'
    [bls12_381/g1_scalarmul]='bls12_381 g1+fp+scalar'
    [bls12_381/g2_scalarmul]='bls12_381 g2+fp2+fp+scalar'
    [bip340/sign]='bip340 sign+k256+std'
    [blindrsa/blind]='blindrsa blind (r, masked inv)+rsa'
    [blindrsa/sign]='blindrsa blindSign (sk)+rsa+std ff'
    [threshold_ecdsa/share]='thr_ecdsa share x_i+paillier'
    [threshold_ecdsa/nonce]='thr_ecdsa nonce k_i/gamma+paillier'
    [p256/comb]='p256 combMulBase'
    [p256/sign]='p256 sign+std ecdsa'
    [rsa/crt]='rsa CRT p/q+std ff'
    [rsa/noncrt]='rsa non-CRT d+std ff'
    [slhdsa/seed]='slhdsa SK.seed'
    [slhdsa/prf]='slhdsa SK.prf'
    [falcon/sign]='falcon sign (fpr+sampler)'
    [bolt8/dh]='bolt8 dh+k256'
    [bolt8/keygen]='bolt8 dh+k256'
    [bolt8/act3]='bolt8 hs+k256+std'
    [bolt8/transport]='bolt8 transport+std'
    [hqc/decaps]='hqc src (DEFECT)'
    [hqc/keygen]='hqc src (DEFECT)'
    [hqc/encaps]='hqc src (DEFECT)'
    [hqc/sampler]='hqc prng (DEFECT)'
    [oscore/derive]='oscore+std hkdf'
    [oscore/protect]='oscore+std ccm'
    [oscore/unprotect]='oscore+std ccm'
    [bn254/field]='bn254 fp.zig'
    [bn254/scalarmul]='bn254 g1+fp+scalar'
    [chachapoly/poly1305]='poly1305.zig'
    [chachapoly/aead]='aead: root+std'
    [ct25519/ct25519]='ct25519/root.zig'
    [ct25519/std]='std 25519'
    [decaf448/scalarmul]='decaf448+ed448'
    [ecvrf/prove]='ecvrf.zig'
    [ed448/full]='ed448 src'
    [ed448/ladder]='ed448 src'
    [k256/field]='k256 field+asm'
    [k256/mul]='k256 group+field'
    [k256/comb]='k256 group+field'
    [k256/sign]='k256 src'
    [k256/ecdsa]='k256 ecdsa src'
    [montint/small]='montint src'
    [montint/portable]='montint src'
    [montint/asmcore]='montint src'
    # ── rounds 5-7, 2026-09-09 ─────────────────────────────────────────────
    [spake2plus/w0w1]='spake2plus computeW0W1+std wide-reduce'
    [spake2plus/computel]='spake2plus computeL (w1*P)+p256 comb'
    [spake2plus/proverstart]='spake2plus proverStart+p256'
    [spake2plus/verifierstart]='spake2plus verifierStart+p256'
    [spake2plus/proverfinish]='spake2plus proverFinish+confirm MAC'
    [spake2plus/verifierfinish]='spake2plus verifierFinish+confirm MAC'
    [bbs/sign]='bbs sign SK+bls12_381'
    [bbs/proofgen]='bbs proofGen undisclosed msgs+bls12_381'
    [coconut/authority_sign]='coconut authority key share+bls12_381'
    [coconut/user_issue]='coconut user attributes (local commit)'
    [coconut/user_show]='coconut proveCredential (attrs+blinding)'
    [hpke/x25519_decap]='hpke X25519 decap (skR)+std'
    [hpke/x25519_authdecap]='hpke X25519 authDecap+std'
    [hpke/p256_decap]='hpke P-256 decap (skR)+p256'
    [hpke/p256_authdecap]='hpke P-256 authDecap+p256'
    [hpke/p384_decap]='hpke P-384 decap (skR)+std p384'
    [hpke/p384_authdecap]='hpke P-384 authDecap+std p384'
    [hpke/open]='hpke Context.open+chachapoly'
    [signal/sign]='signal xeddsa sign+ct25519'
    [signal/ratchet]='signal DH-ratchet root/chain KDF'
    [sphinx/construct]='sphinx construct (session_key)+k256'
    [sphinx/process]='sphinx process (relay privkey)+k256'
    [bolt3/derive]='bolt3 derivePrivateKey+k256'
    [bolt3/revocation]='bolt3 deriveRevocationPrivateKey+k256'
    [bolt3/shachain]='bolt3 perCommitmentSecret (seed; index public)'
    [bolt3/shachain_index]='bolt3 perCommitmentSecret (index tainted; CONTROL)'
    [ctap2pin/ecdh]='ctap2pin ecdhZ (platform scalar)+p256'
    [ctap2pin/one]='ctap2pin One.encapsulate+p256'
    [ctap2pin/two]='ctap2pin Two.encapsulate+p256+hkdf'
    [ctap2pin/token]='ctap2pin pinUvAuthToken HMAC'
    [fss/gen]='fss genWithSeeds (alpha,seeds)'
    [fss/eval]='fss eval (key) -- DEFECT dpf.zig:326'
    [bfv/keygen]='bfv keyGen samplers+ring'
    [bfv/encrypt]='bfv encrypt (plaintext) -- DEFECT bfv.zig:686'
    [bfv/decrypt]='bfv decrypt (sk)+CRT reconstruct'
    [tfhe/keygen]='tfhe lwe/glwe keyGen samplers'
    [tfhe/encrypt]='tfhe encrypt (plaintext)'
    [tfhe/decrypt]='tfhe decrypt (key) -- DEFECT ntt.zig:93/127'
    [tfhe/bootstrap]='tfhe blindRotate/cmux/keySwitch'
    [dkg/coeffs]='dkg round-1 secret coefficients'
    [dkg/combine]='dkg final combined share'
)

# ── arguments ──────────────────────────────────────────────────────────────
SHOW_STACKS=0
DO_CHECK=0
PATTERN_OVERRIDE=""
DO_UPDATE_DIGESTS=0
DO_UPDATE_OUTPUTS=0
# One memcheck process pins one core and cannot use a second, so the default is
# every core. Lower it with -j when you want the machine back, or when comparing
# the `secs` column against an earlier run made at a different width.
JOBS="$(nproc 2>/dev/null || echo 1)"
MODULES=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stacks) SHOW_STACKS=1; shift ;;
        -j|--jobs) JOBS="${2:?-j needs a job count}"; shift 2 ;;
        --check) DO_CHECK=1; shift ;;
        # Rewrites ctgrind-expected.tsv's source-digest column WITHOUT running
        # anything. Deliberately separate from --check: re-pinning is the act
        # of saying "I re-read these contexts and they are still the documented
        # ones", so it must be typed on purpose and land in a diff, never be a
        # side effect of a green run.
        --update-digests) DO_UPDATE_DIGESTS=1; shift ;;
        # The output pin's counterpart. Unlike --update-digests this RUNS the
        # measurement, because the value can only come from a run. Same reason
        # for being a separate verb: re-pinning says "I looked at what the
        # harness printed and it is right", and that must be typed on purpose.
        --update-outputs) DO_CHECK=1; DO_UPDATE_OUTPUTS=1; shift ;;
        --pattern) PATTERN_OVERRIDE="${2:?--pattern needs a regex}"; shift 2 ;;
        -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
        -*) echo "ctgrind: unknown flag $1" >&2; exit 2 ;;
        *) MODULES+=("$1"); shift ;;
    esac
done
if [[ "$DO_UPDATE_DIGESTS" == "1" ]]; then
    src_digest() {
        local module="$1" pattern="$2"
        local dir="$REPO_ROOT/modules/$module/src"
        [[ -d "$dir" ]] || { echo "NO-SRC"; return; }
        local names; names="$(printf '%s' "$pattern" | sed 's/\[\.\]/./g' | tr '|' '\n')"
        local files=() n
        while IFS= read -r n; do
            [[ -n "$n" && -f "$dir/$n" ]] && files+=("$dir/$n")
        done <<<"$names"
        if [[ ${#files[@]} -eq 0 ]]; then echo "NO-OWN-SRC"; return; fi
        printf '%s\n' "${files[@]}" | LC_ALL=C sort | xargs cat | sha256sum | cut -c1-16
    }
    tmp="$(mktemp)"
    while IFS= read -r ln; do
        if [[ "$ln" =~ ^# || -z "$ln" ]]; then printf '%s\n' "$ln" >>"$tmp"; continue; fi
        # ⛔ THE SEVENTH COLUMN IS CARRIED THROUGH, and it was not until
        # 2026-09-08. This rewriter was written when the row had six fields;
        # the output pin was added the same day and this loop was not updated,
        # so it printed six and silently TRUNCATED every row's `out_sha`.
        # Measured when it happened: one `--update-digests` blanked the output
        # pin of 20 of the 24 rows, and the only reason it was caught is that
        # `--check` refuses an empty pin instead of treating it as "not pinned
        # yet". A re-pin of one column must not destroy the other.
        IFS=$'\t' read -r m mo t tm inf _ eout <<<"$ln"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$m" "$mo" "$t" "$tm" "$inf" \
            "$(src_digest "$m" "${PATTERN[$m/$t]:-}")" "$eout" >>"$tmp"
    done <"$EXPECTED_FILE"
    mv "$tmp" "$EXPECTED_FILE"
    echo "ctgrind: source digests rewritten in $EXPECTED_FILE"
    exit 0
fi

# Whether a SUBSET was named on the command line. `--check` needs the
# distinction: an expected row with no measurement is legitimate when the caller
# asked for other modules, and is a FAILURE otherwise -- see the accounting loop.
SUBSET_REQUESTED=0
if [[ ${#MODULES[@]} -eq 0 ]]; then MODULES=("${ALL_MODULES[@]}"); else SUBSET_REQUESTED=1; fi
# ALL_MODULES is derived from the tree now, so a harness added without a recipe
# here shows up on its own -- and would otherwise be "measured" with no targets,
# i.e. silently not measured at all. Both the named and the default (= every
# harness) case go through this, and the two messages are different questions:
# a name that has no harness is a typo, a harness that has no recipe is a gap.
for m in "${MODULES[@]}"; do
    if [[ ! -f "$REPO_ROOT/modules/$m/src/ctgrind_harness.zig" ]]; then
        echo "ctgrind: no harness for module '$m' (expected modules/$m/src/ctgrind_harness.zig)" >&2
        exit 2
    fi
    [[ -n "${TARGETS[$m]:-}" ]] || { echo "ctgrind: modules/$m/src/ctgrind_harness.zig exists but ctgrind.sh has no TARGETS entry for it — add one (plus MODES/PATTERN/WITNESS) or the harness is never driven" >&2; exit 2; }
    [[ -n "${MODES[$m]:-}" ]] || { echo "ctgrind: modules/$m/src/ctgrind_harness.zig exists but ctgrind.sh has no MODES entry for it" >&2; exit 2; }
done

# ⛔⛔ The recipe is FOUR arrays and this loop used to check two of them. A key
# present in TARGETS but missing from LABEL does not fail here: it fails at
# `lbl="${LABEL[$key]}"` inside the MEASUREMENT loop, under `set -u`, AFTER the
# builds, and only for the modules the caller happened to name. Measured
# 2026-09-09: commit c2eee166 pasted 41 LABEL entries into the PATTERN literal
# instead of the LABEL one, so 12 of the 28 modules the campaign called closed
# could not be measured AT ALL, and the failure looked like a crash rather than
# a recipe gap. Check every arm of the recipe, before anything is built.
for m in "${MODULES[@]}"; do
    for t in ${TARGETS[$m]}; do
        [[ -n "${PATTERN[$m/$t]:-}" ]] || { echo "ctgrind: TARGETS lists '$t' for module '$m' but there is no PATTERN[$m/$t] — every target needs the file regex its contexts are attributed by" >&2; exit 2; }
        [[ -n "${LABEL[$m/$t]:-}" ]]   || { echo "ctgrind: TARGETS lists '$t' for module '$m' but there is no LABEL[$m/$t] — every target needs the one-line description the table prints" >&2; exit 2; }
    done
done

# The other half of that same accident, and the half that is genuinely invisible:
# PATTERN came out CORRECT only because the real regex for each stray key was
# assigned later in the same literal and overwrote the label. Had the paste
# landed after instead of before, PATTERN would hold a prose description, every
# `in-file` count would be 0, and the run would report a clean module rather than
# fail. A silently wrong measurement is worse than a crash, so the duplicate is
# an error in its own right — the losing assignment is always a mistake.
dupes="$(awk '
    match($0, /^declare -A (TARGETS|MODES|PATTERN|LABEL)=\(/) { arr = $3; sub(/=\(.*/, "", arr); next }
    arr != "" && /^\)/ { arr = ""; next }
    arr != "" && match($0, /^[[:space:]]*\[[^]]+\]=/) {
        k = substr($0, RSTART, RLENGTH)
        sub(/^[[:space:]]*\[/, "", k); sub(/\]=$/, "", k)
        if ((arr, k) in seen)
            printf "  %s[%s]: line %d is overwritten by line %d\n", arr, k, seen[arr, k], NR
        else seen[arr, k] = NR
    }
' "${BASH_SOURCE[0]}")"
if [[ -n "$dupes" ]]; then
    echo "ctgrind: the same key is assigned twice in one recipe array — the LATER assignment wins and the earlier is lost:" >&2
    echo "$dupes" >&2
    echo "     This is what a LABEL pasted into the PATTERN block looks like from the inside. Delete the wrong one," >&2
    echo "     and check whether the array it was MEANT for is now missing that key." >&2
    exit 2
fi

[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "ctgrind: -j needs a positive integer, got '$JOBS'" >&2; exit 2; }

if ! command -v valgrind >/dev/null 2>&1; then
    echo "ctgrind: valgrind not found on PATH — install it or run this on a host that has it (no auto-install)." >&2
    exit 2
fi

# Off tmpfs: this is the install prefix for every (mode, -fvalgrind) build combo,
# which is large, and /tmp is RAM here. `.zig-cache` is the repo's scratch.
mkdir -p .zig-cache
WORKDIR="$(mktemp -d "$PWD/.zig-cache/ctgrind.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

# ── build ──────────────────────────────────────────────────────────────────
# One build per (mode, -fvalgrind) pair, covering every requested module.
MODFLAGS=()
for m in "${MODULES[@]}"; do MODFLAGS+=("-Dctgrind-module=$m"); done

needed_modes() {
    local out=()
    for m in "${MODULES[@]}"; do
        for mode in ${MODES[$m]}; do
            local seen=0
            for o in ${out[@]+"${out[@]}"}; do [[ "$o" == "$mode" ]] && seen=1; done
            [[ $seen -eq 0 ]] && out+=("$mode")
        done
    done
    printf '%s\n' ${out[@]+"${out[@]}"}
}

mapfile -t BUILD_MODES < <(needed_modes)
for mode in "${BUILD_MODES[@]}"; do
    for vg in true false; do
        echo "Building ctgrind harnesses ($mode, -fvalgrind=$vg)..." >&2
        scripts/capped zig build ctgrind \
            "-Doptimize=$mode" "-Dctgrind-valgrind=$vg" \
            "${MODFLAGS[@]}" -p "$WORKDIR/$mode-$vg" >&2
    done
done

# ── measurement ────────────────────────────────────────────────────────────
# Count valgrind ERROR blocks whose stack contains $2, treating the blank
# "==pid==" separator lines memcheck prints between errors as paragraph
# breaks. Counting BLOCKS (not lines) matters: a single context's stack often
# names the target file on more than one frame (e.g. std's `pcMul16` AND its
# `mul` wrapper both live in `edwards25519.zig`), so a plain `grep -c` over
# lines double-counts relative to what "N contexts" means.
count_contexts_in() {
    local log="$1" pattern="$2"
    classify_contexts "$log" "$pattern" count-in
}

# The fail-closed half of the same paragraph walk. An ERROR block is any
# paragraph carrying at least one `at 0x…:` stack frame — a property of every
# memcheck error report regardless of its kind, rather than a list of the
# kinds we happen to know about, so a new memcheck error kind is classified
# rather than ignored. Blocks are then bucketed in order: PATTERN wins,
# WITNESS second, and whatever matches neither is UNATTRIBUTED.
#
# `mode` selects the output: count-in / count-witness / count-unattr /
# show-unattr (the offending blocks themselves, for the failure message).
classify_contexts() {
    local log="$1" pattern="$2" mode="$3"
    # Drop the harness's OWN stdout first: it is interleaved with memcheck's
    # report, it lands inside an error paragraph, and a harness that happens
    # to print a matching word would otherwise re-classify a real context.
    # Only `==pid==` lines survive; the `==pid==`-only separators then become
    # the paragraph breaks.
    sed -E -e '/^==[0-9]+==/!d' -e 's/^==[0-9]+==[[:space:]]*$//' "$log" \
        | awk -v RS='' -v pat="$pattern" -v wit="$WITNESS" -v mode="$mode" '
            BEGIN { in_c = 0; wit_c = 0; un_c = 0 }
            # not an error report (banner, HEAP SUMMARY, ERROR SUMMARY, …)
            $0 !~ /==[0-9]+==[[:space:]]+at 0x[0-9A-Fa-f]+:/ { next }
            {
                if ($0 ~ pat)      { in_c++ }
                else if ($0 ~ wit) { wit_c++ }
                else {
                    un_c++
                    if (mode == "show-unattr") { printf "%s\n\n", $0 }
                }
            }
            END {
                if (mode == "count-in")      print in_c + 0
                if (mode == "count-witness") print wit_c + 0
                if (mode == "count-unattr")  print un_c + 0
            }'
}

# memcheck stops printing new contexts once it hits its limit and says so.
# Past that point the printed blocks no longer account for the reported
# context total, so the accounting assertion is skipped for such a log —
# explicitly, and only here.
#
# The marker is the "I'm not reporting any more" sentence, NOT "More than N
# errors detected": memcheck prints the latter at 100 errors and keeps
# reporting (in less detail), and matching it would switch the accounting
# assertion off for every noisy row — measured on chachapoly's ReleaseSafe and
# Debug positive controls, which say it at 214 and 285 contexts and whose
# buckets in fact account for every one.
log_hit_error_limit() {
    grep -qF "I'm not reporting any more" "$1"
}

# Runs one (module, mode, valgrind-switch, target, taint) combination under
# memcheck and prints
# "total|in_target|witness|unattributed|accounted|exit_code|logpath",
# where `accounted` is 1 when in+witness+unattr equals valgrind's own context
# total (0 = the classifier lost a block, or memcheck hit its report limit).
run_one() {
    local module="$1" mode="$2" vg="$3" target="$4" taint="$5" file_pattern="$6"
    local bin="$WORKDIR/$mode-$vg/ctgrind/ctgrind-$module"
    local log="$WORKDIR/log_${module}_${mode}_${vg}_${target}_${taint}.txt"
    # Wall time per run, so "how long does this take" stops being a guess and
    # becomes a column. `EPOCHREALTIME` is seconds.microseconds, and its decimal
    # separator is the LOCALE'S -- a comma under cs_CZ -- so the class match
    # `[.,]` is required, not defensive: `${EPOCHREALTIME/./}` silently yields a
    # string with a comma in it here, and the subtraction below then errors.
    local t0="${EPOCHREALTIME/[.,]/}"
    set +e
    # ⚠ `--max-stackframe` is NOT decoration. `std.Io.Threaded`'s stack
    # footprint exceeds memcheck's default 2 MB heuristic, and past it memcheck
    # prints "client switching stacks?" and then floods with bogus
    # "Invalid read/write" errors -- ~7000 of them on every `tfhe` row, drowning
    # the real signal. Found 2026-09-09 by tfhe's harness author, who had to
    # diagnose it before any of that module's numbers meant anything. Raising a
    # heuristic threshold cannot hide a real error, so it is set globally.
    valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
        --max-stackframe=16777216 \
        "$bin" "$target" "$taint" >"$log" 2>&1
    local rc=$?
    set -e
    local ms=$(( ( ${EPOCHREALTIME/[.,]/} - t0 ) / 1000 ))
    local total
    total=$(grep -oE 'errors from [0-9]+ contexts' "$log" | grep -oE '[0-9]+' | head -1 || true)
    total="${total:-0}"
    local in_target witness unattr accounted
    in_target=$(classify_contexts "$log" "$file_pattern" count-in)
    witness=$(classify_contexts "$log" "$file_pattern" count-witness)
    unattr=$(classify_contexts "$log" "$file_pattern" count-unattr)
    if log_hit_error_limit "$log"; then
        accounted=2 # not assertable: memcheck stopped printing
    elif [[ $((in_target + witness + unattr)) -eq "$total" ]]; then
        accounted=1
    else
        accounted=0
    fi
    echo "${total}|${in_target}|${witness}|${unattr}|${accounted}|${rc}|${log}|${ms}"
}

# Milliseconds as `12.3s`, wide enough to read down a column.
fmt_secs() { printf '%d.%01ds' "$(( $1 / 1000 ))" "$(( ($1 % 1000) / 100 ))"; }

ACTUAL="$WORKDIR/actual.tsv"
: >"$ACTUAL"

# ── the job list ───────────────────────────────────────────────────────────
# Enumerated FIRST, then run by a pool, then replayed in this order. The order
# is what makes the table and `actual.tsv` diffable between runs; a pool that
# printed as results arrived would reorder rows by how fast each one happened to
# be, and every run would differ from the last for no reason anybody could see.
#
# ⭐ Running these concurrently cannot change any NUMBER. memcheck's contexts are
# a property of the instruction stream, not of wall time, and each run is its own
# process with its own log path. What contention does change is the `secs` column
# -- so it is comparable across rows of ONE run, and across runs only at the same
# job count, which is why the count is printed in the summary below.
declare -a J_M=() J_MODE=() J_TARGET=() J_VG=() J_TAINT=() J_NOTE=() J_PAT=() J_LBL=()
for m in "${MODULES[@]}"; do
    for mode in ${MODES[$m]}; do
        for target in ${TARGETS[$m]}; do
            key="$m/$target"
            pat="${PATTERN_OVERRIDE:-${PATTERN[$key]}}"
            lbl="${LABEL[$key]}"
            [[ -n "$PATTERN_OVERRIDE" ]] && lbl="(--pattern)"
            for combo in "true yes " "true no control" "false yes trap"; do
                read -r vg taint note <<<"$combo"
                J_M+=("$m");     J_MODE+=("$mode"); J_TARGET+=("$target")
                J_VG+=("$vg");   J_TAINT+=("$taint"); J_NOTE+=("$note")
                J_PAT+=("$pat"); J_LBL+=("$lbl")
            done
        done
    done
done
NJOBS=${#J_M[@]}

# ── the pool ───────────────────────────────────────────────────────────────
# valgrind serialises the threads INSIDE one process, so there is no such thing
# as making a single run use more than one core: the only parallelism available
# is more processes. Peak RSS is ~45 MB per memcheck run here (measured on
# tlock), so the bound is cores, not memory.
echo "Measuring $NJOBS runs across $JOBS parallel valgrind processes..." >&2
wall0="${EPOCHREALTIME/[.,]/}"
running=0
for ((i = 0; i < NJOBS; i++)); do
    while (( running >= JOBS )); do
        wait -n || true
        running=$(( running - 1 ))
    done
    ( run_one "${J_M[i]}" "${J_MODE[i]}" "${J_VG[i]}" "${J_TARGET[i]}" \
              "${J_TAINT[i]}" "${J_PAT[i]}" >"$WORKDIR/res_$i" ) &
    running=$(( running + 1 ))
done
wait
wall_ms=$(( ( ${EPOCHREALTIME/[.,]/} - wall0 ) / 1000 ))

# ── replay, in job order ───────────────────────────────────────────────────
printf '%-11s %-11s %-11s %-8s %-10s %-16s %8s %8s %8s %7s %5s %8s %s\n' \
    "module" "build" "-fvalgrind" "tainted" "target" "in" "total" "in-file" "witness" "unattr" "exit" "secs" "note"
printf '%s\n' "------------------------------------------------------------------------------------------------------------------------"

declare -A MODULE_MS=()
cpu_ms=0
for ((i = 0; i < NJOBS; i++)); do
    # A pool member that died without writing its line is not a row we can
    # invent: say which job, and fail the run.
    if [[ ! -s "$WORKDIR/res_$i" ]]; then
        echo "ctgrind: job $i (${J_M[i]}/${J_MODE[i]}/${J_TARGET[i]} taint=${J_TAINT[i]} -fvalgrind=${J_VG[i]}) produced no result — the worker died before reporting" >&2
        exit 2
    fi
    IFS='|' read -r total in_file witness unattr accounted rc log ms <"$WORKDIR/res_$i"
    rownote="${J_NOTE[i]}"
    [[ "$accounted" == "0" ]] && rownote="$rownote UNACCOUNTED"
    [[ "$accounted" == "2" ]] && rownote="$rownote error-limit"
    printf '%-11s %-11s %-11s %-8s %-10s %-16s %8s %8s %8s %7s %5s %8s %s\n' \
        "${J_M[i]}" "${J_MODE[i]}" "${J_VG[i]}" "${J_TAINT[i]}" "${J_TARGET[i]}" "${J_LBL[i]}" \
        "$total" "$in_file" "$witness" "$unattr" "$rc" "$(fmt_secs "$ms")" "$rownote"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${J_M[i]}" "${J_MODE[i]}" "${J_VG[i]}" "${J_TAINT[i]}" "${J_TARGET[i]}" \
        "$total" "$in_file" "$witness" "$unattr" "$accounted" "$rc" "$log" "${J_PAT[i]}" "$ms" >>"$ACTUAL"
    MODULE_MS["${J_M[i]}"]=$(( ${MODULE_MS["${J_M[i]}"]:-0} + ms ))
    cpu_ms=$(( cpu_ms + ms ))
    if [[ $SHOW_STACKS -eq 1 ]]; then
        echo "----- ${J_M[i]} ${J_MODE[i]} -fvalgrind=${J_VG[i]} taint=${J_TAINT[i]} target=${J_TARGET[i]} -----"
        cat "$log"
        echo "----- end -----"
    fi
done

# ── time, recorded ─────────────────────────────────────────────────────────
# Per module, most expensive first: this is the number that answers "can I wait
# for this?", and without it the only way to find the slow module is to sit
# through the run once.
echo
echo "Time by module (measurement only; the builds above are not counted):"
# ⚠ Sort on the raw millisecond integer, never on the formatted `12.3s`: under
# cs_CZ the decimal separator is a comma, so `sort -n` reads "12.3s" as 12 and
# ties every row that shares a whole second. Same trap as `du | sort -h` there.
for m in "${!MODULE_MS[@]}"; do printf '%s\t%s\n' "${MODULE_MS[$m]}" "$m"; done \
    | sort -rn | while IFS=$'\t' read -r ms_m name; do printf '%12s %s\n' "$(fmt_secs "$ms_m")" "$name"; done
printf 'TOTAL %s wall across %s job(s), %s of memcheck CPU time, %s runs\n' \
    "$(fmt_secs "$wall_ms")" "$JOBS" "$(fmt_secs "$cpu_ms")" "$NJOBS"
echo

[[ $DO_CHECK -eq 0 ]] && exit 0

# ── --check ────────────────────────────────────────────────────────────────
# Deliberately NOT a diff of exact totals. The `total` column includes the
# harness's own non-constant-time formatter and whatever std internals it
# reaches, so it moves with a zig or valgrind upgrade for reasons that say
# nothing about the module — and a check that goes red for the wrong reason
# gets muted, which is worse than no check. What is asserted is exactly what
# the claims rest on:
#
#   * every UNTAINTED control row is 0            (counts are taint-caused)
#   * every no-`-fvalgrind` trap row is 0         (the switch really is load-bearing)
#   * the claim row's in-file count EQUALS the expected value (0 for a module
#     claiming no secret-dependent branch; a stated small number where the
#     module documents which validations it keeps)
#   * the claim row's total is at least `total_min` (>0 wherever a propagation
#     witness is required, so a zero cannot mean "the taint never arrived")
#   * EVERY row — claim, control and trap alike — reports 0 UNATTRIBUTED
#     contexts, and its buckets account for valgrind's own context total.
#     Unconditional and not expressible in ctgrind-expected.tsv on purpose:
#     this is the rule that makes the in-file numbers mean anything, so it
#     must not be something a module can record its way out of.


# ── output pin ──────────────────────────────────────────────────────────────
#
# ⛔ WHY. The ct25519 audit (C1) mutated the HARNESS, not the module: the
# `.ct25519` branch stopped calling `mulRistrettoBase` and assigned the secret
# straight to the output. The table came out byte-identical to the baseline —
# `total 2 / in-file 0 / witness 2 / unattr 0` — and `--check` was GREEN. Every
# row whose claim is "in-file 0" has that hole, because a harness that never
# reaches the module also produces zero in-file contexts. That is 8 rows across
# 6 modules today.
#
# The counts cannot close it: "the module was not called" and "the module has no
# secret-dependent branch" are the same measurement. What separates them is the
# VALUE the harness prints, which every harness already does (`pk=`, `sig=`,
# `x=`, `create[N]=`, `cmov=`, …) — no harness needed changing, only pinning.
#
# Metadata lines are excluded by requiring a long hex value: `valgrind_support=`
# is not hex, and `L=32` / `lanes=4` are far too short to be a curve point or a
# tag. The threshold is 32 hex digits = 16 bytes, below any output here.
out_digest() {
    local log="$1"
    [[ -f "$log" ]] || { echo "NO-LOG"; return; }
    local vals
    # Unanchored on purpose: k256's ecdsa target prints three values on ONE
    # line (`r={x} s={x} recid={d}`), and an anchored match silently found
    # nothing there — the pin reported NO-OUTPUT, which is the right failure
    # but the wrong reason. `recid=3` and `L=32` stay excluded by the 32-digit
    # floor, and `valgrind_support=true` is not hex.
    vals="$(grep -aoE '[A-Za-z_][A-Za-z0-9_]*(\[[0-9]+\])?=[0-9a-f]{32,}' "$log" || true)"
    if [[ -z "$vals" ]]; then echo "NO-OUTPUT"; return; fi
    printf '%s\n' "$vals" | sha256sum | cut -c1-16
}

# ── source pin ──────────────────────────────────────────────────────────────
#
# ⛔ WHY THIS EXISTS, and why the obvious fix does not. The 2026-09-01 k256
# audit (G1) showed the in-file COUNT cannot see a leak that REPLACES an
# expected one: substituting `ecdsa_recover.zig:136`'s `s.isZero()` guard with
# a loop whose trip count is `privkey[31] & 7` leaks 3 key bits per signature
# and reports `total 15 / in-file 10 / witness 5 / unattr 0` — the baseline,
# exactly. The audit proposed pinning the LOCATIONS instead, one `file:line`
# set per row.
#
# Measured 2026-09-08 before building that: it would not work either. The
# substitution edits the line IN PLACE, so the file's numbering is unchanged
# and the stack line set is identical. Nor does the error COUNT help — both
# runs report `139 errors from 15 contexts`. The two memcheck logs are
# byte-identical apart from the pid. Nothing derived from the measurement can
# separate them, because memcheck's taint is binary and both branches are on
# key-derived values.
#
# So the pin has to be on the ARTEFACT instead: the digest of the sources whose
# contexts a row counts. Editing any of them turns the row red until someone
# re-measures and re-justifies. That is coarse — a comment change trips it —
# and coarse is the point: "the code that was analysed is the code that ships"
# is the property the counts silently assumed and never checked.
#
# Only the MODULE'S OWN files are hashed. A pattern may also name std files
# (`ct25519/std`, `chachapoly/aead`), which live outside the tree and move with
# the toolchain; the count bounds already carry those.
src_digest() {
    local module="$1" pattern="$2"
    local dir="$REPO_ROOT/modules/$module/src"
    [[ -d "$dir" ]] || { echo "NO-SRC"; return; }
    # `pattern` is a regex over basenames with `[.]` escapes: turn it back into
    # a plain alternation and take each name that exists in the module.
    local names; names="$(printf '%s' "$pattern" | sed 's/\[\.\]/./g' | tr '|' '\n')"
    local files=()
    local n
    while IFS= read -r n; do
        [[ -n "$n" && -f "$dir/$n" ]] && files+=("$dir/$n")
    done <<<"$names"
    if [[ ${#files[@]} -eq 0 ]]; then echo "NO-OWN-SRC"; return; fi
    printf '%s\n' "${files[@]}" | LC_ALL=C sort | xargs cat | sha256sum | cut -c1-16
}

echo
fail=0
declare -A NEW_OUT=()
while IFS=$'\t' read -r em emode etarget etotal_min ein_file esrc eout; do
    [[ "$em" =~ ^# ]] && continue
    [[ -z "$em" ]] && continue
    line=$(awk -F'\t' -v m="$em" -v mo="$emode" -v t="$etarget" \
        '$1==m && $2==mo && $3=="true" && $4=="yes" && $5==t { print }' "$ACTUAL")
    if [[ -z "$line" ]]; then
        # ⛔ AN EXPECTED ROW THAT WAS NOT MEASURED IS A FAILURE, unless the
        # caller asked for other modules. Until 2026-09-08 this was an
        # unconditional `continue`, and the hole it left is the one this whole
        # gate exists to close: `ALL_MODULES` is derived from the tree
        # (`module-graph` column 5, whose source is the harness file existing),
        # so DELETING or renaming `modules/<m>/src/ctgrind_harness.zig` drops
        # the module out of the run, every one of its expected rows is skipped,
        # and `--check` prints OK. Measured by hiding `ecvrf`'s harness: 7
        # modules measured instead of 8, `ecvrf` absent from the table, exit 0.
        # A module's constant-time claim stopped being verified and nothing
        # said so — the same shape as a gate that scans nothing and passes.
        local_wanted=0
        for _wm in "${MODULES[@]}"; do [[ "$_wm" == "$em" ]] && local_wanted=1; done
        if [[ $SUBSET_REQUESTED -eq 1 && $local_wanted -eq 0 ]]; then
            continue
        fi
        echo "FAIL $em/$emode/$etarget: this row is pinned in ctgrind-expected.tsv but was NEVER MEASURED. Either modules/$em/src/ctgrind_harness.zig is gone (so module-graph no longer reports the module) or ctgrind.sh has no TARGETS/MODES entry for this row. A pinned claim nobody measures is worse than no claim: remove the row on purpose, or restore the harness." >&2
        fail=1
        continue
    fi
    IFS=$'\t' read -r _ _ _ _ _ total in_file _ _ _ _ rowlog _ <<<"$line"
    # `N` pins an exact count; `>=N` / `<=N` pin only the direction. Exact is
    # for the numbers a SPEC.md states as a fact about the module (ed448's
    # three `Fe.invert` validations, ecvrf's three try-and-increment
    # branches, and every claimed zero). A bound is for counts that a
    # compiler or std change legitimately moves — the ReleaseSafe/Debug
    # overflow-check floods, and std's own `rejectIdentity` context that
    # ct25519's negative control depends on merely EXISTING.
    case "$ein_file" in
        ">="*) if [[ "$in_file" -lt "${ein_file#>=}" ]]; then
                   echo "FAIL $em/$emode/$etarget: in-file contexts $in_file, expected $ein_file" >&2; fail=1
               fi ;;
        "<="*) if [[ "$in_file" -gt "${ein_file#<=}" ]]; then
                   echo "FAIL $em/$emode/$etarget: in-file contexts $in_file, expected $ein_file" >&2; fail=1
               fi ;;
        *) if [[ "$in_file" != "$ein_file" ]]; then
               echo "FAIL $em/$emode/$etarget: in-file contexts $in_file, expected $ein_file" >&2; fail=1
           fi ;;
    esac
    if [[ "$total" -lt "$etotal_min" ]]; then
        echo "FAIL $em/$emode/$etarget: total contexts $total < required minimum $etotal_min (propagation witness did not fire)" >&2
        fail=1
    fi
    # Source pin. Absent column = not yet pinned; say so rather than pass.
    if [[ -z "${esrc:-}" ]]; then
        echo "FAIL $em/$emode/$etarget: no source digest in ctgrind-expected.tsv — run --update-digests" >&2
        fail=1
    else
        actual_src="$(src_digest "$em" "${PATTERN[$em/$etarget]:-}")"
        # A row whose pattern names only std files has nothing of the module's
        # own to pin. Say it out loud on every run: a pin that matches because
        # both sides are the same placeholder is a gate that scans nothing, and
        # a gate that scans nothing also exits zero.
        if [[ "$actual_src" == "NO-OWN-SRC" || "$actual_src" == "NO-SRC" ]]; then
            echo "NOTE $em/$emode/$etarget: no source pin — the pattern names no file of this module (its counts are bounds only)."
        fi
        if [[ "$actual_src" != "$esrc" ]]; then
            echo "FAIL $em/$emode/$etarget: the sources this row counts changed (digest $actual_src, pinned $esrc)." >&2
            echo "     The counts above cannot see a leak that REPLACES an expected one — measured, see 'source pin' in this script." >&2
            echo "     Re-read the contexts, satisfy yourself they are still the documented ones, then --update-digests." >&2
            fail=1
        fi
    fi
    # Output pin — see "output pin" above. This is the check that separates
    # "the module has no secret-dependent branch" from "the harness never
    # called the module", which the context counts render identical.
    if [[ "$DO_UPDATE_OUTPUTS" == "1" ]]; then
        # ⛔ `NO-OUTPUT`/`NO-LOG` are the absence of a value, not a value. Storing
        # one pins a string the checker below rejects unconditionally, so the row
        # would carry a digest AND fail forever -- a pin that looks done and
        # measures nothing. Leave it unpinned instead: `PENDING` is the honest
        # record of "this harness printed nothing this pin can read", and it says
        # the work is outstanding rather than broken.
        new_out="$(out_digest "$rowlog")"
        if [[ "$new_out" == "NO-OUTPUT" || "$new_out" == "NO-LOG" ]]; then
            echo "SKIP $em/$emode/$etarget: not pinning an output digest — the harness printed no value this pin can read ($new_out). It needs to print at least 32 hex digits of something derived from the secret; see out_digest." >&2
        else
            NEW_OUT["$em/$emode/$etarget"]="$new_out"
        fi
    elif [[ -z "${eout:-}" ]]; then
        echo "FAIL $em/$emode/$etarget: no output digest in ctgrind-expected.tsv — run --update-outputs" >&2
        fail=1
    else
        actual_out="$(out_digest "$rowlog")"
        if [[ "$actual_out" == "NO-OUTPUT" || "$actual_out" == "NO-LOG" ]]; then
            echo "FAIL $em/$emode/$etarget: the harness printed no value this pin could read ($actual_out)." >&2
            echo "     A harness that prints nothing cannot show it reached the module; see 'output pin'." >&2
            fail=1
        elif [[ "$actual_out" != "$eout" ]]; then
            echo "FAIL $em/$emode/$etarget: the harness's printed result changed (digest $actual_out, pinned $eout)." >&2
            echo "     Either the module now computes something else, or the harness stopped reaching it — the" >&2
            echo "     context counts cannot tell those apart, which is why this pin exists." >&2
            fail=1
        fi
    fi
done <"$EXPECTED_FILE"

if [[ "$DO_UPDATE_OUTPUTS" == "1" ]]; then
    tmp="$(mktemp)"
    while IFS= read -r ln; do
        if [[ "$ln" =~ ^# || -z "$ln" ]]; then printf '%s\n' "$ln" >>"$tmp"; continue; fi
        IFS=$'\t' read -r m mo t tm inf sd od <<<"$ln"
        nd="${NEW_OUT[$m/$mo/$t]:-${od:-}}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$m" "$mo" "$t" "$tm" "$inf" "$sd" "$nd" >>"$tmp"
    done <"$EXPECTED_FILE"
    mv "$tmp" "$EXPECTED_FILE"
    echo "ctgrind: output digests rewritten in $EXPECTED_FILE"
    exit 0
fi

# ⚠ `asecs` is not decoration here either: `actual.tsv` grew a 14th column, and
# without a variable to land in, the LAST name in this list absorbs both field 13
# and field 14 joined by a tab -- so `apat` would become the regex plus a number,
# and the classify_contexts call below would search for a pattern that matches
# nothing. A trailing column is only free when every reader is told about it.
while IFS=$'\t' read -r am amode avg ataint atarget atotal _ _ aun aacc _ alog apat asecs; do
    if [[ "$ataint" == "no" && "$atotal" != "0" ]]; then
        echo "FAIL $am/$amode/$atarget: untainted control reported $atotal contexts, expected 0" >&2
        fail=1
    fi
    if [[ "$avg" == "false" && "$atotal" != "0" ]]; then
        echo "FAIL $am/$amode/$atarget: no-fvalgrind trap reported $atotal contexts, expected 0" >&2
        fail=1
    fi
    # ── fail-closed: nothing is allowed to go uncounted ─────────────────────
    if [[ "$aun" != "0" ]]; then
        echo "FAIL $am/$amode/$atarget (tainted=$ataint, -fvalgrind=$avg): $aun UNATTRIBUTED context(s) — matched neither the module pattern '$apat' nor the formatting witness. A context nobody can name is a leak until proven otherwise; do NOT close this by widening the pattern until you know what it is:" >&2
        classify_contexts "$alog" "$apat" show-unattr >&2
        fail=1
    fi
    if [[ "$aacc" == "0" ]]; then
        echo "FAIL $am/$amode/$atarget (tainted=$ataint, -fvalgrind=$avg): the classifier accounted for fewer contexts than valgrind reported ($atotal) — the paragraph walk in classify_contexts has gone stale against this memcheck's output format. Fix the walk, not the numbers." >&2
        fail=1
    fi
done <"$ACTUAL"

if [[ $fail -eq 0 ]]; then
    echo "ctgrind --check: OK (controls 0, traps 0, unattributed 0, every context accounted for, in-file counts as recorded in scripts/ctgrind-expected.tsv)"
else
    echo "ctgrind --check: FAILED — see above. Re-measure, then update scripts/ctgrind-expected.tsv AND the module's SPEC.md table together." >&2
fi
exit $fail
