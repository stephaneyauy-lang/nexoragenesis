#!/usr/bin/env bash
# Nexora Genesis - the normal NTASM build, and the refusal that guards it.
#
# This is the build AGENTS.md calls "le build normal": it produces the product
# binary out/c-bootstrap/ntasm/ntasm from our own C sources, and it refuses,
# loudly and with a non-zero exit, any attempt to build it out of NASM or out
# of a quarantined source.
#
# It writes nothing outside out/. It is invoked, never resident: no daemon, no
# scheduled task, no state kept in the source tree. The only thing it reads from
# the tree is the source it is allowed to read; everything it produces is a
# build output under out/, and no gate, no source and no release artefact may
# depend on any of it.
#
#   ntbuild.sh [build]        compile and link the product binary   (default)
#   ntbuild.sh check PATH...  classify candidate build inputs, exit 78 if any
#   ntbuild.sh selftest       run the refusal suite in both directions
#   ntbuild.sh policy         print the policy: grants, refusals, exit code
#   ntbuild.sh corpus         print the pinned product corpus: name|sources(+)|sha256
#   ntbuild.sh census         check the corpus DIRECTORIES: every .ntasm is
#                             either a pinned source or a named exclusion
#   ntbuild.sh pins [--verify] print the pinned granted-input digests: path|sha256
#   ntbuild.sh selfhost       run the fixed-point check alone (see below)
#   ntbuild.sh clean          remove out/c-bootstrap/ntasm
#   ntbuild.sh --help
#
# `build` runs the self-host check, so the check is not something a person has
# to remember. The check is scripts/ntselfhost.sh, which owns the definition of
# a fixed point for this producer and the byte comparison that backs it.
#
# Exit codes: 0 allowed or built; 78 refused (EX_CONFIG, see docs/guides/ntasm-build.md);
# anything else is a plain build failure.
set -euo pipefail

POLICY_TAG="NTBUILD-POLICY/1"
REFUSE_EXIT=78
CC_BIN=${NG_PRODUCER:-${CC:-gcc}}
OPT=${NG_OPT:--O2}

# The repository is located from this script, so the build works from any cwd.
SELF=$(realpath -m "${BASH_SOURCE[0]}")
REPO=${NG_REPO:-$(dirname "$(dirname "$SELF")")}
REPO=$(realpath -m "$REPO")
OUTDIR="$REPO/out/c-bootstrap/ntasm"
BINARY="$OUTDIR/ntasm"
OBJDIR=${NG_OBJDIR:-$OUTDIR/obj}
INPUTS_RECORD="$OUTDIR/build.inputs"

# --------------------------------------------------------------------------
# The grant list. A build input is legal if and only if it is in this list or is
# a header transitively included by a list entry. The list is closed: there is
# no environment variable, no flag and no file on disk that can add to it.
# --------------------------------------------------------------------------
GRANT_NAME="bootstrap C, ADR0012 temporary bootstrap producer"
GRANTED_TUS=(
  compiler/c/nova/frontend/nova.c
  compiler/c/ntasm/frontend/ntasm.c
  compiler/c/ntasm/frontend/frontend.c
  compiler/c/ntasm/backend/codegen.c
  compiler/c/ntasm/backend/x64.c
  compiler/c/ntasm/formats/pe.c
  compiler/c/ntasm/formats/object.c
  compiler/c/ntasm/formats/object_build.c
  compiler/c/ntasm/formats/object_link.c
  compiler/c/ntasm/formats/object_materialize.c
  compiler/c/ntasm/analysis/conformance.c
  compiler/c/nova/runtime/run_host.c
  compiler/c/nova/runtime/runtime_v2.c
  compiler/c/nova/pe/pe_oracle.c compiler/c/nova/backend/machine_driver.c
  compiler/c/ntasm/cli/cli.c
  compiler/c/ntasm/cli/main.c
)
INCLUDE_DIRS=(compiler/c compiler/c/nova)

# --------------------------------------------------------------------------
# The pinned BYTES of every granted input: path | sha256, one row per file,
# written here as literals for the same reason RECORDED_EXAMPLES is written as
# literals. A pin has to live in the same artefact that consults it, so there
# is nothing to fall out of sync and nothing to fall out of step; a pin in a
# separate file is a second authority nobody opens, and a pin the build writes
# is a record, not a pin.
#
# WHY THIS EXISTS, measured on this tree: the grant above is NAME-based. A hard
# link planted at a granted name -- inode identical, link count 2 -- was not
# refused. The NASM bytes reached the compiler and the build stopped at gcc,
# not at the guard. And it was not NASM-specific: an ordinary UNGRANTED C file,
# refused on its own with class=not-granted, was equally compilable at a granted
# name. So classify() matching a path against GRANTED_TUS was the weak link, and
# the NASM rules were doing their job the whole time. Rule 1 refuses .asm; a link
# at a granted .c name is not .asm. Adding a fourth rule to that list would have
# made the list longer and the hole identical.
#
# WHY NOT input_manifest(), which already digests every granted TU and every
# header: because it exists for incremental rebuild, so it would have recorded
# the substituted digest as the new baseline and carried on. A manifest that
# updates its baseline to whatever it finds is a void run with a persistence
# file -- it would have reported the build fine, recorded the substituted input
# as the new normal, and the next run would have agreed with it. That is the
# defect being fixed, rebuilt one layer down. A pin is only a pin if it is
# somewhere the build cannot write.
#
# WHAT TO DO WHEN A GRANTED INPUT LEGITIMATELY CHANGES. It is not a corner: it
# is the first time anyone edits a .c under compiler/c/. You edit
# the pin in this array, the same way you edit RECORDED_EXAMPLES above - the
# refusal prints the digest to paste, so the edit is one line and the decision
# stays on the record in the file that consults it. This check refuses until you
# do that on purpose. It is a check, not an inconvenience, and the sentence
# that makes it usable is this one.
# --------------------------------------------------------------------------
# 14 October 2026: only the two already integrated A4/A6 inputs are re-pinned.
# Evidence: out/a1-a10-a9-20261014/build-pin-review.json. No automatic trust update.
PINNED_INPUTS=(
  "compiler/c/nova/frontend/nova.c|62ec6ffebb45a1b519e4ef39f03f820ebc748d95938bc1a7b8d6fcc9f04ca8e9"
  "compiler/c/ntasm/frontend/ntasm.c|23f31fcde8dde500bff0a681e12a5d2f5e00d471ce5b5c41e51120014c061ab0"
  "compiler/c/ntasm/frontend/frontend.c|b49f691c5e64525548ca3bf54449c8fdac4512696d5eed21a2349e179080fa0d"
  "compiler/c/ntasm/backend/codegen.c|dd7095e4fd7c1aea771379079fb6658c336841679efa3da1a5f1e6f7bf62e7a1"
  "compiler/c/ntasm/backend/x64.c|6abff90c1b7fefd8ef10fbe7cdc1611ee9c2c3daf2084772bad62648dd6eec6f"
  "compiler/c/ntasm/formats/pe.c|a99fdcc13284b13bfdc65516e4c4f94af35e5aca8ff9643b31ad5fc1f3c37d38"
  "compiler/c/ntasm/formats/object.c|671b07324d1b59b6181fc5766e79c7b94887d6bb5785f8fe444b18a083e2a855"
  "compiler/c/ntasm/formats/object_build.c|4c00f6cbcb08a983d099229be568bb957c3c0dd7bfc4b8bf75da44953de7a049"
  "compiler/c/ntasm/formats/object_link.c|b1ca1c1b4771d22a3d63f91724ca51cb88ca41732ec16f2ff8c442f856f08802"
  "compiler/c/ntasm/formats/object_materialize.c|3c437c05966ad7189263f9023a26f85a471fea3250c9f51d21699f45247e7cf5"
  "compiler/c/ntasm/analysis/conformance.c|861ac0560f7e84eaf1caea0beb5068b66a5c14b85bc8e9484014816347de3f5b"
  "compiler/c/nova/runtime/run_host.c|c549420c9dd4c6469a16a252d297c91834e0a1666fbbde46bd6ce46bec93be0c" "compiler/c/nova/backend/machine_driver.c|34081ca1bf67d5d8b7722167a3584253691238a4563dc5900bdfeb3a7e5fdf8d"  # A7 7 Oct 2026: the Machine IR driver cli.c calls
  "compiler/c/nova/runtime/runtime_v2.c|6a28aac6c7c31c25432cdf2c41b55c5daac2c0b98689d6efbc37ee25e4bfbfd3"
  "compiler/c/nova/pe/pe_oracle.c|1f9b88b14d7808cceb22504b2d4a77c3f70858f636b4cbeb40c90c4be5e88964"
  "compiler/c/ntasm/cli/cli.c|92e3311037c2de0c3941cba21c81a50bc38f91c9793c2a541be04d5ed204081e"  # A7 7 Oct 2026: --backend mir for assemble/object/link/check, see the cli.c header
  "compiler/c/ntasm/cli/main.c|1c4739b7d0f1c5190859ad04f8d37cb077918fd65911321799b684822b9f9995"
  "compiler/c/ntasm/cli/cli.h|f7c9ea5ee5e8f25264af117b99f00b0f1d029232e9bc3c9ade81b8285e8209e0"
  "compiler/c/ntasm/backend/codegen.h|76d14982557790cd8e17098b78e05badf59a1a13cc880374b0998ea0e2400b91"
  "compiler/c/ntasm/analysis/conformance.h|141153946df8292e9417e1da16a3cc270795c9e4ac6fe4b6718af91a5bed79bf"
  "compiler/c/ntasm/frontend/frontend.h|efe84cf18b182abde658c5be40ea7d5e34cc5245568e8c65c720a072d311b34c"
  "compiler/c/nova/frontend/nova.h|84db76383bbf7ad5755d532148594cb3328bd26c9fd76a0df2830a9dd102d1d3"
  "compiler/c/ntasm/frontend/ntasm.h|80cdcc5e9e6fdf7b0c01f749b6920ef68c352ae9c188f9afbc2a16e9899c36ca"
  "compiler/c/ntasm/formats/object.h|29478805b7553fd3a461c7e2bcff7bccf4524ae90f3b773653e38c0b649e2659"
  "compiler/c/ntasm/formats/pe.h|defe69bb0fda431b5ae5dd0523bb9bef9ebbac628eb0fed29f6bdad1a1f32d9f"
  # ATTESTED 4 October 2026, not merely re-pinned, and the reason is written
  # here because a pin with no stated warrant is the thing that goes stale in
  # the first place. The two headers below were rewritten at 02:19 on 4 October
  # -- a documented repair of a wrongly-removed overflow guard in the kind-2
  # relocation arm, the reasoning written into the file itself -- and the pins
  # were not moved with them, so the build refused with class
  # granted-input-digest on both. The change is legitimate; only the record of
  # it was missing.
  #
  # THE WARRANT, as evidence rather than as assertion: the bytes now on disk,
  # f26b3dee39882b444dff238810457e2b0ea52507c5a801be43f0dfafb16b43b5, are
  # carried by four independent archives of the same day --
  # out/audits/code-20261004/before-hoist, out/audits/code-20261004/frozen,
  # out/audits/code-20261004/snapshot and out/a2-finish-20261004 -- while the
  # previously pinned d5e081afc69914c0afc5526e2fac535a866a12fa86e9c0acf0d1d2d3ea6b3ebe
  # is present NOWHERE under out/. A pin is only worth having when the bytes it
  # names are attested by something that is not the file being pinned.
  #
  # ONE THING THIS DOES NOT SAY, recorded because it was believed first and
  # measured afterwards: pe_layout_oracle.h is byte-identical to pe_layout.h,
  # same include guard, and it ALWAYS was -- out/c-bootstrap/host-v6,
  # host-v7, a6/root-build, builds/w26a9-det/repo, builds/w65frames/scratch
  # and nova/controller-20260926/workers/05-freeze-a1-spec all carry d5e081af
  # for BOTH files. So no check that compares the two against each other has
  # gone vacuous: there was never one. The two halves of the tree share one
  # layout header, which is a design fact, not a defect found here.
  #
  # ATTESTED BY: the session owner, 4 October 2026, on the evidence gathered by
  # lot W222 and reported to them. Nobody in lot W222 wrote these bytes.
  "compiler/c/ntasm/formats/pe_layout.h|f26b3dee39882b444dff238810457e2b0ea52507c5a801be43f0dfafb16b43b5"
  "compiler/c/ntasm/backend/x64.h|50fbb9c0b132561a6e40ac5e8ae33f700ccbadd40d46ae98d861a62776e27ac4"
  "compiler/c/nova/pe/pe_layout_oracle.h|f26b3dee39882b444dff238810457e2b0ea52507c5a801be43f0dfafb16b43b5"
  "compiler/c/nova/pe/pe_oracle.h|9aff8f47b5786b6979bcfc269298c128b76310985fc6abd34d33bb38f7fd262b"
  "compiler/c/nova/runtime/run_host.h|54497b69a0211180b6a7b284fefe8480bb9d481f1720e12ee6f1f925f5d401e3" "compiler/c/nova/backend/machine_driver.h|a8a4f0bc5c14b1e08e5ed2472a592410ac134d6cbc6eed47bbbfa27d1c77d395"
  "compiler/c/nova/runtime/runtime.h|4ecf914e5da82ac2801b820f6c21482627fde22d1e21596e9699018decae38d5"
  "compiler/c/nova/runtime/runtime_v2.h|1536f025c3f1ee35ab61eba2a6dd9fa37c1144c1f828ca863ed4b45e1e24bb3d"
  "compiler/c/nova/runtime/uefi_platform.h|103973e467192c0c88d9501e6dadece886dcb543481add36762c16a6fe360e59"
)

# Directories under quarantine/, and what may be read from each. The NASM tree
# is listed with an EMPTY grant on purpose: it has no grant at all, and none can
# be written without editing this file, which is the whole of the refusal.
QUARANTINE_TREES=(
  "legacy/nasm|"
  "compiler/c|$GRANT_NAME"
  "tests/c|test fixtures, never granted to the producer"
)

# Producers the normal build must never call. Checked on the basename of the
# program, so a wrapper on PATH does not get a free pass by being renamed.
FORBIDDEN_PRODUCERS=(nasm nasm64 yasm fasm as gas llvm-mc llvm-nm masm ml64)
# Extensions the normal build must never accept as an input, whether or not the
# file exists: the build translates C, it never assembles.
ASSEMBLY_EXTS=(asm ASM nasm NASM s S sx)

# ============================ THE DEFINITION OF "CORPUS" =====================
#
# "Corpus" was one word with three referents, in three files, and two lots
# found it independently from different lists and neither count was wrong. The
# three lists are NOT three versions of one thing. Measured on 2026-09-30, each
# answers a different question, is consumed by a different reader, and cannot be
# derived from either of the others. So the word is given THREE names, and
# "corpus" on its own is retired rather than pointed at a winner.
#
#   1. THE PINNED CORPUS -- RECORDED_EXAMPLES below, printed by
#      `ntbuild.sh corpus`. 8 programs over 9 files, each row a name, a list of
#      sources, and the sha256 of the PE the shipped binary assembles it to.
#      Question answered: what does the PRODUCT promise to emit? Owner: THIS
#      FILE. Consumers: the normal build, scripts/ntselfhost.sh, and the `corpus`
#      subcommand. This is the only list of the three that a build acts on.
#
#   2. THE COVERAGE CORPUS -- the CORPUS[] array in
#      tests/c/nova/nova_corpus_convergence.c, 7 members.
#      Question answered: does the NOVA producer converge, byte for byte, on
#      the C reference? It is a deliberate SUBSET of (1): it omits
#      `multi-app-math` because that gate drives one single-file Nova entry and
#      has measured nothing about a two-module program. Owner: that gate. It is
#      not a second version of (1) and must never be edited to match it; it is
#      narrower on purpose, and the paragraph in that file says why.
#
#   3. THE BOUNDARY SHAPES -- the BOUNDARY[] array in the same file, 13 rows.
#      Question answered: for each syntactic SHAPE, does the producer converge
#      or refuse, and with which code? Most rows are source literals that exist
#      in no directory at all; four name a file. Owner: that gate. Calling this
#      a corpus was the third referent, and it is the worst of the three: a
#      reader who took "the corpus" to mean this would be counting shapes.
#
# docs/guides/ntasm-cli.md section 4's table is NOT a fourth list: it is (1) rendered,
# restricted to the single-file rows, which is why it has seven lines where (1)
# has eight. That restriction is stated in the guide and asserted by the cli
# gate, and the guide must keep saying it.
#
# WHERE THE DEFINITION LIVES, and the one thing it could not be. The natural
# owner is the criterion document, docs/status/ntasm-completion.md, which is the
# authority for what the product must do. This lot does not hold that file --
# W25A3Complete does, and an ownership map is not negotiable -- so the
# definition is written here instead, in the file that holds the canonical
# list, and the guide points at it. THAT IS A DEVIATION FROM THE BRIEF'S OWN
# RANKING AND IT IS DELIBERATE: a definition held only by a lot that was going
# to be gone by the next wave would be one edit away from being nobody's.
#
# The property that makes a definition of a word worth having is that the next
# reader can find it. This paragraph is the one place the three names are
# defined, and the census below is what keeps (1) honest about its own
# directory.
#
# ============================ END OF THE DEFINITION ===========================
#
# The pinned corpus: one row per program, name | sources | sha256 of the PE it
# assembles to. These are the digests docs/guides/ntasm-cli.md section 4 recorded, and
# they are also the digests the cli gate compares. The bytes come out of the
# binary this script links; the expectation is a record, not a restatement of
# this file.
#
# `sources` is a LIST of repository-relative paths joined by '+', and it is a
# list because a program is a set of compilation units: `multi-app-math` is a
# module that imports another, and before this field existed the corpus had no
# way to name it at all. Every source goes to ONE `assemble` call, in the order
# written. The seven single-file members produce exactly the command line they
# produced when the path was synthesised from the name, and no directory is
# named by this file any more.
#
# A multi-source member is pinned on the ONE-SHOT form, `assemble a b -o x`,
# because that is the form this build and ntselfhost.sh run. The object+link
# form produces DIFFERENT bytes and is deliberately not pinned here: same 3584
# bytes, 352 of them differ, and nothing in this file ever executes it.
RECORDED_EXAMPLES=(
  "return42|examples/ntasm-v0/c-bootstrap/return42.ntasm|1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457"
  "return43|examples/ntasm-v0/c-bootstrap/return43.ntasm|5811fda51dd2e115eabb39cc2d5c688fcc494da29660e4ac817794bc2b127ac3"
  "returnmax|examples/ntasm-v0/c-bootstrap/returnmax.ntasm|f91e4ba4a0aa3901baebf42f227b05fc97439368584b00737e88ae944cd2bbb5"
  "helper-first|examples/ntasm-v0/c-bootstrap/helper-first.ntasm|c74c7db2e1cf0e6f21e96eac129fee50ef77f705d2bbe9e8ee477c6ea4e5e9c3"
  "static-data|examples/ntasm-v0/c-bootstrap/static-data.ntasm|43fddd77fe59b29b11e6e1d0d05ec05e02d159a357484da8090bfe5fe1dc207a"
  "mutable-data|examples/ntasm-v0/c-bootstrap/mutable-data.ntasm|42f6e3459bdf7bf32280dbea534165d453c361a5fe9228135ae7562f48420690"
  "comptime-macro|examples/ntasm-v0/c-bootstrap/comptime-macro.ntasm|1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457"
  "multi-app-math|examples/ntasm-v0/c-bootstrap-multi/app.ntasm+examples/ntasm-v0/c-bootstrap-multi/math.ntasm|c9d9786d9edd2210b3b9d90c96f3da7997d3b260d286dd219e7ef174f526c08d"
)

# ============================ THE CENSUS, BOTH DIRECTIONS ====================
#
# WHY A CENSUS AND NOT A FLOOR. The cli gate's check on the guide is
# `examples.count >= 7` (tests_ntasm_cli.c:805): a FLOOR. A floor cannot detect
# the defect it was written near, because a ninth file in this directory does
# not lower the count -- the guide table would still hold its seven rows and
# still go green. A floor tolerates growth in one direction only, and the
# direction that matters here is a file appearing with nothing pinning it.
# Measured on 2026-09-30: NO GATE ANYWHERE ENUMERATES THIS DIRECTORY.
# tests_ntasm_cli.c names the directory to build a path and never lists it;
# nova_corpus_convergence.c lists programs, not files. So the floor was not a
# deliberate tolerance for unpinned files -- it is the only check that exists,
# and a check that cannot fail on the defect is not a tolerance of it.
#
# So the census lives HERE, and it is an EQUALITY in both directions, which is
# the shape that can actually catch the thing:
#   - every .ntasm under CORPUS_DIRS is either a source of a pinned row, or is
#     named in CORPUS_EXCLUSIONS below. A file that is neither is RED.
#   - every entry of CORPUS_EXCLUSIONS still exists on disk. An exclusion for a
#     file that was deleted is RED, because it is a claim about the tree that
#     the tree no longer supports.
# The second direction is the one a reader forgets, and without it this table
# could rot into a list of files that were once here.
#
# `call-private-stmt.ntasm` is the case that produced the census, and its
# exclusion is DELIBERATE, not an oversight. Measured 2026-09-30: it assembles
# cleanly (exit 0, 3584 bytes, sha256 b1e549ff...), so "it cannot be pinned"
# was never true -- the guide said pinning it "needs a digest this page cannot
# produce", and the digest is producible by two independent routes (the shipped
# binary, and the gate's C reference, which agree byte for byte). It is
# excluded anyway, for a reason that is about what a corpus row PROMISES rather
# than about feasibility: a pinned row is a product guarantee re-checked on
# every selftest AND booted under QEMU per docs/guides/ntasm-cli.md section 6, and
# this program has no QEMU run and no boot record. Adding it to
# RECORDED_EXAMPLES would assert a boot evidence that does not exist. So it
# stays out of the pin, and the reason it stays out is written here where the
# next person adding a tenth file will read it -- rather than being left to be
# rediscovered as a hole.
#
# The two `-data` files in c-bootstrap-multi are excluded for a different and
# documented reason: they do not assemble at all (E200, docs/guides/ntasm-cli.md
# section 4.1), so there is no digest to pin. That is a property of the files,
# not a choice about them, and the two are kept in separate rows for that reason.
CORPUS_DIRS=(examples/ntasm-v0/c-bootstrap examples/ntasm-v0/c-bootstrap-multi)

# path|why it is not a pinned row. Read by cmd_census in BOTH directions.
CORPUS_EXCLUSIONS=(
  "examples/ntasm-v0/c-bootstrap/call-private-stmt.ntasm|a convergence member, not a product promise: it is BOUNDARY row call_private_stmt_body in nova_corpus_convergence.c and is byte-checked there every run, but it has no QEMU boot record, and a pinned row is re-checked on every selftest AND booted per docs/guides/ntasm-cli.md section 6. Its digest IS producible (b1e549ffb105d1a4daef4efb1935b29a881ec899cf90db98f87a65dab47b943e, measured 2026-09-30 by the shipped binary and by the gate's C reference, which agree); the exclusion is about missing boot evidence, not about feasibility"
  "examples/ntasm-v0/c-bootstrap-multi/app-data-import.ntasm|does not assemble: the C frontend reads an import as a function signature, so 'import math_data.step as step: u64' against an 'export data' is refused E200. Measured and shown in docs/guides/ntasm-cli.md section 4.1. There is no digest to pin because there is no image"
  "examples/ntasm-v0/c-bootstrap-multi/math-data.ntasm|the data half of the pair above; the refusal is on the importing unit, and neither file assembles, so neither is a member"
)

# Read one corpus row. A row is a fact about a program, and the two readers
# below must not be able to read it differently, so the split exists once.
# bash 4.3 namerefs: corpus_row <row> <name-var> <sources-var> <digest-var>
corpus_row() {
  local -n _cr_name=$2 _cr_srcs=$3 _cr_want=$4
  local _cr_row=$1 _cr_rest
  _cr_name=${_cr_row%%|*}
  _cr_rest=${_cr_row#*|}
  _cr_want=${_cr_rest##*|}
  _cr_srcs=${_cr_rest%|*}
}

# The corpus row to a producer command line: '+'-joined paths in, one assemble
# invocation out, sources in the order written. Two files carry this - here and
# scripts/ntselfhost.sh run_generation - and they are the only two places the
# list is turned back into arguments.
corpus_argv() { # corpus_argv <sources> <repo-prefix> <argv-name>
  local -n _ca_out=$3
  local -a _ca_parts=()
  local _ca_p
  IFS=+ read -r -a _ca_parts <<<"$1"
  _ca_out=()
  for _ca_p in "${_ca_parts[@]}"; do _ca_out+=("$2/$_ca_p"); done
}

# --------------------------------------------------------------------------
# Refusal
# --------------------------------------------------------------------------

# Print one refusal block on stderr. $1 class, $2 the path, rest the reason.
refuse_block() {
  local class=$1 path=$2
  shift 2
  {
    echo "NTBUILD_REFUSED class=$class"
    printf '  input:   %s\n' "$path"
    printf '  reason:  %s\n' "$1"
    shift
    local l
    for l in "$@"; do printf '           %s\n' "$l"; done
  } >&2
}

# Refuse and stop the build.
die_refuse() { refuse_block "$@"; exit "$REFUSE_EXIT"; }

have() { # have <needle> <haystack...>
  local n=$1 h
  shift
  for h in "$@"; do [ "$h" = "$n" ] && return 0; done
  return 1
}

# Classify one candidate build input.
# Sets CLASS and WHY. Returns 0 when the input is allowed, 1 when it is refused.
# The order of the tests is the order of the rules in docs/guides/ntasm-build.md, and
# the first rule that matches is the one reported: a file under the NASM
# quarantine is reported as such even though it is also an assembly file,
# because the location is the fact the reader needs.
CLASS=; WHY=()
classify() {
  local raw=$1 abs rel base ext dir grantpart tree under
  abs=$(realpath -m "$raw")
  if [ "${abs#"$REPO"/}" != "$abs" ]; then rel=${abs#"$REPO"/}; else rel=$abs; fi
  base=$(basename "$abs")
  ext=${base##*.}

  # Rule 1 - the NASM quarantine. No grant exists for it, so this cannot be
  # talked out of by any option; the grant list has no entry to point at.
  for dir in "${QUARANTINE_TREES[@]}"; do
    tree=${dir%%|*}; grantpart=${dir#*|}
    under=0
    if [ "$rel" = "$tree" ] || [ "${rel#"$tree"/}" != "$rel" ]; then under=1; fi
    if [ "$grantpart" = "" ] && [ "$under" = 1 ]; then
      CLASS=quarantine-nasm-input
      WHY=(
        "AGENTS.md, Purete des sources: NASM is a temporary quarantined"
        "producer, never the final one, and the normal build must refuse any"
        "NASM invocation once NTASM is self-hosting."
        "This build carries no grant for legacy/nasm/ at all, so"
        "no flag and no environment variable can make this input legal."
        "remedy: translate the .ntasm with NTASM itself, or keep working under"
        "legacy/nasm/ outside the normal build."
      )
      return 1
    fi
  done

  # Rule 2 - an assembly input of any kind. Decided before the file is touched,
  # so a future .S cannot be introduced by being created later.
  if have "$ext" "${ASSEMBLY_EXTS[@]}"; then
    CLASS=assembly-input
    WHY=(
      "The normal build translates C and never assembles. AGENTS.md allows no"
      "GAS, no MASM and no inline assembly, and NASM is refused outright, so no"
      "assembly extension is a build input of this build whether or not the"
      "file exists."
    )
    return 1
  fi

  # Rule 3 - outside the repository.
  if [ "$rel" = "$abs" ]; then
    CLASS=outside-repo
    WHY=(
      "The normal build reads only from the repository. A path that resolves"
      "outside $REPO is not a source of this project."
    )
    return 1
  fi

  # Rule 4 - not a file that is there.
  if [ ! -f "$abs" ]; then
    CLASS=nonexistent-input
    WHY=("A build input that is not a regular file cannot be compiled.")
    return 1
  fi

  # Rule 5 - not a C source or header.
  if [ "$ext" != c ] && [ "$ext" != h ]; then
    CLASS=not-a-c-source
    WHY=(
      "The granted inputs are C translation units and C headers. $base is"
      "neither, and no other language enters the normal build."
    )
    return 1
  fi

  # Rule 6 - a granted translation unit, or a header it includes.
  if have "$rel" "${GRANTED_TUS[@]}" || have "$rel" "${HEADER_CLOSURE[@]}"; then
    CLASS=allowed
    return 0
  fi

  # Rule 7 - inside a quarantined tree but not granted, or inside the tree and
  # not granted at all. Same effect, different message.
  for dir in "${QUARANTINE_TREES[@]}"; do
    local tree=${dir%%|*}
    if [ "$rel" = "$tree" ] || [ "${rel#"$tree"/}" != "$rel" ]; then
      CLASS=ungranted-quarantine-source
      WHY=(
        "$rel lives under $tree, which is quarantined, and it is not in the"
        "grant list of $POLICY_TAG. The grant is closed: adding a file from a"
        "quarantined tree to the normal build is an edit to this script and a"
        "decision on the record, never a default."
      )
      return 1
    fi
  done

  CLASS=not-granted
  WHY=(
    "$rel is inside the repository but is not a granted build input of"
    "$POLICY_TAG. The grant covers ${#GRANTED_TUS[@]} C translation units and"
    "the headers they include, and nothing else."
  )
  return 1
}

# Every header transitively included by a granted translation unit. Computed
# from the granted sources, not written out here, so a new #include is picked up
# without this file having to be edited - and a file that nothing includes is
# still not a build input.
HEADER_CLOSURE=()
compute_header_closure() {
  local queue=("${GRANTED_TUS[@]}") cur inc dir cand abs found
  HEADER_CLOSURE=()
  while [ ${#queue[@]} -gt 0 ]; do
    cur=${queue[0]}
    queue=("${queue[@]:1}")
    while IFS= read -r inc; do
      [ -n "$inc" ] || continue
      found=0
      for dir in "$(dirname "$cur")" "${INCLUDE_DIRS[@]}"; do
        [ -f "$REPO/$dir/$inc" ] || continue
        abs=$(realpath -m "$REPO/$dir/$inc")
        case "$abs" in "$REPO"/*) ;; *) die_refuse outside-repo "$inc" "Header resolves outside the repository." ;; esac
        cand=${abs#"$REPO"/}
        if ! have "$cand" "${HEADER_CLOSURE[@]}"; then
          HEADER_CLOSURE+=("$cand")
          queue+=("$cand")
        fi
        found=1
        break
      done
      [ "$found" -eq 1 ] || die_refuse nonexistent-input "$cur:$inc" "Quoted header is missing from the relocated source tree."
    done < <(sed -n 's/^[[:space:]]*#[[:space:]]*include[[:space:]]*"\([^" ]*\)".*/\1/p' "$REPO/$cur")
  done
}

# The pinned digest of one repo-relative path, or nothing when no row names it.
# Prints nothing and fails when the path is unpinned: a granted input with no
# pin is a hole, not a pass, and it is treated as one below.
pin_digest() { # pin_digest <repo-relative-path> -> sha256 on stdout
  local want=$1 row
  for row in "${PINNED_INPUTS[@]}"; do
    if [ "${row%%|*}" = "$want" ]; then printf '%s\n' "${row#*|}"; return 0; fi
  done
  return 1
}

# Every granted input, as repo-relative paths, deduped and normalised. The
# closure can hold a spelling like compiler/c/nova/../nova.h, and
# two spellings of one file must not be two pins or the count lies.
granted_input_paths() {
  local p abs
  for p in "${GRANTED_TUS[@]}" "${HEADER_CLOSURE[@]}"; do
    abs=$(realpath -m "$REPO/$p")
    printf '%s\n' "${abs#"$REPO"/}"
  done | sort -u
}

# The check. Every granted input must be named by a pin row and must hash to
# it. Both directions are enforced, because a pin set that silently stopped
# covering an input is the same void run wearing a different hat: "32 checked"
# over a set of 40 is not coverage.
check_granted_input_digests() {
  local -a paths=()
  local path want got checked=0 row
  while IFS= read -r path; do paths+=("$path"); done < <(granted_input_paths)
  [ "${#paths[@]}" -gt 0 ] || die_refuse empty-grant "$POLICY_TAG" \
    "No granted input resolved. A pin check that checked nothing is not a pass." \
    "remedy: this is a defect in this script, not a permitted tree."
  for path in "${paths[@]}"; do
    if ! want=$(pin_digest "$path"); then
      die_refuse unpinned-granted-input "$path" \
        "$path is a granted build input and no row of PINNED_INPUTS names it." \
        "A granted input the pin set does not cover is a hole, not a pass: the" \
        "grant is what may be READ, the pin is what may be COMPILED, and this" \
        "file has granted the read without pinning the bytes." \
        "remedy: add the row, exactly as you would edit RECORDED_EXAMPLES:" \
        "  scripts/ntbuild.sh pins"
    fi
    got=$(digest "$REPO/$path")
    checked=$((checked + 1))
    if [ "$got" != "$want" ]; then
      die_refuse granted-input-digest "$path" \
        "$path is granted by NAME and its bytes are not the pinned ones." \
        "expected sha256: $want" \
        "actual   sha256: $got" \
        "The grant is name-based, so a hard link or a copy planted at this" \
        "path keeps the name the policy matches on and changes everything the" \
        "compiler sees. This is the check that stops it, and it is a refusal" \
        "rather than a rebuild: a manifest would have recorded this digest as" \
        "the new baseline and agreed with it on the next run." \
        "remedy, if the change is legitimate: edit the pin in PINNED_INPUTS in" \
        "this file, the same way you edit RECORDED_EXAMPLES above. The digest" \
        "to paste is printed here and by 'scripts/ntbuild.sh pins'."
    fi
  done
  # A row naming something the grant does not read is a stale pin, and it is
  # reported as a defect rather than ignored: an ignored row is a claim about a
  # file that is not a build input any more.
  for row in "${PINNED_INPUTS[@]}"; do
    have "${row%%|*}" "${paths[@]}" || die_refuse stale-input-pin "${row%%|*}" \
      "PINNED_INPUTS names ${row%%|*}, which the grant does not read." \
      "A pin over a file that is no longer a build input describes nothing this" \
      "build can enforce, and leaving it there is how a pin set rots into" \
      "decoration." \
      "remedy: delete the row, in the same edit that stopped granting the file."
  done
  echo "NTBUILD_INPUTS_PINNED checked=$checked rows=${#PINNED_INPUTS[@]}"
  return 0
}

# The producer itself. A build whose compiler is an assembler is refused before
# a single file is read.
check_producer() {
  local base
  base=$(basename -- "${CC_BIN%% *}")
  if have "$base" "${FORBIDDEN_PRODUCERS[@]}"; then
    die_refuse forbidden-producer "$CC_BIN" \
      "AGENTS.md: NASM is a temporary quarantined producer, never the final" \
      "one, and the normal build must refuse any NASM invocation. The producer" \
      "selected for this build is $base, which is an assembler." \
      "remedy: leave the producer at its default, or set NG_PRODUCER to a C" \
      "compiler. The C bootstrap compiler is the only producer the normal" \
      "build accepts."
  fi
}

# The identity of the producer, not just its name. check_producer above reads
# the BASENAME, which a wrapper defeats: a file named `gcc` earlier on PATH that
# calls nasm and returns gcc's exit code produces a valid object and passes
# every other check in this script. Wave 8 recorded that vector as uncovered;
# this is the closure, and it is a refusal rather than a comment.
#
# Two properties are enforced, in this order:
#   1. the producer must resolve to a real file that is not a script. A shell
#      script on PATH named like a compiler is a wrapper by construction - the
#      legitimate producer named in AGENTS.md, "GCC/Clang and their linker", is
#      a compiled binary - so this refuses the shape the attack takes.
#   2. the producer's sha256 is recorded in the build log and compared with the
#      one the previous build recorded. A digest change is not a refusal: a
#      legitimate toolchain upgrade must stay possible. It is a loud line
#      naming both digests, so the swap is on the record and not invisible.
#
# What this does NOT close: a compiled wrapper, which is not a script and has a
# legitimate-looking digest until it is pinned by an auditor. A pinned digest
# closes that one, and the pin is what the build log is for. A check that
# cannot name its own limit is worse than no check.
PRODUCER_PIN=""
check_producer_identity() {
  local tok resolved head2
  tok=${CC_BIN%% *}
  if ! resolved=$(command -v -- "$tok" 2>/dev/null) || [ -z "$resolved" ]; then
    die_refuse unresolvable-producer "$CC_BIN" \
      "The producer '$tok' is not on PATH, so this build has no producer at all." \
      "remedy: install a C compiler, or set NG_PRODUCER to its absolute path."
  fi
  if ! resolved=$(realpath -m -- "$resolved" 2>/dev/null) || [ ! -f "$resolved" ]; then
    die_refuse unresolvable-producer "$CC_BIN" \
      "The producer '$tok' resolves to $resolved, which is not a regular file." \
      "remedy: point NG_PRODUCER at the compiler binary itself."
  fi
  head2=$(head -c 2 -- "$resolved" 2>/dev/null || true)
  if [ "$head2" = "#!" ]; then
    die_refuse producer-is-a-script "$resolved" \
      "AGENTS.md: the normal build's producer is a C compiler, not a program" \
      "that calls one. $tok on PATH is a script, first line:" \
      "  $(head -1 -- "$resolved" | cut -c1-60)" \
      "A script named like a compiler is the exact shape of the uncovered" \
      "vector: it can invoke nasm and return the compiler's exit code, and the" \
      "object it leaves behind is indistinguishable from a real one." \
      "remedy: remove it from PATH, or set NG_PRODUCER to the compiler's" \
      "absolute path. This refusal is deliberately over-broad: it also refuses" \
      "a ccache-style wrapper, which is a real cost and the safe direction."
  fi
  PRODUCER_RESOLVED=$resolved
  PRODUCER_DIGEST=$(digest "$resolved")
  local pin="$OUTDIR/producer.pin"
  if [ -f "$pin" ]; then
    PRODUCER_PIN=$(cut -d' ' -f1 <"$pin")
    if [ "$PRODUCER_PIN" != "$PRODUCER_DIGEST" ]; then
      echo "NTBUILD_PRODUCER_CHANGED path=$resolved" \
           "was=$PRODUCER_PIN now=$PRODUCER_DIGEST" >&2
    fi
  fi
  mkdir -p "$OUTDIR"
  printf '%s  %s\n' "$PRODUCER_DIGEST" "$resolved" >"$pin"
  echo "NTBUILD_PRODUCER path=$resolved sha256=$PRODUCER_DIGEST is_assembler=no is_script=no"
}

# Inline assembly in a granted C source. AGENTS.md allows no GAS, no MASM and
# no inline assembly anywhere, and an asm block inside a granted .c is the one
# remaining way to get assembler bytes into the product through a source the
# policy already permits. Wave 8 recorded this vector as uncovered.
#
# Two things make this correct in BOTH directions, and both were wrong in the
# first version of it. A plain regex over the raw text refused a source whose
# only assembly was the characters asm( inside a string literal - a false
# refusal, which is the same defect class as A10's false refusal in wave 8 -
# and it accepted `asm volatile ("hlt")`, because it required the paren
# immediately after the keyword and missed the attribute. So the text is first
# normalised: comments and string and character literals are removed, and only
# what is left of the language is scanned.
#
# The scan reports how many files it read, so "scanned 34 and found nothing" is
# distinguishable from "scanned nothing" - the ambiguity that hid a dead check
# for a whole wave in this project.
INLINE_ASM_RE='(^|[^[:alnum:]_])(__asm__|__asm|asm)([[:space:]]+[A-Za-z_][A-Za-z_0-9]*)*[[:space:]]*\('

# Emit the C source with comments and literals blanked out. This is not a C
# parser and does not need to be: it only has to stop the scan from being
# fooled by text that is not code.
strip_c_noise() {
  awk '
    { line = $0; out = ""; i = 1; n = length(line)
      if (inblock) {
        j = index(line, "*/")
        if (j == 0) next
        i = j + 2; inblock = 0
      }
      while (i <= n) {
        two = substr(line, i, 2); c = substr(line, i, 1)
        if (two == "//") break
        if (two == "/*") {
          inblock = 1
          j = index(substr(line, i + 2), "*/")
          if (j == 0) { i = n + 1 } else { i = i + 2 + j + 1 }
          inblock = 0
          continue
        }
        if (c == "\"" || c == "\047") {
          q = c; i++
          while (i <= n) {
            ch = substr(line, i, 1)
            if (ch == "\\") { i += 2; continue }
            i++
            if (ch == q) break
          }
          out = out " "; continue
        }
        out = out c; i++
      }
      print out }
  ' "$1"
}

check_no_inline_asm() {
  local -a files=("$@")
  local scanned=0 hits=0 f line
  for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    scanned=$((scanned + 1))
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      hits=$((hits + 1))
      refuse_block inline-asm-source "${f#"$REPO"/}" \
        "AGENTS.md, Purete des sources: no GAS, no MASM and no inline assembly." \
        "This granted C source carries an inline assembly block, which is the" \
        "last way assembler bytes reach the product through a permitted input." \
        "at ${line%%:*}" \
        "remedy: express the instruction as C, or move the producer to NTASM."
      return 1
    done < <(strip_c_noise "$f" | grep -nE "$INLINE_ASM_RE" || true)
  done
  echo "NTBUILD_INLINE_ASM_SCAN sources=$scanned hits=$hits"
  return 0
}

# Where the build may put things. Everything it produces is a build output.
check_output_dir() {
  local abs
  abs=$(realpath -m "$OBJDIR")
  case "$abs" in
    "$REPO"/out/*) ;;
    *)
      die_refuse output-outside-out "$OBJDIR" \
        "out/ is the only place a build may write. AGENTS.md keeps binaries and" \
        "evidence there and nowhere else, and this build takes no instruction" \
        "to write into the source tree or a temporary directory." \
        "remedy: unset NG_OBJDIR, or point it at a directory under out/."
      ;;
  esac
}

# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

cmd_policy() {
  echo "$POLICY_TAG"
  echo "producer: ${CC_BIN} (refused if it is an assembler: ${FORBIDDEN_PRODUCERS[*]})"
  echo "refusal exit code: $REFUSE_EXIT"
  echo "granted tree:"
  for t in "${QUARANTINE_TREES[@]}"; do
    if [ -z "${t#*|}" ]; then
      printf '  %s  grant=(none: unconditional refusal)\n' "${t%%|*}"
    else
      printf '  %s  grant=%s\n' "${t%%|*}" "${t#*|}"
    fi
  done
  echo "granted translation units: ${#GRANTED_TUS[@]}"
  local t
  for t in "${GRANTED_TUS[@]}"; do echo "  $t"; done
  echo "pinned granted inputs: ${#PINNED_INPUTS[@]} rows in PINNED_INPUTS (path|sha256)"
  echo "  the grant is NAME-based; these are the BYTES those names must still hold."
  echo "  a legitimate change to a granted input means editing its pin, exactly as"
  echo "  you would edit RECORDED_EXAMPLES. 'ntbuild.sh pins' prints the rows."
  echo "  'ntbuild.sh pins --verify' checks them and names the file that differs."
  echo "refused classes:"
  echo "  quarantine-nasm-input     any path under legacy/nasm/"
  echo "  assembly-input            .asm .ASM .nasm .NASM .s .S .sx"
  echo "  outside-repo              a path that resolves outside the repository"
  echo "  nonexistent-input         a path that is not a regular file"
  echo "  not-a-c-source            an existing file that is not .c or .h"
  echo "  ungranted-quarantine-source  under bootstrap/quarantine/, not granted"
  echo "  not-granted               inside the repository, not granted"
  echo "  forbidden-producer        the selected compiler is an assembler"
  echo "  unresolvable-producer     the selected compiler is not on PATH"
  echo "  producer-is-a-script      the compiler on PATH is a wrapper script"
  echo "  inline-asm-source         a granted C source carries inline assembly"
  echo "  output-outside-out        an output directory outside out/"
  echo "  granted-input-digest      a granted input's bytes differ from its pin"
  echo "  unpinned-granted-input    a granted input no row of PINNED_INPUTS names"
  echo "  stale-input-pin           a row of PINNED_INPUTS the grant does not read"
  echo "  empty-grant               no granted input resolved; a check that checked"
  echo "                            nothing is not a pass"
  echo "product binary: ${BINARY#"$REPO"/}"
  echo "outputs are build outputs: no gate, source or release artefact may read them"
}

# The pinned corpus, printed for whoever consumes it: name|sources|digest, where
# `sources` is '+'-joined. The pins and the source lists live here and nowhere
# else: ntselfhost.sh reads this output rather than carrying a second copy of
# the same rows, because two copies of a fact held together by a comment is one
# copy waiting to drift. The same is true of the split, which ntselfhost.sh does
# not do: it receives the three fields already separated.
cmd_corpus() {
  local pair name srcs want
  for pair in "${RECORDED_EXAMPLES[@]}"; do
    corpus_row "$pair" name srcs want
    printf '%s|%s|%s\n' "$name" "$srcs" "$want"
  done
}

# The census. Two equalities, and both are load-bearing -- see the paragraph
# above CORPUS_DIRS for why a floor could not do this job.
#
# Prints one line per file, `path|pinned|excluded`, then a summary banner whose
# counts a reader can check against `ntbuild.sh corpus` and `ls` by hand. The
# banner is on stdout so a caller can grep it; the FAIL lines are on stderr, and
# a green banner with a red file list is not a state this function can produce.
cmd_census() {
  local pair name srcs want p f
  local -A pinned=() excluded=()
  local -a files=() d parts

  # Direction 1 inputs: what the pin claims, and what the exclusions claim.
  for pair in "${RECORDED_EXAMPLES[@]}"; do
    corpus_row "$pair" name srcs want
    parts=()
    IFS=+ read -r -a parts <<<"$srcs"
    for p in "${parts[@]}"; do pinned["$p"]=$name; done
  done
  for pair in "${CORPUS_EXCLUSIONS[@]}"; do
    p=${pair%%|*}
    excluded["$p"]=1
  done

  # Enumerate what is actually there. Sorted so two runs print the same order.
  for d in "${CORPUS_DIRS[@]}"; do
    [ -d "$REPO/$d" ] || continue
    while IFS= read -r f; do files+=("$d/$f"); done \
      < <(cd "$REPO" && ls -1 "$d" | LC_ALL=C sort)
  done

  local bad=0 np=0 nx=0
  for p in "${files[@]}"; do
    f=""
    [ -n "${pinned[$p]:-}" ] && f="pinned:${pinned[$p]}"
    if [ -n "${excluded[$p]:-}" ]; then
      f="${f:+$f,}excluded"
      nx=$((nx + 1))
    elif [ -n "$f" ]; then
      np=$((np + 1))
    else
      printf 'FAIL unpinned-nor-excluded %s\n' "$p" >&2
      bad=1
      continue
    fi
    printf '%s|%s\n' "$p" "$f"
  done
  # Direction 2: an exclusion naming a file that is gone is a stale claim.
  for p in "${!excluded[@]}"; do
    if [ ! -f "$REPO/$p" ]; then
      printf 'FAIL exclusion-names-absent-file %s\n' "$p" >&2
      bad=1
    fi
  done
  # Direction 3: a pin naming a file that is gone. The selftest would catch
  # this as a failed assemble, but the message would be about the tool, not
  # about the pin, so it is named here where the reader is looking.
  for p in "${!pinned[@]}"; do
    if [ ! -f "$REPO/$p" ]; then
      printf 'FAIL pin-names-absent-file %s\n' "$p" >&2
      bad=1
    fi
  done
  printf 'NTBUILD_CORPUS_CENSUS pinned=%d excluded=%d files=%d bad=%d\n' \
    "$np" "$nx" "${#files[@]}" "$bad"
  return "$bad"
}

# The pinned granted-input digests, printed the way `corpus` prints the corpus:
# one row per file, path|digest. This is a RENDERING of PINNED_INPUTS, not a
# second copy of it, and it exists for one reason - the remedy the refusal
# prints. A legitimate change to a granted input is a one-line edit to the
# array, and this is what you paste into it.
#
# With --verify it does the other half: it runs the check and prints a line per
# file, so a reader can see WHICH file is wrong rather than being told a count.
cmd_pins() {
  local verify=0 a p want got ok=0 bad=0
  for a in "$@"; do [ "$a" = "--verify" ] && verify=1; done
  if [ "$verify" -eq 0 ]; then
    printf '%s\n' "${PINNED_INPUTS[@]}"
    return 0
  fi
  compute_header_closure
  while IFS= read -r p; do
    if ! want=$(pin_digest "$p"); then
      printf '  NOPIN  %s\n' "$p"; bad=$((bad + 1)); continue
    fi
    got=$(digest "$REPO/$p")
    if [ "$got" = "$want" ]; then
      printf '  ok     %s\n' "$p"; ok=$((ok + 1))
    else
      printf '  DIFFERS %s\n     pinned %s\n     actual %s\n' "$p" "$want" "$got"
      bad=$((bad + 1))
    fi
  done < <(granted_input_paths)
  echo "NTBUILD_PINS_VERIFY ok=$ok bad=$bad rows=${#PINNED_INPUTS[@]}"
  [ "$bad" -eq 0 ]
}

cmd_check() {
  compute_header_closure
  local refused=0 total=0 p
  for p in "$@"; do
    total=$((total + 1))
    if classify "$p"; then
      printf 'NTBUILD_ALLOWED class=allowed input=%s\n' "$p"
    else
      refuse_block "$CLASS" "$p" "${WHY[@]}"
      refused=$((refused + 1))
    fi
  done
  echo "NTBUILD_CHECK inputs=$total refused=$refused policy=$POLICY_TAG"
  [ "$refused" -eq 0 ] || exit "$REFUSE_EXIT"
}

input_manifest() {
  local t h
  # The record is not only the sources. It is also the producer and the flags,
  # because a build at a different optimisation level is a different build: a
  # manifest that ignored them let `NG_OPT=-O0 build` report UP_TO_DATE over a
  # -O2 binary and print flags=-O0 in a log describing -O2 bytes. Measured,
  # not assumed; see the fixed-point check, which needs the level to take.
  echo "producer $CC_BIN ${PRODUCER_DIGEST:-unknown} flags -std=c11 $OPT"
  for t in "${GRANTED_TUS[@]}"; do
    printf '%s  %s\n' "$(digest "$REPO/$t")" "$t"
  done
  for h in "${HEADER_CLOSURE[@]}"; do
    printf '%s  %s\n' "$(digest "$REPO/$h")" "$h"
  done
}

digest() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

cmd_build() {
  check_producer
  check_producer_identity
  check_output_dir
  compute_header_closure

  # Every declared input goes through the policy, in both roles: as a build
  # input of this build, and as a candidate anyone might want to add.
  local p
  for p in "${GRANTED_TUS[@]}"; do
    if ! classify "$p"; then
      refuse_block "$CLASS" "$p" "${WHY[@]}"
      echo "The grant list and the policy disagree; that is a defect in this" \
           "script, not a permitted input." >&2
      exit "$REFUSE_EXIT"
    fi
  done

  # The grant says which NAMES may be read. This says which BYTES those names
  # must still hold, and it runs before a single file is compiled: a hard link
  # planted at a granted name passes every rule in classify() and is refused
  # here instead, on content, before gcc is handed anything.
  check_granted_input_digests

  local extra=${NG_EXTRA_SRC:-}
  if [ -n "$extra" ]; then
    if classify "$extra"; then
      echo "NTBUILD_EXTRA_ALLOWED input=$extra"
    else
      refuse_block "$CLASS" "$extra" "${WHY[@]}"
      exit "$REFUSE_EXIT"
    fi
  fi

  # Inline assembly is checked over the exact set of files that will be read,
  # the granted units and the header closure, not over a glob of the tree.
  local -a scanned=()
  for p in "${GRANTED_TUS[@]}"; do scanned+=("$REPO/$p"); done
  for p in "${HEADER_CLOSURE[@]}"; do scanned+=("$REPO/$p"); done
  check_no_inline_asm "${scanned[@]}" ||
    die_refuse inline-asm-source "${GRANTED_TUS[*]}" \
      "A granted C source carries inline assembly; see the report above."

  mkdir -p "$OUTDIR" "$OBJDIR"

  # Incremental on a content manifest, not on timestamps: a change to a header
  # must rebuild what includes it, and a touch must not.
  local manifest current=""
  manifest=$(input_manifest)
  if [ -f "$INPUTS_RECORD" ]; then current=$(cat "$INPUTS_RECORD"); fi
  if [ "$manifest" != "$current" ]; then
    echo "NTBUILD_INPUTS_CHANGED units=${#GRANTED_TUS[@]} headers=${#HEADER_CLOSURE[@]}"
  fi
  if [ -x "$BINARY" ] && [ "$manifest" = "$current" ]; then
    echo "NTBUILD_UP_TO_DATE binary=$BINARY"
  else
    local t o
    for t in "${GRANTED_TUS[@]}"; do
      o="$OBJDIR/$(basename "$t" .c).o"
      echo "  CC $t"
      "$CC_BIN" -std=c11 "$OPT" -I"$REPO/compiler/c" -c "$REPO/$t" -o "$o"
    done
    echo "  LD $BINARY"
    "$CC_BIN" -std=c11 "$OPT" -I"$REPO/compiler/c" \
      "$OBJDIR"/*.o -o "$BINARY"
  fi
  printf '%s\n' "$manifest" >"$INPUTS_RECORD"

  # The binary must say what it is. A build that produced a tool which will not
  # name its own provenance has not finished.
  local version
  version=$("$BINARY" --version)
  case "$version" in
    *"provenance=BOOTSTRAP_EXTERNAL_C"*) ;;
    *)
      die_refuse unprovenanced-binary "$BINARY" \
        "The linked binary does not report provenance=BOOTSTRAP_EXTERNAL_C." \
        "It printed: $version" \
        "A build output that cannot name its own producer is not an artefact"
      ;;
  esac
  local binary_digest
  binary_digest=$(digest "$BINARY")

  # The fixed-point check. It runs here, in the build, so that it is not
  # something a person has to remember, and it is what decides whether this
  # build is a build. The check rebuilds the producer twice from clean, so it
  # destroys and recreates out/c-bootstrap/ntasm; the digest asserted above is
  # therefore re-asserted afterwards, and a producer that does not rebuild to
  # the same bytes fails the build rather than quietly leaving a different
  # binary behind a build log that describes the first one.
  local depth=${NG_SELFHOST_DEPTH:-0}
  local selfhost=skipped
  if [ "$depth" -eq 0 ]; then
    local restore
    if ! restore=$("$SELF" selfhost --expect-producer "$binary_digest" \
                     --restore-opt "$OPT" 2>&1); then
      printf '%s\n' "$restore" >&2
      die_refuse selfhost-failed "${BINARY#"$REPO"/}" \
        "The fixed-point check failed; the artefact above names the digests" \
        "that did not agree. A build whose producer cannot be shown to emit" \
        "these bytes twice from clean is not a reproducible build."
    fi
    printf '%s\n' "$restore"
    selfhost=$(printf '%s\n' "$restore" | sed -n 's/^NTSELFHOST_COMPARE //p')
    if [ "$(digest "$BINARY")" != "$binary_digest" ]; then
      die_refuse selfhost-restore-mismatch "$BINARY" \
        "The fixed-point check rebuilt the producer from clean and the binary" \
        "it left is not the one this build linked." \
        "before: $binary_digest" \
        "after:  $(digest "$BINARY")" \
        "The build log describes a binary that is no longer on disk."
    fi
    echo "NTBUILD_SELFHOST_RESTORE sha256=$binary_digest verified=yes"
  else
    echo "NTBUILD_SELFHOST_DEPTH depth=$depth (this build is a child of the fixed-point check)"
  fi
  {
    echo "NTBUILD_OK policy=$POLICY_TAG"
    echo "producer=$CC_BIN flags=-std=c11 $OPT"
    echo "binary=${BINARY#"$REPO"/}"
    echo "bytes=$(wc -c <"$BINARY" | tr -d ' ')"
    echo "sha256=$binary_digest"
    echo "provenance=BOOTSTRAP_EXTERNAL_C"
    echo "version=$version"
    echo "producer_sha256=${PRODUCER_DIGEST:-none} producer_path=${PRODUCER_RESOLVED:-none}"
    echo "selfhost=$selfhost depth=$depth"
    echo "input_units=${#GRANTED_TUS[@]} input_headers=${#HEADER_CLOSURE[@]}"
  } | tee "$OUTDIR/build.log"
}

cmd_clean() {
  rm -rf "$OUTDIR"
  echo "NTBUILD_CLEAN removed ${OUTDIR#"$REPO"/}"
}

# --------------------------------------------------------------------------
# The refusal suite. Every case drives this script as a subprocess and reads
# its exit code and its stderr, so a case can fail if the policy stops being
# enforced. The expectations are the classes and the messages, both of which are
# declared once, above; the interesting half is the seven examples, whose bytes
# come from the binary this build just linked.
# --------------------------------------------------------------------------
selftest_fail=0
selftest_pass=0

# Run this script against a COPY of the tree, reached through NG_REPO. The cwd
# matters and is not incidental: classify() resolves a relative candidate path
# against the cwd, so a build of a shadow tree has to be run FROM that tree or
# every relative path resolves back into the real one and the case measures
# nothing. Depth 1 because the shadow carries the sources and not the corpus -
# the fixed-point check is about the producer, and has its own case.
in_shadow() { # in_shadow <shadow-repo> <command...>
  local shadow=$1; shift
  (
    cd "$shadow" || exit 1
    NG_REPO="$shadow" NG_SELFHOST_DEPTH=1 NG_OBJDIR="$shadow/out/obj" \
      exec "$SELF" "$@"
  )
}

expect() { # expect <wanted-exit> <label> <substring-or-empty> <command...>
  local want=$1 label=$2 needle=$3
  shift 3
  local out rc
  set +e
  out=$("$@" 2>&1)
  rc=$?
  set -e
  local bad=""
  [ "$rc" = "$want" ] || bad="exit $rc, wanted $want"
  if [ -n "$needle" ]; then
    case "$out" in
      *"$needle"*) ;;
      *) bad="$bad; message did not name '$needle'" ;;
    esac
  fi
  if [ -z "$bad" ]; then
    selftest_pass=$((selftest_pass + 1))
    printf '  ok    %-42s exit=%s\n' "$label" "$rc"
  else
    selftest_fail=$((selftest_fail + 1))
    printf '  FAIL  %-42s %s\n' "$label" "$bad"
    printf '%s\n' "$out" | sed -n '1,6p' | sed 's/^/          /'
  fi
}

# expect, for an output whose literal text is NOT the property. A literal copied
# out of a producer's output freezes the day it was copied: it goes red the day
# the producer grows, which says nothing about the property, and as a substring
# it can match a line that does not carry the property at all. So the output is
# handed to a JUDGE, a function of this file that names what it found wrong.
# The judge runs in THIS shell - no subshell, no pipe - so neither `set -e` nor
# a SIGPIPE can decide for it; it appends one reason per defect to SHAPE_BAD and
# records the lines it read in SHAPE_SEEN, which are printed on both outcomes so
# a green line shows what it was green ON.
SHAPE_BAD=""
SHAPE_SEEN=""
expect_shape() { # expect_shape <wanted-exit> <label> <judge> <command...>
  local want=$1 label=$2 judge=$3
  shift 3
  local out rc
  set +e
  out=$("$@" 2>&1)
  rc=$?
  set -e
  SHAPE_BAD=""
  SHAPE_SEEN=""
  "$judge" "$out"
  local bad=""
  [ "$rc" = "$want" ] || bad="exit $rc, wanted $want"
  [ -z "$SHAPE_BAD" ] || bad="${bad:+$bad; }${SHAPE_BAD#; }"
  if [ -z "$bad" ]; then
    selftest_pass=$((selftest_pass + 1))
    printf '  ok    %-42s exit=%s\n' "$label" "$rc"
  else
    selftest_fail=$((selftest_fail + 1))
    printf '  FAIL  %-42s %s\n' "$label" "$bad"
  fi
  printf '%s' "$SHAPE_SEEN" | sed 's/^/          read: /'
}

# The judge for `ntselfhost.sh --selftest`. The property is that the
# fixed-point check has been SEEN to go red: case E perturbs one real pin and
# runs the whole check, and its line says the check exited 1. The selftest
# publishes two lines for that, and the judge reads both, by their shape:
#   NTSELFHOST_SELFTEST_DONE pass=P fail=F executed=X declared=D partial=Q
#   "  ok    E <label> exit=1"
# It wants fail=0, partial=no, and P = X = D - every declared case ran and
# passed - AND case E present exactly once, passed, at exit=1. The count alone
# does not carry the proof any more: a selftest that dropped case E and lowered
# its declared count, or that flipped E's expectation to exit 0, still prints
# fail=0 with X = D. Only E's own line can say E ran and the check went red.
selfhost_selftest_shape() { # selfhost_selftest_shape <output>
  local line done_line="" e_line="" n_done=0 n_e=0
  while IFS= read -r line; do
    case "$line" in
      "NTSELFHOST_SELFTEST_DONE "*) done_line=$line; n_done=$((n_done + 1)) ;;
      "  ok    E "*|"  FAIL  E "*) e_line=$line; n_e=$((n_e + 1)) ;;
    esac
  done <<<"$1"
  [ -z "$done_line" ] || SHAPE_SEEN+="$done_line"$'\n'
  [ -z "$e_line" ] || SHAPE_SEEN+="$e_line"$'\n'
  local re='^NTSELFHOST_SELFTEST_DONE pass=([0-9]+) fail=([0-9]+) executed=([0-9]+) declared=([0-9]+) partial=([a-z]+)$'
  if [ "$n_done" -ne 1 ]; then
    SHAPE_BAD+="; $n_done NTSELFHOST_SELFTEST_DONE lines, wanted 1"
  elif ! [[ $done_line =~ $re ]]; then
    SHAPE_BAD+="; the DONE line is not pass= fail= executed= declared= partial="
  else
    local p=${BASH_REMATCH[1]} f=${BASH_REMATCH[2]} x=${BASH_REMATCH[3]}
    local d=${BASH_REMATCH[4]} q=${BASH_REMATCH[5]}
    [ "$f" -eq 0 ] || SHAPE_BAD+="; fail=$f"
    [ "$q" = no ] || SHAPE_BAD+="; partial=$q, a subset ran and no full selftest is claimed"
    [ "$x" -eq "$d" ] || SHAPE_BAD+="; executed=$x of declared=$d"
    [ "$p" -eq "$d" ] || SHAPE_BAD+="; pass=$p of declared=$d"
  fi
  if [ "$n_e" -eq 0 ]; then
    SHAPE_BAD+="; case E, the perturbed pin, is not in the output"
  elif [ "$n_e" -ne 1 ]; then
    SHAPE_BAD+="; case E printed $n_e times"
  elif ! [[ $e_line =~ ^"  ok    E ".*" exit=1"$ ]]; then
    SHAPE_BAD+="; case E did not pass at exit=1, so the perturbed check was not seen red"
  fi
  return 0
}

cmd_selftest() {
  compute_header_closure
  echo "NTBUILD_SELFTEST policy=$POLICY_TAG refused_if="
  echo "  the normal build is asked for NASM, or for a quarantined input, or is"
  echo "  pointed at a path outside out/"

  echo "refused:"
  expect "$REFUSE_EXIT" "quarantine NASM source" \
    "class=quarantine-nasm-input" \
    "$SELF" check legacy/nasm/ntasm-bootstrap.asm
  expect "$REFUSE_EXIT" "quarantine NASM probe" \
    "class=quarantine-nasm-input" \
    "$SELF" check legacy/nasm/nova-compute-cpu-r0-r1.asm
  expect "$REFUSE_EXIT" "assembly input (.asm), absent" \
    "class=assembly-input" \
    "$SELF" check docs/boot.asm
  expect "$REFUSE_EXIT" "assembly input (.S), absent" \
    "class=assembly-input" \
    "$SELF" check spec/never-written.S
  expect "$REFUSE_EXIT" "ungranted quarantined C source" \
    "class=ungranted-quarantine-source" \
    "$SELF" check tests/c/nova/tests_ntasm_cli.c
  expect "$REFUSE_EXIT" "ungranted quarantined C source, top level" \
    "class=ungranted-quarantine-source" \
    "$SELF" check tests/c/ntasm/tests.c
  expect "$REFUSE_EXIT" "C source in the tree, never granted" \
    "class=not-granted" \
    "$SELF" check verifieur/deepseek-call-arity-20260913/tests_ntasm_refs.c
  expect "$REFUSE_EXIT" "source outside the repository" \
    "class=outside-repo" \
    "$SELF" check ../AGENTS.md
  expect "$REFUSE_EXIT" "source that does not exist" \
    "class=nonexistent-input" \
    "$SELF" check compiler/c/no-such-translation-unit.c
  expect "$REFUSE_EXIT" "not a C source" \
    "class=not-a-c-source" \
    "$SELF" check spec/ntasm/ntasm.md
  expect "$REFUSE_EXIT" "producer is NASM" \
    "class=forbidden-producer" \
    env NG_PRODUCER=nasm "$SELF" build
  expect "$REFUSE_EXIT" "extra source is the NASM root" \
    "class=quarantine-nasm-input" \
    env NG_EXTRA_SRC=legacy/nasm/ntasm-bootstrap.asm "$SELF" build
  expect "$REFUSE_EXIT" "extra source is ungranted quarantine" \
    "class=ungranted-quarantine-source" \
    env NG_EXTRA_SRC=tests/c/ntasm/tests.c "$SELF" build
  expect "$REFUSE_EXIT" "output directory outside out/" \
    "class=output-outside-out" \
    env NG_OBJDIR=/tmp/ntbuild-escape "$SELF" build

  # The granted input is granted BY NAME, and a name is not a byte count. This
  # case is the measured hole: a hard link planted at a granted name is not
  # refused, and the substituted bytes reach the compiler. The perturbation is
  # done on a COPY of the tree, reached through NG_REPO, so the tree this
  # repository ships is never the thing being tested - and a shadow whose
  # perturbation failed to take would let the real numbers print and look like
  # a pass, so every case here ASSERTS THE PERTURBATION before running a build.
  #
  # Two substitutions, because the finding was not NASM-specific: the NASM
  # source, and an ordinary UNGRANTED C file that is refused on its own. A check
  # that covered only the first would still let the second compile.
  #
  # NG_SELFHOST_DEPTH=1 because the shadow carries the sources and not the
  # corpus: the fixed-point check is about the PRODUCER and is exercised by its
  # own case below. What is under test here is the pin, which runs long before.
  local shadow="$OUTDIR/selftest-shadow"
  local victim="$shadow/compiler/c/nova/frontend/nova.c"
  local realvictim="$REPO/compiler/c/nova/frontend/nova.c"
  rm -rf "$shadow"
  mkdir -p "$shadow/compiler" "$shadow/legacy" "$shadow/tests" "$shadow/out"
  cp -a "$REPO/tests/c" "$shadow/tests/c"
  cp -al "$REPO/compiler/c" "$shadow/compiler/c" 2>/dev/null ||
    cp -a "$REPO/compiler/c" "$shadow/compiler/c"
  cp -al "$REPO/legacy/nasm" "$shadow/legacy/nasm" 2>/dev/null ||
    cp -a "$REPO/legacy/nasm" "$shadow/legacy/nasm"
  # An ungranted C file, one this policy already refuses on its own terms.
  local ungranted=""
  for u in tests/c/nova/tests_pe_oracle.c \
           tests/c/ntasm/tests.c \
           tests/c/ntasm/build_witness.c; do
    [ -f "$REPO/$u" ] && { ungranted=$u; break; }
  done
  if [ -z "$ungranted" ]; then
    selftest_fail=$((selftest_fail + 1))
    printf '  FAIL  %-42s no ungranted C file to plant\n' "pin substitution"
  else
    cp -a "$REPO/$ungranted" "$shadow/compiler/c/planted_ungranted.c"
    local plant
    for plant in legacy/nasm/ntasm-bootstrap.asm \
                  compiler/c/planted_ungranted.c; do
      rm -f "$victim"
      ln "$shadow/$plant" "$victim" 2>/dev/null || cp -a "$shadow/$plant" "$victim"
      local want_inode got_inode links want_digest got_digest
      want_inode=$(stat -c %i "$shadow/$plant"); got_inode=$(stat -c %i "$victim")
      links=$(stat -c %h "$victim")
      want_digest=$(digest "$shadow/$plant"); got_digest=$(digest "$victim")
      if [ "$want_inode" != "$got_inode" ] || [ "$links" -lt 2 ] ||
         [ "$want_digest" != "$got_digest" ]; then
        selftest_fail=$((selftest_fail + 1))
        printf '  FAIL  %-42s the perturbation did not take\n' "planted $plant"
        printf '          inode want=%s got=%s links=%s\n' "$want_inode" "$got_inode" "$links"
        printf '          digest want=%s got=%s\n' "$want_digest" "$got_digest"
        continue
      fi
      printf '  ok    %-42s inode=%s links=%s\n' "planted $plant" "$got_inode" "$links"
      selftest_pass=$((selftest_pass + 1))
      expect "$REFUSE_EXIT" "granted name hard-linked to $plant" \
        "class=granted-input-digest" \
        in_shadow "$shadow" build
    done
  fi
  # The control that MUST pass, and it is the one no rule list gets for free:
  # the SAME shadow, with the substitution removed, must still build. A check
  # that refuses everything is not a check, and this is the case that says so.
  rm -f "$victim"; ln "$realvictim" "$victim"
  expect 0 "same shadow, substitution removed" "NTBUILD_INPUTS_PINNED" \
    in_shadow "$shadow" build
  # And the pins still match the real tree, which is the direction that says the
  # refusals above were about the planted bytes and nothing else.
  expect 0 "pinned granted-input digests match" \
    "NTBUILD_PINS_VERIFY ok=${#PINNED_INPUTS[@]} bad=0" \
    "$SELF" pins --verify
  rm -rf "$shadow"

  # The fixed-point check must be shown to go red, not only to go green, and the
  # proof is asked for here so it is exercised on every selftest.
  # `ntselfhost.sh --selftest` exits 0 when its cases behave AS EXPECTED -
  # including the end-to-end one, which must come back non-zero - so the exit
  # code alone does not carry the proof. Asserting exit 1 here would be
  # asserting that the selftest is broken.
  # This used to be the literal "NTSELFHOST_SELFTEST_DONE pass=5 fail=0", from
  # when the selftest had five cases; it went red at nineteen without anything
  # being wrong. Measured on 7 October 2026, it was also open the other way: as
  # a substring it matched "pass=5 fail=0 executed=5 declared=19 partial=yes",
  # printed at exit 0 by NG_SELFHOST_ST_CASES="A B C D F", a run in which case
  # E never executed. The judge reads the shape instead; see
  # selfhost_selftest_shape.
  expect_shape 0 "self-host check goes red on a perturbed pin" \
    selfhost_selftest_shape \
    "$SELF" selfhost --selftest

  # The wrapper vector, in the shape the attack actually takes. nasm is
  # installed on this host and this script really would be executed, so the
  # case is not hypothetical: a build that accepted it would hand its .c files
  # to NASM and get a valid object back with nothing to tell the difference.
  local fake="$OUTDIR/selftest-fakebin"
  rm -rf "$fake"; mkdir -p "$fake"
  printf '%s\n' '#!/usr/bin/env bash' \
    '# a wrapper named like the compiler, calling the forbidden producer' \
    'exec /usr/bin/nasm -f elf64 "$@"' >"$fake/gcc"
  chmod +x "$fake/gcc"
  expect "$REFUSE_EXIT" "compiler wrapper script that calls nasm" \
    "class=producer-is-a-script" \
    env "PATH=$fake:$PATH" NG_PRODUCER=gcc "$SELF" build
  expect "$REFUSE_EXIT" "producer that is not on PATH at all" \
    "class=unresolvable-producer" \
    env NG_PRODUCER=definitely-not-installed-9f3a "$SELF" build
  rm -rf "$fake"

  # Inline assembly, driven through the same function the build uses, over a
  # real file, in both directions. The file lives under out/ because the grant
  # list is closed: a test may not add itself to the build it is testing.
  local probe="$OUTDIR/selftest-inline"
  rm -rf "$probe"; mkdir -p "$probe"
  printf '%s\n' 'int f(void){ return 1; }' >"$probe/clean.c"
  printf '%s\n' 'int f(void){ __asm__("nop"); return 1; }' >"$probe/asm.c"
  printf '%s\n' 'int g(void){ asm volatile ("hlt"); return 0; }' >"$probe/short.c"
  printf '%s\n' 'static const char *s = "asm(" ;' >"$probe/string.c"
  if check_no_inline_asm "$probe/clean.c" "$probe/string.c" >/dev/null 2>&1; then
    selftest_pass=$((selftest_pass + 1))
    printf '  ok    %-42s no inline assembly\n' "clean C and a string are allowed"
  else
    selftest_fail=$((selftest_fail + 1))
    printf '  FAIL  %-42s refused a source with no assembly\n' "clean C"
  fi
  local p
  for p in asm short; do
    if check_no_inline_asm "$probe/$p.c" >/dev/null 2>&1; then
      selftest_fail=$((selftest_fail + 1))
      printf '  FAIL  %-42s accepted inline assembly\n' "inline asm in $p.c"
    else
      selftest_pass=$((selftest_pass + 1))
      printf '  ok    %-42s refused\n' "inline asm in $p.c"
    fi
  done
  rm -rf "$probe"

  echo "allowed:"
  expect 0 "granted translation unit" "" \
    "$SELF" check compiler/c/ntasm/cli/cli.c
  expect 0 "granted translation unit in nova/" "" \
    "$SELF" check compiler/c/nova/runtime/runtime_v2.c
  expect 0 "granted header" "" \
    "$SELF" check compiler/c/ntasm/frontend/frontend.h
  expect 0 "the normal build itself" "" "$SELF" build

  # The half that is not a refusal: the binary this build just linked must
  # still emit the seven recorded digests. A refusal that holds while the tool
  # is broken is not a build.
  echo "product:"
  local pair name srcs want got
  local -a argv=()
  for pair in "${RECORDED_EXAMPLES[@]}"; do
    corpus_row "$pair" name srcs want
    corpus_argv "$srcs" "$REPO" argv
    if [ "${#argv[@]}" -eq 0 ]; then
      selftest_fail=$((selftest_fail + 1))
      printf '  FAIL  %-42s names no source at all\n' "example $name"
      continue
    fi
    local tmp="$OUTDIR/obj/selftest-$name.efi"
    set +e
    "$BINARY" assemble "${argv[@]}" -o "$tmp" >/dev/null 2>&1
    local rc=$?
    set -e
    if [ "$rc" != 0 ]; then
      selftest_fail=$((selftest_fail + 1))
      printf '  FAIL  %-42s assemble exit=%s\n' "example $name" "$rc"
      continue
    fi
    got=$(digest "$tmp")
    if [ "$got" = "$want" ]; then
      selftest_pass=$((selftest_pass + 1))
      printf '  ok    %-42s %s\n' "example $name" "${got:0:16}"
    else
      selftest_fail=$((selftest_fail + 1))
      printf '  FAIL  %-42s got %s wanted %s\n' "example $name" "$got" "$want"
    fi
    rm -f "$tmp"
  done

  # The census, and its control. A check that has never been seen to go red is
  # not known to be able to, and this is a check whose entire job is a
  # condition that is currently FALSE on this tree -- so a version of it that
  # cannot fail would look identical to this one for as long as the condition
  # stayed false. The control therefore plants a ninth file, in a SHADOW of the
  # directory, and requires the census to name it.
  #
  # The shadow is used rather than the real directory because the real one is
  # the tree a sibling lot may be editing, and a selftest that creates and
  # deletes a file in examples/ to prove a point is a selftest that can leave a
  # corpus directory one file different from how it found it.
  echo "corpus census:"
  expect 0 "every corpus-directory file is pinned or excluded" \
    "NTBUILD_CORPUS_CENSUS" \
    "$SELF" census

  # The control. A copy of the two corpus directories with one extra .ntasm
  # that is in no pin and in no exclusion is the exact defect this lot is
  # about, and the census must refuse it BY NAME. Run against a shadow repo
  # root so the real tree is untouched.
  local cshadow="$OUTDIR/selftest-census-shadow"
  rm -rf "$cshadow"; mkdir -p "$cshadow"
  local cdir
  for cdir in "${CORPUS_DIRS[@]}"; do
    mkdir -p "$cshadow/$cdir"
    cp "$REPO/$cdir"/*.ntasm "$cshadow/$cdir/" 2>/dev/null || true
  done
  printf 'module expt.ninth\ntarget x86_64-nexora-uefi\nsection .text {\n    export fn main()->u64\n    effects {}\n    clobbers {} {\n        return 7\n    }\n}\n' \
    > "$cshadow/examples/ntasm-v0/c-bootstrap/ninth-file.ntasm"
  expect 1 "a ninth unpinned file is refused, by name" \
    "unpinned-nor-excluded examples/ntasm-v0/c-bootstrap/ninth-file.ntasm" \
    env NG_REPO="$cshadow" "$SELF" census
  # ... and the other direction: the same shadow, with the file removed, must go
  # back to green. A one-way check is a check that only knows how to complain.
  rm -f "$cshadow/examples/ntasm-v0/c-bootstrap/ninth-file.ntasm"
  expect 0 "the same shadow, ninth file removed, is clean again" \
    "NTBUILD_CORPUS_CENSUS" \
    env NG_REPO="$cshadow" "$SELF" census
  # The third direction, because a stale exclusion is a claim about a file that
  # is gone: delete a file the exclusions name and the census must say so.
  rm -f "$cshadow/examples/ntasm-v0/c-bootstrap/call-private-stmt.ntasm"
  expect 1 "an exclusion naming a deleted file is refused" \
    "exclusion-names-absent-file" \
    env NG_REPO="$cshadow" "$SELF" census
  rm -rf "$cshadow"

  # A refusal must leave nothing behind. If the build had been interrupted after
  # linking, a stale binary would still be sitting in out/ and the next run
  # would report it as up to date.
  if [ -e "$OUTDIR/obj/../escape" ]; then
    selftest_fail=$((selftest_fail + 1))
    echo "  FAIL  refused build wrote outside out/"
  fi

  echo "NTBUILD_SELFTEST_DONE pass=$selftest_pass fail=$selftest_fail"
  [ "$selftest_fail" -eq 0 ]
}

usage() {
  sed -n '2,31p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# The fixed-point check lives in its own script because it owns a definition
# and a corpus protocol that are longer than this file should carry. It is
# still part of the build: cmd_build calls it, and this command only lets a
# person run it alone.
cmd_selfhost() { exec "$REPO/scripts/ntselfhost.sh" --build "$SELF" "$@"; }


case "${1:-build}" in
  build)   shift || true; cmd_build "$@" ;;
  check)   shift; cmd_check "$@" ;;
  selftest) shift || true; cmd_selftest "$@" ;;
  corpus)   shift; cmd_corpus "$@" ;;
  census)  shift; cmd_census "$@" ;;
  policy)  shift || true; cmd_policy "$@" ;;
  clean)   shift || true; cmd_clean "$@" ;;
  selfhost) shift || true; cmd_selfhost "$@" ;;
  pins)    shift; cmd_pins "$@" ;;
  -h|--help|help) usage ;;
  *) echo "ntbuild.sh: unknown command '$1'" >&2; usage >&2; exit 2 ;;
esac
