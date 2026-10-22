#!/usr/bin/env bash
# Nexora Genesis - the A8 CANDIDATE house-build entrypoint.
#
# The A8 CANDIDATE route is the HOUSE build: scripts/ntbuild_house.py, which
# reconstructs the producer from pinned Nova sources through the house
# transport. This file is its shell front, and nothing more: it resolves the
# repository from its own path, forwards the command and its flags in argv
# (never in a string a shell would read again), and refuses everything the
# house build does not own.
#
# IT IS NOT THE NORMAL BUILD OF THIS REPOSITORY. The principal build of this
# snapshot is still scripts/ntbuild.sh, the legacy C bootstrap producer. The
# house build becomes the normal build only once the A8 contract is proven;
# until then this file is a CANDIDATE route, and nothing here changes what
# the normal build of this repository is.
#
#   ntbuild_house.sh [build]        the house build (default)
#   ntbuild_house.sh policy         the house policy
#   ntbuild_house.sh check PATH...  classify candidate house sources
#   ntbuild_house.sh pins           the house pins, printed and verified on disk
#   ntbuild_house.sh selftest       the house unit tests
#   ntbuild_house.sh selfhost       the house self-host route
#   ntbuild_house.sh bootstrap ...  the LEGACY C bootstrap producer, explicitly
#   ntbuild_house.sh --help
#
# THE LEGACY COMMANDS ARE NOT REACHABLE BY DEFAULT. corpus, census, clean and
# the C producer itself belong to the legacy script, which this repository
# preserves as scripts/ntbuild.sh (the house stage called the same script
# scripts/ntbuild_bootstrap.sh; the tree it builds was relocated, so the
# paths inside it were adapted). They require an explicit
# `ntbuild_house.sh bootstrap ...`, and there is NO silent fallback in either
# direction: a legacy command asked of this entrypoint is refused, and the
# refusal names the invocation that does it; a missing interpreter or a missing
# house builder is refused too, and never becomes a run of the C bootstrap.
#
# The house builder reads an unknown word as a PATH to build, so this
# entrypoint refuses an unknown command instead of forwarding it: forwarding
# `corpus` would silently start a build.
#
# THE SEED IS EXTERNAL. The pinned seed PE is a PUBLISHED artefact: it is not
# a file of this repository, and it must not be committed. NG_SEED_DIR names
# the directory that holds it, and that directory may be outside the tree.
# The builder's default is the repository path bootstrap/nova-native, and the
# seed's digest is checked against the manifest wherever it is read from.
#
# Exit codes: 0 delivered; 78 refused (this entrypoint's own refusals, and the
# house builder's refusals passed through); anything else is the house
# builder's own failure code.
set -euo pipefail

REFUSE_EXIT=78

# --------------------------------------------------------------------------
# The repository, resolved from this script's own path so the build works from
# any cwd. NG_REPO wins when it is set: shadow trees and tests reach the build
# through it, and it is honoured by being PASSED as --repo, never interpolated
# into a command line.
# --------------------------------------------------------------------------
self=${BASH_SOURCE[0]}
case "$self" in
  */*) ;;
  -*) self="./$self" ;;
  *) self=$(command -v "$self" 2>/dev/null || printf '%s' "$self") ;;
esac
self_dir=${self%/*}
[ "$self_dir" != "$self" ] || self_dir=.
scripts_dir=$(cd -P -- "$self_dir" 2>/dev/null && pwd -P) || scripts_dir=""
if [ -z "$scripts_dir" ]; then
  printf 'ntbuild_house.sh: cannot resolve my own directory (%s)\n' "$self" >&2
  exit "$REFUSE_EXIT"
fi
repo=$(cd -P -- "$scripts_dir/.." 2>/dev/null && pwd -P) || repo=""
if [ -z "$repo" ]; then
  printf 'ntbuild_house.sh: cannot resolve the repository root from %s\n' "$scripts_dir" >&2
  exit "$REFUSE_EXIT"
fi
if [ -n "${NG_REPO:-}" ]; then
  repo=$NG_REPO
  if [ ! -d "$repo" ]; then
    printf 'ntbuild_house.sh: NG_REPO=%s is not a directory\n' "$repo" >&2
    exit "$REFUSE_EXIT"
  fi
fi

# --------------------------------------------------------------------------
# The SEED is a PUBLISHED artefact: it is not a file of this repository, and
# the build reads it from a directory that may be OUTSIDE the tree, the way
# the transport takes its firmware and its images as arguments. NG_SEED_DIR
# names that directory; it is honoured by being PASSED as --seed-dir, never
# interpolated into a command line. Unset, the house builder keeps its own
# default: the repository path bootstrap/nova-native.
# --------------------------------------------------------------------------
seed_dir=""
if [ -n "${NG_SEED_DIR:-}" ]; then
  seed_dir=$NG_SEED_DIR
  if [ ! -d "$seed_dir" ]; then
    printf 'ntbuild_house.sh: NG_SEED_DIR=%s is not a directory\n' "$seed_dir" >&2
    exit "$REFUSE_EXIT"
  fi
fi

house_builder="$scripts_dir/ntbuild_house.py"
# The LEGACY route of this repository is scripts/ntbuild.sh: the reconciled
# C bootstrap producer. The house stage called it scripts/ntbuild_bootstrap.sh;
# in this repository that script IS scripts/ntbuild.sh.
legacy_script="$scripts_dir/ntbuild.sh"
python_bin=${NG_PYTHON:-python3}

# Is there an interpreter to run? A path is checked as a path, a name is
# looked up on PATH. Nothing here is ever expanded by a shell.
have_interpreter() {
  case "$1" in
    */*) [ -f "$1" ] && [ -x "$1" ] ;;
    *) command -v "$1" >/dev/null 2>&1 ;;
  esac
}

# --------------------------------------------------------------------------
# The two routes.
# --------------------------------------------------------------------------

# The house route: one command, its flags forwarded verbatim, the repository
# passed as --repo, and the seed directory passed as --seed-dir when
# NG_SEED_DIR names one. The builder is exec'd, so its exit code IS this
# script's exit code, and there is no second chance to fall back.
run_house() {
  local cmd=$1
  shift
  if [ ! -f "$house_builder" ]; then
    printf 'ntbuild_house.sh: the house builder is missing: %s\n' "$house_builder" >&2
    exit "$REFUSE_EXIT"
  fi
  case "$python_bin" in
    -*)
      printf 'ntbuild_house.sh: NG_PYTHON must be a program name or a path, not an option: %s\n' \
        "$python_bin" >&2
      exit "$REFUSE_EXIT"
      ;;
  esac
  if ! have_interpreter "$python_bin"; then
    printf 'ntbuild_house.sh: no python interpreter (%s) to run the house build.\n' \
      "$python_bin" >&2
    printf 'ntbuild_house.sh: install python3, or set NG_PYTHON to the interpreter to use.\n' >&2
    exit "$REFUSE_EXIT"
  fi
  if [ -n "$seed_dir" ]; then
    exec "$python_bin" "$house_builder" --repo "$repo" --seed-dir "$seed_dir" "$cmd" "$@"
  fi
  exec "$python_bin" "$house_builder" --repo "$repo" "$cmd" "$@"
}

# The legacy route: the preserved C bootstrap script, and only it. It reads
# NG_REPO itself, and its own self-host route (ntselfhost.sh --build SELF)
# still points at the legacy producer, because SELF is the legacy script.
run_legacy() {
  if [ ! -f "$legacy_script" ]; then
    printf 'ntbuild_house.sh: the preserved legacy script is missing: %s\n' "$legacy_script" >&2
    exit "$REFUSE_EXIT"
  fi
  exec "${BASH:-bash}" "$legacy_script" "$@"
}

# --------------------------------------------------------------------------
# The refusals. Every one of them names the invocation that does the thing.
# --------------------------------------------------------------------------

refuse_legacy() {
  local cmd=$1 remedy reason
  case "$cmd" in
    corpus)
      remedy='ntbuild_house.sh bootstrap corpus'
      reason='corpus is a command of the LEGACY C bootstrap script; the house build pins its own Nova sources and has no corpus command.'
      ;;
    census)
      remedy='ntbuild_house.sh bootstrap census'
      reason='census is a command of the LEGACY C bootstrap script; it checks the C corpus directories, which the house build never reads.'
      ;;
    clean)
      remedy='ntbuild_house.sh bootstrap clean'
      reason='clean removes out/c-bootstrap/ntasm in the LEGACY C bootstrap script; the house build removes nothing and writes only into its own fresh run directory.'
      ;;
    *)
      remedy='ntbuild_house.sh bootstrap ...'
      reason='that command belongs to the LEGACY C bootstrap script.'
      ;;
  esac
  printf 'NTBUILD_REFUSED class=legacy-command-requires-bootstrap\n' >&2
  printf '  input:   %s\n' "$cmd" >&2
  printf '  reason:  %s\n' "$reason" >&2
  printf '            This entrypoint never falls back to the legacy script on its own.\n' >&2
  printf '  remedy:  %s\n' "$remedy" >&2
  exit "$REFUSE_EXIT"
}

refuse_unknown() {
  printf 'NTBUILD_REFUSED class=unknown-command\n' >&2
  printf '  input:   %s\n' "$1" >&2
  printf '  reason:  not a command of the house build.\n' >&2
  printf '            The house builder reads an unknown word as a PATH to build,\n' >&2
  printf '            so this entrypoint refuses it instead of forwarding it.\n' >&2
  printf '  remedy:  ntbuild_house.sh --help\n' >&2
  exit "$REFUSE_EXIT"
}

refuse_option() {
  printf 'NTBUILD_REFUSED class=unknown-command\n' >&2
  printf '  input:   %s\n' "$1" >&2
  printf '  reason:  options belong AFTER the command: ntbuild_house.sh <command> [options]\n' >&2
  printf '            --repo, --timeout and --seed-dir are the house builder options; use\n' >&2
  printf '            NG_REPO for the repository, or put --repo after the command.\n' >&2
  printf '  remedy:  ntbuild_house.sh --help\n' >&2
  exit "$REFUSE_EXIT"
}

usage() {
  printf '%s\n' \
'ntbuild_house.sh - the A8 CANDIDATE house-build entrypoint.' \
'' \
'It is NOT the normal build of this repository: the principal build of this' \
'snapshot is still scripts/ntbuild.sh, the legacy C bootstrap producer. The' \
'house build becomes the normal build only once the A8 contract is proven.' \
'' \
'  ntbuild_house.sh [build]        build the producer through the house transport (default)' \
'  ntbuild_house.sh policy         print the house policy' \
'  ntbuild_house.sh check PATH...  classify candidate house sources' \
'  ntbuild_house.sh pins           print the house pins and verify them on disk' \
'  ntbuild_house.sh selftest       run the house unit tests' \
'  ntbuild_house.sh selfhost       the house self-host route (seed -> N1 -> N2)' \
'  ntbuild_house.sh build --seed-dir DIR' \
'                               build with the PUBLISHED seed in DIR' \
'  ntbuild_house.sh bootstrap ...  the LEGACY C bootstrap producer, explicitly' \
'  ntbuild_house.sh --help' \
'' \
'The legacy commands are NOT reachable by default:' \
'  corpus                   -> ntbuild_house.sh bootstrap corpus' \
'  census                   -> ntbuild_house.sh bootstrap census' \
'  clean                    -> ntbuild_house.sh bootstrap clean' \
'  the C producer (the old default build) -> ntbuild_house.sh bootstrap build' \
'' \
'There is no silent fallback: a legacy command asked of this entrypoint is' \
'refused (exit 78), and the refusal names the invocation that does it.' \
'' \
'Environment:' \
'  NG_REPO      the repository to build in (default: the parent of scripts/)' \
'  NG_PYTHON    the interpreter that runs the house builder (default: python3)' \
'  NG_SEED_DIR  the directory that holds the PUBLISHED seed PE, which is not' \
'               a file of this repository (default: <repo>/bootstrap/nova-native)' \
'' \
'Exit codes: 0 delivered, 78 refused, anything else the house builder failed.'
}

# --------------------------------------------------------------------------
# The dispatch. The command is decided HERE and never guessed downstream: the
# house builder would read an unknown word as a path to build.
# --------------------------------------------------------------------------
cmd=${1:-build}
case "$cmd" in
  build|policy|check|pins|selftest|selfhost)
    shift || true
    run_house "$cmd" "$@"
    ;;
  bootstrap)
    shift || true
    run_legacy "$@"
    ;;
  corpus|census|clean)
    refuse_legacy "$cmd"
    ;;
  -h|--help|help)
    usage
    ;;
  -*)
    refuse_option "$cmd"
    ;;
  *)
    refuse_unknown "$cmd"
    ;;
esac
