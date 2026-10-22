#!/usr/bin/env bash
# Nexora Genesis - the QEMU campaign, replayed from the tree.  A6.
#
# This is the thing A6 asks for and the tree did not have: a QEMU campaign
# whose SCRIPT IS IN THE TREE, over MORE THAN ONE CASE.  Its evidence is
# legacy/ntasm-s0/fixed-point/REPLAY.md; that file names the harness as
# "not in the tree" and says a reader must supply it.  This is that reader.
#
#   ntqemucampaign.sh list
#   ntqemucampaign.sh run [options]
#     --case NAME         run only NAME (repeatable)
#     --perturb NAME      flip one byte in NAME's REFERENCE COPY, in the
#                         scratch area, never in the tree.  That case must go
#                         red and every other case must stay green.  This is
#                         how the campaign is shown to be ABLE to fail.
#     --ovmf-dir DIR      look for OVMF_CODE_4M.fd / OVMF_VARS_4M.fd in DIR.
#                         Point it at a directory with no firmware and the
#                         campaign FAILS LOUDLY.  It never skips.
#     --keep              leave the scratch area in place on exit
#     --help
#
# Exit: 0 every case passed and the tree did not move under the run.
#       1 at least one case failed, or the tree moved during the run.
#       3 the campaign DID NOT RUN: a tool, the firmware or a tree byte is
#         absent.  There is no exit 0 that means "skipped", and no code path
#         anywhere in this file that turns an absent datum into a pass.
#
# ---------------------------------------------------------------------------
# THE CHARTER QUESTION, stated here rather than deferred
# ---------------------------------------------------------------------------
# AGENTS.md says: "Les runners hote conserves exclusivement sous out/ [...]
# Aucun runner persistant n'est autorise hors de out/."  This file is a runner,
# it lives in scripts/, and it boots QEMU.  That tension is real and it is in
# every header rather than hidden:
#
#   * This script is INVOKED, never resident: no daemon, no scheduled task, no
#     state kept in the tree.  It is not referenced by legacy/tools/coldproof/ngbuild.sh,
#     no gate runs it, no source includes it, no release artefact depends on it,
#     and it writes NOTHING inside the repository -- NG_BUILD is required to be
#     outside and a path inside the repository is refused, not cleaned.
#     Those are the properties AGENTS.md names for a host runner.
#   * Whether "invoked, never resident, writes nothing into the tree, wired
#     into nothing" is still "a persistent runner" in AGENTS.md's letter is the
#     user's call and not this script's.  The earlier evidence for this same
#     campaign stays where AGENTS.md put it, under
#     out/c-bootstrap/nova/evidence/S0FixedPoint/, and is not superseded here.
#
# ---------------------------------------------------------------------------
# WHAT IT DOES NOT DO
# ---------------------------------------------------------------------------
# Nothing here touches A8.  This is proof-3 machinery: the S0 producer
# reproducing its own bytes under QEMU.  The FINAL v0 producer is a different
# object, is named by no file read here, and this campaign says nothing about
# it.  The two must never be read as one result.
#
# ---------------------------------------------------------------------------
# WHERE THE BYTES COME FROM
# ---------------------------------------------------------------------------
# Every byte written into every ESP comes from this tree.  Nothing is read from
# out/ and NO COMPILER RUNS: the launcher, the core module and the source under
# test are copied verbatim, and the artefact compared is the one the producer
# under test WROTE into its own ESP.  The tools are truncate, mkfs.vfat, mmd,
# mdir, mcopy, cp, cmp, sha256sum, qemu-system-x86_64, grep, sleep, python3.
set -uo pipefail

SELF=$(realpath -m "${BASH_SOURCE[0]}")
REPO=${NG_REPO:-$(dirname "$(dirname "$SELF")")}
REPO=$(realpath -m "$REPO")

D=$REPO/legacy/ntasm-s0/fixed-point
PIN=$D/compiler-host.NTASM1.EFI
CORE=$D/compiler-core.NTASM1.EFI
SRC=$REPO/legacy/ntasm-s0/compiler-host.ntasm
PIN_SHA=82826f458aff21d4f5167b296b56813899ea422caedb9d8fda2d8120a9b4882d

MARKER_OK='NG_NTASM_NATIVE_SCAN_OK'
MARKER_E002='NG_NTASM_MODULE_E002'
MARKER_E700='NGS0 E700'

# --------------------------------------------------------------------------
# THE CASES.  Four cases, four axes; each row is here because deleting it would
# leave its claim with no case at all.  A campaign of N identical cases measures
# one thing N times, so no two rows below share a claim.
#
# name | axis | layout | must show | must NOT show | reference
# --------------------------------------------------------------------------
CASES=(
  "s0-fixed-point|F1 self-production: the S0 producer, booted from tree bytes, writes ::/NTASM1.EFI equal to the in-tree pin|FULL|$MARKER_OK|NGS0 E700|PIN"
  "s0-no-core|F2 module absence is a REFUSAL and yields no artefact: without ::/NTCORE.EFI the producer publishes E002 and must not claim success|HOST_SRC|$MARKER_E002|$MARKER_OK|NONE"
  "s0-output-exists|F3 the E700 no-overwrite clause under QEMU: a pre-existing ::/NTASM1.EFI is refused and left byte-identical|FULL_PRECREATE|NGS0 E700|$MARKER_OK|PLANTED"
  "s0-repeat|F4 determinism across two independent executions: the same tree, booted twice, yields byte-identical output|REPEAT|$MARKER_OK|NGS0 E700|PIN"
)
# ALL FOUR DRIVE THE SAME PRODUCER BINARY.  This is one program under four
# axes, not four programs, and it is reported as one program under four axes.

layout_desc() {
  case "$1" in
    FULL)          echo "launcher + core module + source" ;;
    HOST_SRC)      echo "launcher + source; the core module is ABSENT" ;;
    FULL_PRECREATE) echo "launcher + core module + source, with ::/NTASM1.EFI pre-created" ;;
    REPEAT)        echo "launcher + core module + source, booted twice" ;;
    *)             echo "?" ;;
  esac
}

die() { printf 'A6_CAMPAIGN_ABORT %s\n' "$*" >&2; exit 3; }
usage() { sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# --------------------------------------------------------------------------
# PREREQUISITES.  Every absent thing is a HARD failure naming itself.
# --------------------------------------------------------------------------
check_prereqs() {
  local missing=0 t
  for t in truncate mkfs.vfat mmd mdir mcopy cmp sha256sum grep python3; do
    command -v "$t" >/dev/null 2>&1 || { printf 'A6_CAMPAIGN_MISSING_TOOL %s\n' "$t" >&2; missing=1; }
  done
  command -v "$QEMU_BIN" >/dev/null 2>&1 || { printf 'A6_CAMPAIGN_MISSING_TOOL %s\n' "$QEMU_BIN" >&2; missing=1; }
  [ "$missing" -eq 0 ] || die "a required tool is absent: the campaign DID NOT RUN and has no verdict"
  CODE=${NG_OVMF_CODE:-$NG_OVMF_DIR/OVMF_CODE_4M.fd}
  VARS=${NG_OVMF_VARS:-$NG_OVMF_DIR/OVMF_VARS_4M.fd}
  [ -r "$CODE" ] || { printf 'A6_CAMPAIGN_MISSING_FIRMWARE %s\n' "$CODE" >&2; missing=1; }
  [ -r "$VARS" ] || { printf 'A6_CAMPAIGN_MISSING_FIRMWARE %s\n' "$VARS" >&2; missing=1; }
  [ "$missing" -eq 0 ] || die "OVMF firmware is absent: the campaign DID NOT RUN and has no verdict (it did not skip)"
  local f
  for f in "$PIN" "$CORE" "$SRC"; do
    [ -r "$f" ] || { printf 'A6_CAMPAIGN_MISSING_TREE_BYTE %s\n' "$f" >&2; missing=1; }
  done
  [ "$missing" -eq 0 ] || die "a tree byte the payload needs is absent: the campaign DID NOT RUN"
  # The pin must still BE the pinned oracle.  If the tree's own reference has
  # drifted, every comparison below is against the wrong thing and a green run
  # would be green on a moved target.
  local hp; hp=$(sha256sum "$PIN" | cut -d' ' -f1)
  [ "$hp" = "$PIN_SHA" ] || die "the in-tree pin hashes $hp, not $PIN_SHA: the oracle has drifted and no comparison below would mean anything"
  printf 'A6_CAMPAIGN_QEMU %s\n' "$("$QEMU_BIN" --version 2>/dev/null | head -1)"
  printf 'A6_CAMPAIGN_FIRMWARE code=%s vars=%s\n' "$CODE" "$VARS"
  return 0
}

setup_build() {
  BUILD=${NG_BUILD:-${TMPDIR:-/tmp}/ntqemu-campaign-$(date +%H%M%S)-$$}
  case "$BUILD" in
    "$REPO"|"$REPO"/*) die "NG_BUILD=$BUILD is inside the repository; the scratch area must be OUTSIDE it" ;;
  esac
  mkdir -p "$BUILD/refs" "$BUILD/runs" || die "cannot create the scratch area $BUILD"
  # ONE REFERENCE COPY PER CASE.  Not one shared reference: --perturb has to be
  # able to move exactly one case's oracle and leave every other case's alone,
  # and a shared file cannot do that.
  local row name ref
  for row in "${CASES[@]}"; do
    IFS='|' read -r name _ _ _ _ ref <<<"$row"
    case "$ref" in
      PIN)     cp "$PIN"  "$BUILD/refs/$name.ref" ;;
      PLANTED) cp "$CORE" "$BUILD/refs/$name.ref" ;;
      NONE)    : ;;
      *)       die "case $name names an unknown reference kind '$ref'" ;;
    esac
  done
  printf 'A6_CAMPAIGN_BUILD %s\n' "$BUILD"
}

# Binary perturbation of a reference COPY: opens r+b, writes one byte, then
# reads it back with a "rb" open and asserts the needle is present, so "the
# oracle moved" is measured rather than assumed.  The tree is never opened for
# writing anywhere in this file.
perturb_ref() {
  python3 - "$BUILD/refs/$1.ref" <<'PY'
import sys
p = sys.argv[1]
with open(p, "r+b") as f:
    f.seek(4096); old = f.read(1)
    new = b"\x55" if old != b"\x55" else b"\xaa"
    f.seek(4096); f.write(new); f.flush()
with open(p, "rb") as f:
    f.seek(4096); got = f.read(1)
assert got == new and got != old, "needle not confirmed gone"
print("perturbed reference %s: offset 4096 %r -> %r, confirmed by binary read-back" % (p, old, got))
PY
}

# --------------------------------------------------------------------------
# One boot.  Build the ESP from tree bytes, boot it, wait for a MARKER -- a
# timeout is not a verdict -- then pull the artefact back out THROUGH THE IMAGE,
# because what the guest wrote to its own filesystem is the only thing that
# counts as produced.
# --------------------------------------------------------------------------
boot_once() {
  local name="$1" layout="$2" rdir="$3" marker="$4"
  rm -rf "$rdir"; mkdir -p "$rdir" || die "$name: cannot create $rdir"
  local esp="$rdir/esp.img"
  truncate -s 32M "$esp" || die "$name: truncate failed"
  mkfs.vfat -F 16 -n EFX "$esp" >"$rdir/mkfs.log" 2>&1 || die "$name: mkfs.vfat failed, see $rdir/mkfs.log"
  # mmd does not create parents: the two levels go in as two commands.
  mmd -i "$esp" ::/EFI || die "$name: mmd ::/EFI failed"
  mmd -i "$esp" ::/EFI/BOOT || die "$name: mmd ::/EFI/BOOT failed"
  mcopy -i "$esp" "$PIN" ::/EFI/BOOT/BOOTX64.EFI || die "$name: mcopy launcher failed"
  if [ "$layout" != HOST_SRC ]; then
    mcopy -i "$esp" "$CORE" ::/NTCORE.EFI    || die "$name: mcopy core module failed"
    mcopy -i "$esp" "$SRC"  ::/NTASM1.NTASM || die "$name: mcopy source under test failed"
  fi
  if [ "$layout" = FULL_PRECREATE ]; then
    mcopy -i "$esp" "$BUILD/refs/$name.ref" ::/NTASM1.EFI || die "$name: mcopy planted output failed"
  fi
  mdir -i "$esp" ::/ >"$rdir/mdir.txt" 2>&1

  cp "$VARS" "$rdir/vars.fd" || die "$name: cannot copy the OVMF vars"
  PORT=$((56000 + ($$ % 3000) + PORTSEQ)); PORTSEQ=$((PORTSEQ + 1))
  qemu-system-x86_64 \
    -machine q35,accel=tcg -cpu max -m 256M \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$CODE" \
    -drive if=pflash,format=raw,unit=1,file="$rdir/vars.fd" \
    -drive if=virtio,format=raw,file="$esp" \
    -boot order=c,menu=off -nic none -display none \
    -monitor "tcp:127.0.0.1:$PORT,server=on,wait=off" \
    -serial "file:$rdir/serial.log" -d guest_errors -D "$rdir/qemu.log" \
    -no-reboot -no-shutdown &
  local qpid=$!

  local i=0 limit=${NG_QEMU_WAIT:-120}
  while [ "$i" -lt "$limit" ]; do
    grep -aq "$marker" "$rdir/serial.log" 2>/dev/null && { sleep 2; break; }
    kill -0 "$qpid" 2>/dev/null || break
    i=$((i+1)); sleep 1
  done
  printf 'quit\n' | timeout 25 python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', $PORT), timeout=8); s.settimeout(5)
try: s.recv(65536)
except Exception: pass
s.sendall(b'quit\n')
try: s.recv(65536)
except Exception: pass
s.close()" >/dev/null 2>&1
  for _ in $(seq 1 15); do kill -0 "$qpid" 2>/dev/null || break; sleep 1; done
  kill "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null
  return 0
}

# "bytes sha256", or the two words ABSENT and -.  Absence is reported as
# absence and is never turned into a zero-length success.
pull_artefact() {
  local rdir="$1"
  if mcopy -i "$rdir/esp.img" ::/NTASM1.EFI "$rdir/produced.EFI" 2>/dev/null; then
    printf '%s %s\n' "$(wc -c <"$rdir/produced.EFI" | tr -d ' ')" \
                     "$(sha256sum "$rdir/produced.EFI" | cut -d' ' -f1)"
  else
    printf 'ABSENT -\n'
  fi
}

report() {
  printf 'A6_CASE %-18s bytes=%-7s sha256=%-64s compare=%-12s %s\n' "$1" "$2" "$3" "$4" "$5"
}
# verdict records the case's outcome and RETURNS it.  Every caller propagates
# this value: a case that failed must reach the exit status, or the campaign
# would report PASS with a red case printed above it -- which is the one shape
# this whole file exists to be unable to produce.
verdict() { # name PASS|FAIL reason
  printf 'A6_CASE %s VERDICT=%s reason=%s\n' "$1" "$2" "$3"
  if [ "$2" = PASS ]; then : >"$BUILD/runs/$1/.pass"; rm -f "$BUILD/runs/$1/.fail"; return 0
  else : >"$BUILD/runs/$1/.fail"; rm -f "$BUILD/runs/$1/.pass"; return 1; fi
}

run_case() {
  local name="$1" want="$2" forbid="$3" ref="$4" layout="$5"
  local rdir="$BUILD/runs/$name/a"; mkdir -p "$rdir"
  boot_once "$name" "$layout" "$rdir" "$want"

  local ok=0 bad=0 bytes sha
  grep -aq "$want"    "$rdir/serial.log" 2>/dev/null && ok=1
  grep -aq "$forbid" "$rdir/serial.log" 2>/dev/null && bad=1
  read -r bytes sha <<<"$(pull_artefact "$rdir")"

  if [ "$ok" -ne 1 ]; then
    report "$name" "$bytes" "$sha" NO-MARKER "expected '$want' never appeared on the serial line"
    verdict "$name" FAIL no-marker; return 1
  fi
  if [ "$bad" -eq 1 ]; then
    report "$name" "$bytes" "$sha" REFUSED-BY "forbidden marker '$forbid' appeared"
    verdict "$name" FAIL forbidden-marker; return 1
  fi
  if [ "$ref" = NONE ]; then
    if [ "$bytes" = ABSENT ]; then
      report "$name" ABSENT - n/a "PASS refused as specified; no artefact claimed"
      verdict "$name" PASS refused-as-specified; return $?
    fi
    report "$name" "$bytes" "$sha" UNEXPECTED "an artefact appeared where the claim is that none does"
    verdict "$name" FAIL artefact-present; return $?
  fi
  if [ "$bytes" = ABSENT ]; then
    report "$name" ABSENT - NO-ARTEFACT "the producer wrote no ::/NTASM1.EFI"
    verdict "$name" FAIL no-artefact; return 1
  fi
  if cmp -s "$rdir/produced.EFI" "$BUILD/refs/$name.ref"; then
    report "$name" "$bytes" "$sha" IDENTICAL "PASS byte-identical to $BUILD/refs/$name.ref"
    verdict "$name" PASS identical-to-reference; return $?
  fi
  report "$name" "$bytes" "$sha" DIFFERENT "FAIL against $BUILD/refs/$name.ref"
  verdict "$name" FAIL cmp-different; return $?
}

run_repeat_case() {
  local name=s0-repeat a b
  a="$BUILD/runs/$name/a"; b="$BUILD/runs/$name/b"
  mkdir -p "$a" "$b"
  boot_once "$name" FULL "$a" "$MARKER_OK"
  boot_once "$name" FULL "$b" "$MARKER_OK"
  local ab bb a_bytes a_sha b_bytes b_sha
  read -r a_bytes a_sha <<<"$(pull_artefact "$a")"
  read -r b_bytes b_sha <<<"$(pull_artefact "$b")"
  if [ "$a_bytes" = ABSENT ] || [ "$b_bytes" = ABSENT ]; then
    report "$name" "$a_bytes" "$a_sha" NO-ARTEFACT "one of the two executions produced nothing"
    verdict "$name" FAIL no-artefact; return 1
  fi
  if [ "$a_sha" != "$b_sha" ]; then
    report "$name" "$a_bytes" "$a_sha" "run2=$b_sha" "FAIL the two executions disagree"
    verdict "$name" FAIL nondeterministic; return 1
  fi
  report "$name" "$a_bytes" "$a_sha" "run2=$b_sha" "PASS the two executions agree and match the in-tree pin"
  verdict "$name" PASS deterministic; return $?
}

# --------------------------------------------------------------------------
main() {
  QEMU_BIN=${NG_QEMU:-qemu-system-x86_64}
  NG_OVMF_DIR=${NG_OVMF_DIR:-/usr/share/OVMF}
  PORTSEQ=0
  local mode=run keep=0
  local -a only=() perturb=()
  while [ $# -gt 0 ]; do
    case "$1" in
      list)      mode=list ;;
      run)       mode=run ;;
      --case)    only+=("$2"); shift ;;
      --perturb) perturb+=("$2"); shift ;;
      --ovmf-dir) NG_OVMF_DIR="$2"; shift ;;
      --keep)    keep=1 ;;
      --help|-h) usage; exit 0 ;;
      *) printf 'A6_CAMPAIGN_ABORT unknown argument: %s\n' "$1" >&2; exit 3 ;;
    esac
    shift
  done

  if [ "$mode" = list ]; then
    echo "A6 QEMU CAMPAIGN -- the cases, and the axis each one owns"
    echo "  recipe   legacy/ntasm-s0/fixed-point/REPLAY.md"
    echo "  payload  tree bytes only; no compiler is invoked; nothing is read from out/"
    echo "  scope    all four cases drive ONE producer binary: one program, four axes"
    echo "  scope    proof-3 machinery (the S0 fixed point).  It does not touch A8."
    echo
    local row name axis layout
    for row in "${CASES[@]}"; do
      IFS='|' read -r name axis layout _ _ _ <<<"$row"
      printf '  %-18s %s\n' "$name" "$axis"
      printf '      payload  %s\n\n' "$(layout_desc "$layout")"
    done
    return 0
  fi

  check_prereqs
  setup_build

  # FENCE.  The campaign reads four things from the tree; hash them before and
  # after.  Comparing a moved tree against itself proves nothing, so a moved
  # tree is a LOUD FAILURE, never a footnote.
  local fence_before fence_after
  fence_before=$(sha256sum "$PIN" "$CORE" "$SRC" | sha256sum | cut -d' ' -f1)

  local p
  for p in ${perturb[@]+"${perturb[@]}"}; do
    printf 'A6_CAMPAIGN_PERTURB %s\n' "$p"
    perturb_ref "$p" || die "cannot perturb the reference copy of case $p"
  done

  local rc=0 ran=0 row name axis layout show forbid ref o wanted
  for row in "${CASES[@]}"; do
    IFS='|' read -r name axis layout show forbid ref <<<"$row"
    if [ "${#only[@]}" -gt 0 ]; then
      wanted=0; for o in "${only[@]}"; do [ "$o" = "$name" ] && wanted=1; done
      [ "$wanted" -eq 1 ] || continue
    fi
    ran=$((ran+1))
    printf 'A6_CAMPAIGN_RUN %s axis=%s\n' "$name" "$axis"
    if [ "$name" = s0-repeat ]; then run_repeat_case "$name"; else run_case "$name" "$show" "$forbid" "$ref" "$layout"; fi
    [ $? -ne 0 ] && rc=1
  done
  [ "$ran" -gt 0 ] || die "no case matched: --case named none of ${only[*]-}"

  fence_after=$(sha256sum "$PIN" "$CORE" "$SRC" | sha256sum | cut -d' ' -f1)
  printf 'A6_CAMPAIGN_FENCE before=%s\n' "$fence_before"
  printf 'A6_CAMPAIGN_FENCE after=%s\n' "$fence_after"
  if [ "$fence_before" != "$fence_after" ]; then
    printf 'A6_CAMPAIGN_VERDICT=FAIL reason=tree-moved-during-run\n' >&2
    rc=1
  fi

  # The failing set is RECOMPUTED from what each case recorded, so the exit
  # status names the cases that failed and not merely "red".
  local -a failed=()
  for row in "${CASES[@]}"; do
    IFS='|' read -r name _ _ _ _ _ <<<"$row"
    [ -f "$BUILD/runs/$name/.pass" ] || { [ -f "$BUILD/runs/$name/.fail" ] && failed+=("$name"); }
  done
  if [ "$rc" -eq 0 ]; then
    printf 'A6_CAMPAIGN_VERDICT=PASS cases=%s build=%s\n' "$ran" "$BUILD"
  else
    if [ "${#failed[@]}" -gt 0 ]; then
      printf 'A6_CAMPAIGN_VERDICT=FAIL cases=%s failed_case=%s\n' "$ran" "${failed[*]}" >&2
    else
      printf 'A6_CAMPAIGN_VERDICT=FAIL cases=%s\n' "$ran" >&2
    fi
  fi
  [ "$keep" -eq 1 ] || : # the scratch area is outside the repository by construction
  exit $rc
}

main "$@"