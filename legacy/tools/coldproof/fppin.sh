#!/bin/bash
# LOT46 -- the derived pins for the S0 fixed point.
#
# FORMAT. The rows are ntbuild.sh's corpus format, character for character:
# `name|sources|digest`, `sources` '+'-joined, one row per line on stdout
# (scripts/ntbuild.sh:773-785, `cmd_corpus`). A consumer reads them as a
# read-only stream and re-derives nothing -- the shape ntselfhost.sh:246 uses:
#
#     while IFS='|' read -r name rel pin; do ... done < <(producer)
#
# WHY THE ROWS ARE NOT COPIES. Every digest below is recomputed from the tree
# on every run: sha256sum over a named file, or the digest of the file the
# fixed-point replay produces under QEMU. Nothing here is written by this
# script into an authority; `--verify` compares what it derived against the
# expectation handed to it and refuses on any difference, so a wrong
# expectation is red, not absorbed.
#
# WHAT IS DERIVED AND WHAT IS NOT -- this is the whole content of the file.
#
#   fixed-point-host   DERIVED, by the fixed point itself. The launcher is its
#                      own producer (REPLAY.md:57-60): boot it on
#                      legacy/ntasm-s0/compiler-host.ntasm and it writes
#                      ::/NTASM1.EFI, which is byte-identical to the in-tree
#                      compiler-host.NTASM1.EFI. So the digest is re-derived
#                      from the tree by RUNNING the tree, not by trusting a
#                      number somebody typed. Cost: one QEMU boot, ~3 s.
#
#   fixed-point-core   NOT DERIVED. Measured 2026-10-01: the only producer in
#                      the tree, out/c-bootstrap/ntasm/ntasm, refuses both S0
#                      sources with `E200: expected 'module'` and exits 1, so
#                      no command in the tree can regenerate compiler-core.
#                      NTMASM1.EFI. The row below is therefore a pin whose
#                      derivation is the digest of an opaque deposited binary --
#                      a transcription wearing a derived row's clothes, and the
#                      script says DERIVED=no on it rather than pretending.
#
# USAGE
#   fppin.sh [--expect FILE]        print the rows; compare against FILE
#   fppin.sh --verify                same, exit 1 on any difference
#   fppin.sh --expect-expect 1       plant a deliberately wrong expectation
#   fppin.sh --corpus-format         print the corpus rows only, nothing else
#
# Exit codes: 0 rows derived and matching; 1 a difference, or an input absent,
# or a refused check. A run with no exit condition is not a pass.

set -u
REPO=${NG_REPO:-/mnt/d/Projets/Racine-C/NexoraGenesis}
FP_DIR=${NG_FIXED_POINT_DIR:-$REPO/legacy/ntasm-s0/fixed-point}
BUILD=${NG_BUILD:-$REPO/out/c-bootstrap/nova/lot46/fppin}
HOST_SRC=legacy/ntasm-s0/compiler-host.ntasm
CORE_SRC=legacy/ntasm-s0/modules/compiler-core.ntasm
HOST_EFI=$FP_DIR/compiler-host.NTASM1.EFI
CORE_EFI=$FP_DIR/compiler-core.NTASM1.EFI

verify=0; corpus_only=0; expect=""; sabotage=0
while [ $# -gt 0 ]; do
  case $1 in
    --verify)       verify=1 ;;
    --corpus-format) corpus_only=1 ;;
    --expect)       expect=$2; shift ;;
    --expect-expect) sabotage=1 ;;   # plant a wrong expectation on purpose
    *) printf 'LOT46_FPPIN usage_error:%s\n' "$1"; exit 1 ;;
  esac
  shift
done

say() { [ "$corpus_only" = 1 ] || printf '%s\n' "$*"; }
fail() { printf 'LOT46_FPPIN MISMATCH %s\n' "$*"; return 1; }

# ---- the guards, read before the symptoms --------------------------------
for t in sha256sum mcopy mkfs.vfat mmd qemu-system-x86_64 python3 cmp truncate; do
  command -v "$t" >/dev/null 2>&1 || { say "tool_absent:$t"; }
done
for f in "$HOST_EFI" "$CORE_EFI" "$REPO/$HOST_SRC" "$REPO/$CORE_SRC"; do
  [ -f "$f" ] || { printf 'LOT46_FPPIN input_absent %s\n' "${f#"$REPO"/}"; exit 1; }
done

tree_host=$(sha256sum "$HOST_EFI" | cut -d' ' -f1)
tree_core=$(sha256sum "$CORE_EFI" | cut -d' ' -f1)
host_bytes=$(wc -c <"$HOST_EFI" | tr -d ' ')
core_bytes=$(wc -c <"$CORE_EFI" | tr -d ' ')

# ---- the DERIVED digest: run the fixed point ------------------------------
# Nothing here trusts the number in REPLAY.md. The expected value is produced
# by booting the in-tree launcher on the in-tree source and reading the bytes
# it writes out of the ESP.
replay() { # $1 = run dir
  local run=$1 port=$(( 55100 + $$ % 500 ))
  mkdir -p "$run" || return 1
  (
    set -e
    cd "$run"
    truncate -s 32M esp.img
    mkfs.vfat -F 16 -n EFX esp.img >/dev/null
    mmd -i esp.img ::/EFI
    mmd -i esp.img ::/EFI/BOOT
    mcopy -i esp.img "$HOST_EFI" ::/EFI/BOOT/BOOTX64.EFI
    mcopy -i esp.img "$CORE_EFI"   ::/NTCORE.EFI
    mcopy -i esp.img "$REPO/$HOST_SRC" ::/NTASM1.NTASM
    # read the payload back out, not from intent (REPLAY.md:99-100)
    mcopy -i esp.img ::/EFI/BOOT/BOOTX64.EFI check-host.efi
    cmp check-host.efi "$HOST_EFI"
    cp "${NG_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}" vars.fd
    qemu-system-x86_64 -machine q35,accel=tcg -cpu max -m 256M \
      -drive if=pflash,format=raw,unit=0,readonly=on,file="${NG_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}" \
      -drive if=pflash,format=raw,unit=1,file=vars.fd \
      -drive if=virtio,format=raw,file=esp.img \
      -boot order=c,menu=off -nic none -display none \
      -monitor tcp:127.0.0.1:$port,server=on,wait=off \
      -serial file:serial.log -d guest_errors -D qemu.log \
      -no-reboot -no-shutdown &
    i=0
    while [ $i -lt 240 ]; do
      grep -q NG_NTASM_NATIVE_SCAN_OK serial.log 2>/dev/null && break
      i=$((i+1)); sleep 1
    done
    grep -q NG_NTASM_NATIVE_SCAN_OK serial.log || { echo "no-marker"; exit 3; }
    printf 'quit\n' | python3 -c "
import socket
s=socket.create_connection(('127.0.0.1',$port),timeout=8); s.settimeout(5)
try: s.recv(65536)
except Exception: pass
s.sendall(b'quit\n')
try: s.recv(65536)
except Exception: pass
s.close()" || true
    mcopy -i esp.img ::/NTASM1.EFI produced.EFI
  ) >"$run/replay.log" 2>&1 || return 1
  [ -f "$run/produced.EFI" ] || return 1
  sha256sum "$run/produced.EFI" | cut -d' ' -f1
}

say "deriving fixed-point-host by running the fixed point (one QEMU boot)"
derived_host=$(replay "$BUILD/replay-$$")
rc=$?
if [ $rc -ne 0 ] || [ -z "${derived_host:-}" ]; then
  printf 'LOT46_FPPIN DERIVATION_FAILED host: the replay did not finish; no conclusion\n'
  exit 1
fi
derived_host_bytes=$(wc -c <"$BUILD/replay-$$/produced.EFI" | tr -d ' ')

# ---- the rows ------------------------------------------------------------
# name|sources|digest, the corpus format of scripts/ntbuild.sh:783.
rows() {
  printf 'fixed-point-host|%s|%s\n' "$HOST_SRC" "$derived_host"
  printf 'fixed-point-core|%s|%s\n' "$CORE_SRC" "$tree_core"
}
[ "$corpus_only" = 1 ] && { rows; exit 0; }

bad=0
say "LOT46_FPPIN rows=2"
printf '  fixed-point-host   DERIVED=yes  by=boot(launcher,%s) bytes=%s sha256=%s\n' \
  "$HOST_SRC" "$derived_host_bytes" "$derived_host"
printf '  fixed-point-core   DERIVED=no   by=sha256sum(deposited PE) bytes=%s sha256=%s\n' \
  "$core_bytes" "$tree_core"
printf '  reason_core_not_derived=no producer in the tree accepts S0; measured E200 expected module on %s and %s, rc=1\n' \
  "$HOST_SRC" "$CORE_SRC"
printf '  in_tree_host_sha256=%s in_tree_core_sha256=%s\n' "$tree_host" "$tree_core"

# The one equality the fixed point actually claims: what the launcher produced
# is the launcher. This is the check; the two numbers are not the check.
if [ "$derived_host" = "$tree_host" ]; then
  printf '  FIXED_POINT_REPRODUCED derived==in_tree sha256=%s\n' "$derived_host"
else
  printf '  FIXED_POINT_MISMATCH derived=%s in_tree=%s\n' "$derived_host" "$tree_host"
  bad=1
fi
[ "$derived_host_bytes" = "$host_bytes" ] || {
  printf '  BYTES_MISMATCH derived=%s in_tree=%s\n' "$derived_host_bytes" "$host_bytes"; bad=1; }

# ---- the expectation, if one was handed in -------------------------------
if [ "$sabotage" = 1 ]; then
  expect="$BUILD/WRONG.exp"
  mkdir -p "$BUILD"
  printf 'fixed-point-host|%s|%s\n' "$HOST_SRC" \
    0000000000000000000000000000000000000000000000000000000000000000 >"$expect"
  printf '  negative_control: expectation planted with a wrong host digest\n'
fi
if [ -n "$expect" ]; then
  [ -f "$expect" ] || { printf 'LOT46_FPPIN expectation_absent %s\n' "$expect"; exit 1; }
  while IFS='|' read -r n rel pin; do
    [ -n "$n" ] || continue
    case $n in
      fixed-point-host) got=$derived_host ;;
      fixed-point-core) got=$tree_core ;;
      *) printf '  UNKNOWN_ROW %s\n' "$n"; bad=1; continue ;;
    esac
    [ "$got" = "$pin" ] && printf '  ok     %s %s\n' "$n" "$got" \
                      || { printf '  DIFFERS %s\n     expected %s\n     derived  %s\n' "$n" "$pin" "$got"; bad=1; }
  done <"$expect"
fi

[ "$verify" = 1 ] || [ -n "$expect" ] || [ "$bad" = 0 ] || true
printf 'LOT46_FPPIN result=%s\n' "$([ $bad -eq 0 ] && echo PASS || echo FAIL)"
exit $bad