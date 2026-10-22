#!/usr/bin/env bash
# Bounded live A8 check of the transport, with the HMP liveness poll.
#
# This is NOT part of the pure test suite: it starts a real QEMU, in WSL,
# with the OVMF firmware. It is the one live run the review asked for, and
# it is bounded: two boots, each with its own budget.
#
#   green  the certified host of the watchdog proof. The run must PASS, and
#          the liveness block must show a DUE observation that confirmed the
#          success, and the extracted OUTPUT.EFI must be byte-identical to
#          the published one.
#   red    the host of the deliberate watchdog case, whose guest powers off.
#          The run must FAIL FAST, with "paused (shutdown)" in the reason,
#          the HMP transcript kept, and the whole boot finished in seconds
#          instead of the budget.
#
# The archive is READ ONLY: every image is read from it and nothing is
# written back. The evidence lands under <repo>/out/a8-live.
#
# Usage: bash tests/transport/a8_live_check.sh
set -u
REPO=${A8_REPO:-/mnt/c/Users/steph/Documents/Codex/2026-10-22/a8-maintenance}
ARCHIVE=${A8_ARCHIVE:-/mnt/c/NexoraGenesis/out/a8-selfhost-20261015}
STAGE=$ARCHIVE/house-stage-20261021-01/out/watchdog-tests
TRANSPORT=$REPO/scripts/nova_native_transport.py
WORK=$REPO/out/a8-live
BUDGET=${A8_LIVE_BUDGET:-120}
PY=${PYTHON:-python3}

run_case() {
  name=$1; host=$2
  echo "=== $name ($host) budget=${BUDGET}s"
  "$PY" "$TRANSPORT" --repo "$REPO" --work-root out/a8-live --name "$name" \
      --timeout "$BUDGET" --code /usr/share/OVMF/OVMF_CODE_4M.fd \
      --vars /usr/share/OVMF/OVMF_VARS_4M.fd \
      run "$host" \
      "$ARCHIVE/runtime-native/asm-runtime-02/produced.EFI" \
      "$ARCHIVE/runtime-native/selfcompile-batches-p2-04/OUTPUT.EFI" \
      --payload "NOVA.IN=$ARCHIVE/runtime-native/native-driver-many-seed-14/two-modules-42/NOVA.IN" \
      --extract-file OUTPUT.EFI
  echo "=== $name exit=$?"
}

mkdir -p "$WORK"
run_case live-green "$STAGE/assemble-green/produced.EFI"
run_case live-red "$STAGE/assemble-red/produced.EFI"
echo "=== done; the evidence is under $WORK"
