#!/usr/bin/env bash
# Builds Nexora Kart with the project's own NTASM compiler.
#   bootstrap C compiler (quarantined) -> ntasm
#   tools/gen_assets.py                -> build/assets.ntasm (tables, art)
#   tools/ntpp.py                      -> build/kart.ntasm (constants inlined)
#   ntasm assemble                     -> build/esp/EFI/BOOT/BOOTX64.EFI
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
out="$here/build"
root="$repo/compiler/c"
mkdir -p "$out/esp/EFI/BOOT"
bash "$repo/scripts/ntbuild.sh" build
cp "$repo/out/c-bootstrap/ntasm/ntasm" "$out/ntasm"
python3 "$here/tools/gen_assets.py" "$out/assets.ntasm"
# Build-time switches for tests: AUTOPILOT=1 lets the computer drive the
# player's kart, DEBUG=1 logs frame rate and race results on COM1.
python3 "$here/tools/ntpp.py" "$here/src/kart.ntasm" "$out/kart.ntasm" \
  "AUTOPILOT=${AUTOPILOT:-0}" "DEBUG=${DEBUG:-0}"
rm -f "$out/esp/EFI/BOOT/BOOTX64.EFI"
"$out/ntasm" assemble "$out/kart.ntasm" -o "$out/esp/EFI/BOOT/BOOTX64.EFI"
echo "OK: $out/esp/EFI/BOOT/BOOTX64.EFI"
