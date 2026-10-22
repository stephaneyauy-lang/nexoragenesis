#!/usr/bin/env bash
# Builds Nexora OS with the project's own NTASM compiler.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
out="$here/build"
root="$repo/compiler/c"
mkdir -p "$out/esp/EFI/BOOT"
bash "$repo/scripts/ntbuild.sh" build
cp "$repo/out/c-bootstrap/ntasm/ntasm" "$out/ntasm"
python3 "$here/tools/gen_assets.py" "$out/assets.ntasm"
python3 "$here/../kart/tools/ntpp.py" /dev/null /dev/null 2>/dev/null || true
# build the embedded Nova app with the project's Nova compiler
novacc="$out/novacc"
${CC:-gcc} -std=c11 -O2 \
  "$repo/compiler/c/nova/frontend/nova.c" \
  "$repo/compiler/c/ntasm/frontend/ntasm.c" \
  "$repo/compiler/c/ntasm/frontend/frontend.c" \
  "$repo/compiler/c/ntasm/backend/codegen.c" \
  "$repo/compiler/c/ntasm/backend/x64.c" \
  "$repo/compiler/c/ntasm/formats/pe.c" \
  "$repo/compiler/c/ntasm/formats/object.c" \
  "$repo/compiler/c/ntasm/formats/object_build.c" \
  "$repo/compiler/c/ntasm/formats/object_link.c" \
  "$repo/compiler/c/ntasm/formats/object_materialize.c" \
  "$repo/compiler/c/ntasm/analysis/conformance.c" \
  "$repo/compiler/c/nova/runtime/run_host.c" \
  "$repo/compiler/c/nova/runtime/runtime_v2.c" \
  "$repo/compiler/c/nova/pe/pe_oracle.c" \
  "$repo/compiler/c/nova/backend/machine_driver.c" \
  "$repo/compiler/c/nova/cli/cli.c" -o "$novacc"
rm -f "$out/hello.efi"
"$novacc" build "$here/apps/hello.nova" -o "$out/hello.efi"
python3 "$here/tools/embed_nova.py" "$out/hello.efi" "$out/novaapp.ntasm"
python3 "$here/tools/ntpp.py" "$here/src/nexoros.ntasm" "$out/nexoros.ntasm"
rm -f "$out/esp/EFI/BOOT/BOOTX64.EFI"
"$out/ntasm" assemble "$out/nexoros.ntasm" -o "$out/esp/EFI/BOOT/BOOTX64.EFI"
echo "OK: $out/esp/EFI/BOOT/BOOTX64.EFI"
