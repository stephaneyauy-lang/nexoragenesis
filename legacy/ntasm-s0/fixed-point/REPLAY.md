# Replay recipe — reproducing the S0 fixed point from this directory

**STATUS: GREEN, 29 September 2026, run from a tree with nothing read from
`out/`.** A8(b) — the S0 producer reproducing its own bytes byte-for-byte — is
**verifiable from a clean checkout**, and this file is the command that does it.

```
produced ::/NTASM1.EFI   17408 bytes
          sha256 82826f458aff21d4f5167b296b56813899ea422caedb9d8fda2d8120a9b4882d
in-tree  compiler-host.NTASM1.EFI   sha256 82826f458aff21d4f5167b296b56813899ea422caedb9d8fda2d8120a9b4882d
cmp produced.EFI compiler-host.NTASM1.EFI   ->  IDENTICAL, exit 0
serial:  NSCAN S00E6 T00002E57 R00000178 D00000BA8 B0000AB11 Q000054EF
         NG_NTASM_NATIVE_SCAN_OK
```

**Two components only.** `module-host`, `native-lexer`, `native-source` and the
rest of the S0 tree are **not** replayed and **not** claimed. Two green is not
six. The trust root is still out of band: these files are the *result*, not an
independent input, so this proves determinism and self-reproduction, not that
the launcher is correct — by the definition of a trust root.

**And the honesty about dates, which is the point of this file:** the two PE
were **deposited into the tree on 29 September 2026**, by this project, from a
replay. They were not there before. This file's earlier revision said the
opposite — that the recipe was untested — and it was honest at the time. Both
halves are true on their own dates and the dates are stated so nobody has to
guess which edition they are reading.

---

## What is the artefact and what is the harness

| | what | where |
|---|---|---|
| **artefact** | the two PE | **this directory**, in the tree, yours to compare |
| **input** | the S0 sources | `../compiler-host.ntasm`, `../modules/compiler-core.ntasm` |
| **harness** | the QEMU invocation, the ESP layout, the boot/marker loop | **not in the tree** |

The harness is not here because `AGENTS.md` says *« Aucun runner persistant
n'est autorisé hors de `out/` »*. **A reader must supply it.** That is a
constraint, not an omission, and it is why this is a recipe rather than a
script: a committed script would be a runner.

## The ESP layout

Read back out of the image with `mdir`, not assumed:

```
::/EFI/BOOT/BOOTX64.EFI   17408   the launcher
::/NTCORE.EFI             20992   the core PE
::/NTASM1.NTASM           43793   the source under test, verbatim
::/NTASM1.EFI                     WRITTEN BY THE PRODUCER — do not create it
```

### Three traps, all of which cost a run

1. **The launcher is one of the two PE, not a third one.**
   `compiler-host.NTASM1.EFI` is byte-identical to the `BOOTX64.EFI` the
   producer writes; same `82826f45…`. The producer is its own input. Do not go
   looking for a separate bootstrap loader.
2. **`NTASM1.EFI` must NOT exist before the run.**
   `spec/ntasm/ntasm-s0.md:408` — `E700` is *« sortie déjà existante; aucun
   écrasement autorisé »*. The producer **creates** its output and refuses to
   overwrite. **Verified as a control, not assumed:** a run identical except
   that `::/NTASM1.EFI` was pre-created gives `NGS0 E700 L0000 C0000
   O00000000` and no marker, while the unperturbed run is green.
3. **`NTASM1.NTASM` does not fit FAT 8.3 and `mcopy` handles that for you.**
   Its extension is five characters, so 8.3 cannot express it and the on-disk
   name is the mangled alias `NTASM1~1|NTA` — visible in the `mdir` output
   above, with the long name beside it. **`mcopy` emits the long-filename
   entries; a hand-rolled FAT writer will not, and OVMF will then not see the
   file at all.** This is the single most expensive trap in this recipe: a
   from-scratch writer burns an afternoon discovering LFN checksum and `.`/`..`
   placement, and the resulting image fails with `Not Found` and no `FS0` at
   all, which looks nothing like a filename problem.

## The recipe

```sh
set -e
REPO=/path/to/NexoraGenesis          # the tree root
D="$REPO/legacy/ntasm-s0/fixed-point"
RUN=$(mktemp -d); cd "$RUN"

# 1. the carrier. 32 MiB FAT16, used whole.
truncate -s 32M esp.img
mkfs.vfat -F 16 -n EFX esp.img
mmd -i esp.img ::/EFI
mmd -i esp.img ::/EFI/BOOT

# 2. the payload. Every byte below comes from the tree; nothing from out/.
mcopy -i esp.img "$D/compiler-host.NTASM1.EFI" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i esp.img "$D/compiler-core.NTASM1.EFI"   ::/NTCORE.EFI
mcopy -i esp.img "$REPO/legacy/ntasm-s0/compiler-host.ntasm" ::/NTASM1.NTASM
#    ::/NTASM1.EFI is deliberately NOT created. See trap 2.

# 2b. VERIFY THE PAYLOAD IS THE ONE YOU MEANT. Read the bytes back out of
#     the image you just built and compare to the tree, not to your intent.
mcopy -i esp.img ::/EFI/BOOT/BOOTX64.EFI check-host.efi
cmp check-host.efi "$D/compiler-host.NTASM1.EFI"    # must be identical

# 3. a WRITABLE copy of the vars. The code image is read-only.
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd

# 4. boot.
PORT=54961
qemu-system-x86_64 \
  -machine q35,accel=tcg -cpu max -m 256M \
  -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,unit=1,file=vars.fd \
  -drive if=virtio,format=raw,file=esp.img \
  -boot order=c,menu=off -nic none -display none \
  -monitor tcp:127.0.0.1:$PORT,server=on,wait=off \
  -serial file:serial.log -d guest_errors -D qemu.log \
  -no-reboot -no-shutdown &

# 5. the exit condition is the MARKER, then HMP quit. Not a timeout-as-success.
i=0
while [ $i -lt 240 ]; do
  grep -q NG_NTASM_NATIVE_SCAN_OK serial.log 2>/dev/null && break
  i=$((i+1)); sleep 1
done
grep -q NG_NTASM_NATIVE_SCAN_OK serial.log || { echo "FAIL: no marker"; exit 1; }
printf 'quit\n' | python3 -c "
import socket
s=socket.create_connection(('127.0.0.1',$PORT),timeout=8); s.settimeout(5)
try: s.recv(65536)
except Exception: pass
s.sendall(b'quit\n')
try: s.recv(65536)
except Exception: pass
s.close()"

# 6. the comparison that is the whole point.
mcopy -i esp.img ::/NTASM1.EFI produced.EFI
cmp produced.EFI "$D/compiler-host.NTASM1.EFI" && echo "FIXED POINT REPRODUCED"
```

## A correction to step 4, about `qemu.log`

**`qemu.log` is NOT expected to be empty, and an assertion that it is will fail
on a correct run.** Mine was 450 bytes on the green run:

```
Invalid read at addr 0xFED40000, size 1, region '(null)', reason: rejected
Invalid read at addr 0xFED40030, size 4, region '(null)', reason: rejected
Invalid read at addr 0xFED40014, size 4, region '(null)', reason: rejected
```

That is **OVMF probing the ACPI/PM timer block at `0xFED4xxxx` during
firmware init — the firmware, not the producer.** The establishing replay
recorded a 0-byte `qemu.log` because it used the 2 MiB OVMF build; WSL ships
only the 4 MiB one, which probes differently. **Assert on the marker and the
byte comparison, not on the emptiness of the guest-error log.** An earlier
revision of this file asserted `test ! -s qemu.log` and was simply wrong.

## The two controls, because one run is not a measurement

A green run proves nothing on its own unless you can also show the rig is
capable of going red. Both of these were executed on 29 September 2026:

| question | control | observed |
|---|---|---|
| did the run do what I asked? | **must-FAIL**: pre-create `::/NTASM1.EFI` | `NGS0 E700 L0000 C0000 O00000000`, no marker, no `NSCAN` — **refused, as it must** |
| was the payload the one I meant? | **must-PASS**: read the PE back out of the image | both hash-identical to the tree files |

Answer them in that order and report them separately. A rig that cannot produce
the red has not been shown to produce the green.
