# `frameless-uefi/` — the executed proof that the image producer emits no frame

**What a reader should do with these two files: compare them.** They are here so
the claim `spec/ntasm/ntasm.md` makes about a frameless execution proof can be
checked from a clean checkout, instead of being a claim about a directory that
only exists after a run.

| file | bytes | sha256 | what it is |
|---|---|---|---|
| `program.ntasm` | 352 | `91cd6d80bf92ff11441d53b61483626222b846fcf4dc2c803d58f4482514559e` | the source under test: **three** functions, **zero** parameters |
| `nova-produced.efi` | 3072 | `905e84cea7fab918688b0069b1640dff8a24c17ef4a13e35b4d08c62d41df0ae` | the PE the Nova producer wrote for it; entry RVA `0x1000` |

`program.ntasm` is the whole reason the claim is worth making. Every one of its
three functions — `main`, `seed`, `twice` — declares no parameter, and the
frame-producing producer in the C oracle refuses to skip the frame in that
shape, so the two producers visibly disagree here. That disagreement is the
point; do not "fix" the programme by adding a parameter.

## What is deliberately NOT here

The host runner that produced `nova-produced.efi` is **not** copied in. It stays
at `out/c-bootstrap/nova/ntasm-nova-uefi-20260926/`, together with
`driver.c`, `run-nova-uefi.ps1` and `build-driver.sh`.

This is not an oversight. `AGENTS.md` states: *« Les runners hôte conservés
exclusivement sous `out/` sont des preuves d'orchestration non productrices […]
Aucun runner persistant n'est autorisé hors de `out/`. »* Copying a runner into
the tree would break that rule, so the rule decided this case rather than
convenience. `out/` is also a consumed build state — the self-host destroys it
on entry — so a citation pointing into it is a citation that stops resolving.

The split is therefore: **the inputs and the product are in the tree, the
harness is not.** A reader can check the two digests, the size, the entry RVA
and the source shape from the tree alone, and must run the harness from `out/`
to regenerate.

## Reproducing the run

Build the driver from `out/c-bootstrap/nova/ntasm-nova-uefi-20260926/` with its
own `build-driver.sh`, then run it under QEMU/OVMF with the 32 MiB FAT16 ESP
whose layout is `::/EFI/BOOT/BOOTX64.EFI` (a stock OVMF loader), the module
under test, and the source. The marker is `NG_NTASM_C_RESULT_OK`, result 42.
