**When these two files were deposited: 29 September 2026.** This is a fact
about provenance, not a footnote, and it is the one thing a reader six weeks
from now will get wrong if it is not written down here.

- They were **copied in on 29 September 2026** from
  `out/ntasm/token-limit-stage2/compiler-{host,core}/produced-NTASM1.EFI`, after a
  four-case QEMU/OVMF replay (two components × two generations, all four
  byte-identical, `cmp` exit 0). The copy was verified byte-identical, not merely
  digest-equal.
- **The tree did NOT carry this comparison before that date.** The S0 sources
  were in the tree and the outputs were not — measured: a scan of every file
  under `legacy/ntasm-s0/` for the `MZ` magic returned **0**, with a positive
  control showing the same scan finds a PE immediately under `out/`.
- So *« byte-identical to the S0 in the tree »* is **true as of 29 September
  2026 and was not verifiable on 5 September 2026.** The acceptance table in
  `docs/status/ntasm-completion.md` describes the September state. **Do not read this
  directory as evidence that the trust predates its own deposit.**

## What a reader should do with these two files: nothing

They are here to be compared, not built, not edited, and not deleted. They are
the *output* of the S0 producer, kept in the tree so the claim in
`spec/ntasm/ntasm.md` that the producer reproduces its own bytes byte-for-byte can be
checked from a clean checkout. Until they were copied here, that claim was true
and unreadable: a reader doing what the sentence says — looking for binaries
under `legacy/ntasm-s0/` — would have found none and concluded the claim was
false.

| file | bytes | sha256 | component | source under test |
|---|---|---|---|---|
| `compiler-host.NTASM1.EFI` | 17408 | `82826f458aff21d4f5167b296b56813899ea422caedb9d8fda2d8120a9b4882d` | host | `../compiler-host.ntasm` (43793 o, `1d72d975…`) |
| `compiler-core.NTASM1.EFI` | 20992 | `a02425be642b839586593b6b5468bc13f4f85d29a503987aa972e4750d1d428f` | core | `../modules/compiler-core.ntasm` (54798 o, `fc1c5d5a…`) |

## Why these are copies and not a move

`out/` is deliberately left untouched. The self-host destroys `out/` on entry,
so a move would break the replay that currently works. The tree copy is
additive; the originals are still at
`out/ntasm/token-limit-stage2/compiler-{host,core}/produced-NTASM1.EFI` and were
verified byte-identical to these two at the moment of copying.

## The launcher is one of these two files

This is the load-bearing fact and it is easy to get wrong. Generation 1 is
launched **by the host PE itself** — `compiler-host.NTASM1.EFI` is byte-identical
to `out/ntasm/token-limit-stage2/compiler-host/esp/EFI/BOOT/BOOTX64.EFI`, the
same `82826f45…`. The producer is its own input. **There is no third PE**, and
adding one would be a category error.

## The ESP layout, for anyone re-running this

```
::/EFI/BOOT/BOOTX64.EFI   = this directory's compiler-host.NTASM1.EFI  (the launcher)
::/NTCORE.EFI             = this directory's compiler-core.NTASM1.EFI
::/NTASM1.NTASM           = the source under test
::/NTASM1.EFI             = written by the producer, then read back and compared
```

QEMU line, per case, verbatim from the replay that established this:

```
qemu-system-x86_64 -machine q35,accel=tcg -cpu max -m 256M
  -drive if=pflash,format=raw,unit=0,readonly=on,file=<edk2-x86_64-code.fd>
  -drive if=pflash,format=raw,unit=1,file=<copy of edk2-i386-vars.fd>
  -drive if=virtio,format=raw,file=<esp.raw, 32 MiB FAT16>
  -boot order=c,menu=off -nic none -display none
  -monitor tcp:PORT,server=on,wait=off
  -serial file:serial.log -d guest_errors -D qemu.log
  -no-reboot -no-shutdown
```

then HMP `quit` once `NG_NTASM_NATIVE_SCAN_OK` appears in `serial.log`.

**There is no committed replay script.** The driver that built the ESP was a
throwaway and was deleted. Do not expect to find one, and do not write an
instruction that cites one — describe the invocation and the layout, as above.

## Scope, stated so a clean run of two is not read as six

**Only these two components were replayed.** `module-host.ntasm`,
`native-lexer.ntasm`, `native-source.ntasm` and the rest of `legacy/ntasm-s0/`
were **not** replayed and are **not** claimed. A clean run of these two is not a
clean run of the S0 tree.

The trust root remains out of band. Generation 1's launcher came from `out/`;
these files are the *result*, not an independent input. Re-running proves
determinism and self-reproduction, not that the launcher is correct — by the
definition of a trust root.
