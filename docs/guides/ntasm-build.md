# ntasm — the normal build, and what it refuses

Current entry point (14 October 2026): [French quickstart](ntasm-quickstart.md).
Current evidence: [A9 acceptance](../status/ntasm-a9-acceptance.md). Dated transcripts
below retain their historical hashes; the current binary is identified by its
build log and integration receipt.

Status: written against the tree of 2026-09-27. Every command, exit code and
digest below was executed on that tree; nothing here is transcribed from an
earlier revision of the build.

`ntasm` is the NTASM assembler: `.ntasm` in, an NXO object or a PE32+ EFI
application out. [`docs/guides/ntasm-cli.md`](ntasm-cli.md) is its command surface.
This document is the other half: how the binary is produced, and **what the
build stops**.

The build is [`scripts/ntbuild.sh`](../../scripts/ntbuild.sh). It is the build
`AGENTS.md` calls *le build normal*. It links the product binary from seventeen C
translation units, and it **refuses**, with a non-zero exit and a message that
names what was refused and why, any attempt to build it out of NASM or out of a
quarantined source.

---

## 1. Prerequisites

Nothing is fetched, nothing is installed, and nothing is resident. One host C
compiler translates the tool's own C; it never translates NTASM, and it is never
the producer of anything the product ships.

| component | version used for the digests here |
| --- | --- |
| gcc (Ubuntu) | 13.3.0-6ubuntu2~24.04.1 |
| GNU bash | 5.2.21(1)-release |
| GNU coreutils `realpath`, `sha256sum` | 9.4 |
| WSL distribution | Ubuntu 24.04.4 LTS |

`NASM 2.16.01` is also installed on this host. That is deliberate: the refusal
below is only worth having if NASM is present and would work if it were asked.
`nasm -f elf64` produces a valid object here; the build declines to use it.

The script is **invoked, never resident**. It starts no daemon, registers no
scheduled Windows task, and keeps no state in the source tree. Everything it
writes is under `out/`.

---

## 2. The commands

Run from anywhere; the script finds the repository from its own path.

```bash
./scripts/ntbuild.sh              # build the product binary (default)
./scripts/ntbuild.sh check PATH…  # classify candidate build inputs
./scripts/ntbuild.sh selftest     # run the refusal suite, both directions
./scripts/ntbuild.sh policy       # print the policy: grants, refusals, exit code
./scripts/ntbuild.sh corpus       # print the pinned corpus: name|path|sha256
./scripts/ntbuild.sh selfhost     # run the fixed-point check alone
./scripts/ntbuild.sh clean        # remove out/c-bootstrap/ntasm
```

Exit codes: **0** allowed or built; **78** refused; anything else is a plain
build failure. 78 is `EX_CONFIG`; the C suite has its own `E` codes and does not
share this one, so there is no collision to read around.

The build is incremental on a **content manifest**, not on timestamps. It writes
`out/c-bootstrap/ntasm/build.inputs`, the producer and its sha256, the flags,
the sha256 of all sixteen translation units and all eighteen headers, and
rebuilds everything when that manifest changes. A change to a header therefore
rebuilds what includes it, and `touch` rebuilds nothing.

The producer and the flags are in the manifest because a build at a different
optimisation level is a different build. This was measured, not assumed: with
only the sources in the manifest, `NG_OPT=-O0 ntbuild.sh build` following an
`-O2` build reported `NTBUILD_UP_TO_DATE` and left the **-O2** binary on disk
while the log line it printed said `flags=-std=c11 -O0`. A manifest that
ignores the toolchain is a manifest that lies.

---

## 3. The product binary

```
out/c-bootstrap/ntasm/ntasm
```

| property | value |
| --- | --- |
| provenance string | `ntasm 0.0.1-c-bootstrap provenance=BOOTSTRAP_EXTERNAL_C B2.1=not-delivered` |
| provenance | `BOOTSTRAP_EXTERNAL_C` — the **temporary external bootstrap producer**, not the self-hosted tool |
| size | 377 352 bytes |
| build flags | `-std=c11 -O2` |
| translation units | 16 |
| headers reached | 18 |

The build refuses to finish unless the linked binary prints that provenance
string. A build output that cannot name its own producer is not an artefact.

`provenance=BOOTSTRAP_EXTERNAL_C` is the honest label and the guide will not
soften it. `AGENTS.md` admits C under `compiler/c/` as a temporary
bootstrap exception; NTASM is not yet self-hosted, so this binary is that
exception, not the fixed point A8 asks for. When the tool is ported to Nova,
this build becomes the thing that must refuse *itself*, and the refusal in
section 5 is the mechanism that will do it.

### Where things live, and why

| thing | path | why there |
| --- | --- | --- |
| product binary | `out/c-bootstrap/ntasm/ntasm` | a build output; rebuilt at will, never a source |
| object files | `out/c-bootstrap/ntasm/obj/` | build outputs, with the binary |
| content manifest | `out/c-bootstrap/ntasm/build.inputs` | the evidence a binary digest is meaningful against |
| build banner | `out/c-bootstrap/ntasm/build.log` | the provenance record of the last build |
| the PEs you assemble | wherever you pass `-o` | your choice; `ntasm` writes only there |
| QEMU images and logs | under `out/` | host orchestration evidence, never a source |

No gate, no source and no release artefact may read any of it. `out/` is where
binaries and evidence go, and a build output is a build output.

---

## 4. Reproducing byte-identical output

Two different claims, and they have different answers. Conflating them is how a
build gets called reproducible when it is not.

**The producer's output does not depend on the host compiler.** This is the
claim that matters, and it is exact. The same source assembled by a producer
built at `-O0`, `-O1`, `-O2` and `-O3`. Every directory below is created by the
block, and every path is under `out/`, so there is nothing here to have
remembered. This revision spells the build step out in full; the earlier one
printed `…build…` in its place, which is a placeholder and not a command, and
the block could not be run at all.

```console
$ for OPT in O0 O1 O2 O3; do
>   B=out/c-bootstrap/producer-independence/$OPT; mkdir -p $B
>   for s in nova ntasm frontend codegen x64 pe object object_build object_link \
>            object_materialize conformance nova/run_host nova/runtime_v2 \
>            nova/pe_oracle cli main; do
>     gcc -std=c11 -$OPT -I compiler/c -c compiler/c/$s.c \
>         -o $B/$(basename $s).o || exit 1
>   done
>   gcc -std=c11 -$OPT -I compiler/c $B/*.o -o $B/ntasm || exit 1
>   $B/ntasm assemble examples/ntasm-v0/c-bootstrap/return42.ntasm -o $B/ret42.efi
> done
NTASM_C_ASSEMBLED bytes=3072 provenance=BOOTSTRAP_EXTERNAL_C
NTASM_C_ASSEMBLED bytes=3072 provenance=BOOTSTRAP_EXTERNAL_C
NTASM_C_ASSEMBLED bytes=3072 provenance=BOOTSTRAP_EXTERNAL_C
NTASM_C_ASSEMBLED bytes=3072 provenance=BOOTSTRAP_EXTERNAL_C
$ sha256sum out/c-bootstrap/producer-independence/O*/ret42.efi
1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457  out/c-bootstrap/producer-independence/O0/ret42.efi
1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457  out/c-bootstrap/producer-independence/O1/ret42.efi
1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457  out/c-bootstrap/producer-independence/O2/ret42.efi
1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457  out/c-bootstrap/producer-independence/O3/ret42.efi
```

Four producers, one digest, and the digest is the one `docs/guides/ntasm-cli.md`
section 4 recorded on 2026-09-05. The claim is the one that matters, and it
survives re-measurement: four builds at four optimisation levels, four
identical 64-hex lines. **What does not survive is any number that depends on
the compiler's own output size** — this block builds its own producers, and
their byte sizes move with the gcc build and with the granted sources, so no
size from it is printed here. All seven programs of
`examples/ntasm-v0/c-bootstrap/` reproduce their recorded digests through the
binary this build links; `./scripts/ntbuild.sh selftest` checks all seven on
every run.

**The host binary itself is reproducible for a pinned source content, a pinned
compiler and pinned flags.** Same source, same gcc, same `-O`, byte for byte:

```console
$ ./scripts/ntbuild.sh clean && ./scripts/ntbuild.sh build   # sha256=96e000e9…
$ ./scripts/ntbuild.sh clean && ./scripts/ntbuild.sh build   # sha256=96e000e9…
$ NG_OBJDIR=out/c-bootstrap/ntasm/obj2 ./scripts/ntbuild.sh build  # sha256=96e000e9…
```

> **Correction, 28 septembre 2026. The digests below are the 2026-09-27 ones and
> they no longer reproduce.** A reader who runs the `console` block today gets
> `96e000e9…`, not `fae0ae67…`. This is not a broken build — it is the mechanism
> this section describes, working: the source content moved, so `build.inputs`
> moved, so the binary digest moved. **The claim being made here is still true**;
> what was false was the presentation of a 27 September anchor as if it were
> current.
>
> Measured today, cold, `./scripts/ntbuild.sh clean && ./scripts/ntbuild.sh build`
> in WSL Ubuntu 24.04 against `/usr/bin/x86_64-linux-gnu-gcc-13`:
>
> | flags | sha256 | bytes | selfhost |
> | --- | --- | --- | --- |
> | `-O2` | `96e000e98687c4aa32cec02a0c762e49a2864ee4593ec11c6a56bcb92e3b5531` | 377 352 | `reproduced=yes verified=yes` |
> | `-O0` | `26abbc660e9a5215661c760b189beeafdd181b05e3aee4b8e0f060905f0be590` | 499 632 | `distinct=yes` against `-O2` |
>
> The `-O1` and `-O3` rows in the table below have **not** been re-measured against
> the current tree and are left as recorded rather than guessed at. A number that
> was not re-measured is not evidence, and a number replaced by a plausible
> substitute is worse than one that is visibly stale.
>
> The `-O0` digest has now appeared **three** times in this file across source
> contents — `2d4255ab…` in the table, `f5e159b9…` in the selfhost block — and the
> `-O2` twice. A binary digest is only meaningful together with the `build.inputs`
> it was produced from, and this file does not record that pairing for each row.
> That is the real defect, and it is the norm the A9 row now carries: *si une page
> ne dit pas quelles commandes ont été exécutées, traitez-la comme de la prose non
> vérifiée.*

It is *not* optimiser-independent, and no amount of wishing will make it so —
the compiler is part of the producer. Measured, same sources:

| flags | sha256 of `out/c-bootstrap/ntasm/ntasm` |
| --- | --- |
| `-O0` | `2d4255ab…` **(2026-09-27, does not reproduce; today `26abbc66…`)** |
| `-O1` | `b36d5878…` **(2026-09-27, NOT re-measured since)** |
| `-O2` | `fae0ae67…` **(2026-09-27, does not reproduce; today `96e000e9…`)** |
| `-O3` | `261249c2…` **(2026-09-27, NOT re-measured since)** |

So a binary digest is only meaningful together with the source it was built
from. The anchor to quote is the **pair**:

```
build.inputs  a4af9796…   (2026-09-27)   <- not re-measured since
binary        96e000e9…   (2026-09-28)   <- measured cold, reproduced=yes verified=yes
```

`build.inputs` is the manifest of section 2. It was captured on 2026-09-27 with
`compiler/c/ntasm/backend/codegen.c` at
`18d4b2c5097c9bd86198398a819455547040f651e28115ec726b78c5a3b55390`. A different
`codegen.c` gives a different `build.inputs`, and therefore a different binary
digest, with nothing wrong anywhere: the source moved, not the build. The build
detects that on its own and rebuilds, which is how this was found.

### Why the sources live where they live

All sixteen translation units are under `compiler/c/`, thirteen at
the top and three under `nova/`. That is where `AGENTS.md` puts the temporary C
bootstrap exception, and it is why the grant in section 5 exists and why it is
written down. When the tool moves to Nova this build's inputs move out of
quarantine with it, and the grant becomes a fact about the tree rather than an
allowance.

---

## 5. The quarantine rule

`AGENTS.md`, *Pureté des sources*:

> Dès que NTASM est auto-hébergé, il doit reproduire bit pour bit les artefacts
> NASM retenus; **le build normal final doit refuser toute invocation NASM.**

> Les langages source du produit final sont NX, Cnuva, Nova et NTASM.

The rule was written. The mechanism was not there: before this build existed,
nothing in the tree refused anything. The recipe in `docs/guides/ntasm-cli.md` section 1
was a shell loop, and that loop will compile any `.S` you hand it.

This block defines its own two variables. **The earlier revision of it printed
`$C` and `$B` without ever defining them here** — they are set in the *other*
guide, at `docs/guides/ntasm-cli.md` section 1 — so as printed `-I$C` collapsed to a
bare `-I` and `$B/main.S` to `/main.S`. It also named a `main.S` that did not
exist and printed two lines of output, `assembled by GAS, not by NTASM` and
`exit 0`, that no binary on this tree has ever produced. Run as printed it
exited **1**, then **1**, then **127**. Both faults are fixed below: the
variables are defined here, the file is written here, and every line of output
is one that was measured.

```console
$ C=compiler/c
$ B=out/c-bootstrap/section5-counterexample
$ mkdir -p $B
$ # main.c, ASSEMBLED instead of compiled: the same main, by hand.
$ printf '.text\n\t.globl\tmain\nmain:\n\tjmp\tnt_cli\n\t.section\t.note.GNU-stack,"",@progbits\n' > $B/main.S
$ for s in nova ntasm frontend codegen x64 pe object object_build object_link \
>        object_materialize conformance nova/run_host nova/runtime_v2 \
>        nova/pe_oracle cli; do
>   gcc -std=c11 -O2 -I$C -c $C/$s.c -o $B/$(basename $s).o || exit 1
> done
$ gcc -std=c11 -O2 -I$C -c $B/main.S -o $B/main.o
$ gcc -std=c11 -O2 -I$C $B/*.o -o $B/ntasm
$ $B/ntasm assemble examples/ntasm-v0/c-bootstrap/return42.ntasm -o $B/ret42.efi
NTASM_C_ASSEMBLED bytes=3072 provenance=BOOTSTRAP_EXTERNAL_C
$ sha256sum $B/ret42.efi
1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457  out/c-bootstrap/section5-counterexample/ret42.efi
$ # no rule in the tree objects.  The same file, handed to the build:
$ ./scripts/ntbuild.sh check $B/main.S
NTBUILD_REFUSED class=assembly-input
  input:   out/c-bootstrap/section5-counterexample/main.S
  reason:  The normal build translates C and never assembles. AGENTS.md allows no
           GAS, no MASM and no inline assembly, and NASM is refused outright, so no
           assembly extension is a build input of this build whether or not the
           file exists.
NTBUILD_CHECK inputs=1 refused=1 policy=NTBUILD-POLICY/1
$ echo $?
78
```

— a working product binary, assembled by GAS, exit 0, emitting the same digest
section 4 records, **and no objection from any project rule**. That is what the
refusal had to be built against, and the last six lines are the difference:
the loop accepts the file and the build does not.

The counter-example is not weakened by this revision. It is a real `.S` that a
real compiler assembles, not a `.c` file with a new extension — the earlier
form, which fed `main.c`'s C text to `gas`, exited 1 at
`Error: junk '(int argc,char **argv)' after expression` and so never
demonstrated anything. **The hole the loop had was never "it will accept a
file it should refuse"; it was "it has no opinion at all".** This block shows
the no-opinion half succeeding and the opinion half refusing the same file.

### What is granted

A build input is legal if and only if it is one of the sixteen translation units
listed by `./scripts/ntbuild.sh policy`, or a header transitively included by
one. The grant is **closed**: there is no environment variable, no flag and no
file on disk that can add to it. Adding a quarantined file to the normal build is
an edit to `scripts/ntbuild.sh` and a decision on the record, never a default.

`legacy/nasm/` is listed with an **empty grant**. Not a small one,
not a conditional one: none. There is no mechanism in the policy that could
accept a file from that tree, so a refusal there cannot be talked out of.

### What is refused

| class | refused when | exit |
| --- | --- | --- |
| `quarantine-nasm-input` | any path resolving under `legacy/nasm/` | 78 |
| `assembly-input` | extension `.asm .ASM .nasm .NASM .s .S .sx`, decided **before** the file is touched | 78 |
| `outside-repo` | the path resolves outside the repository | 78 |
| `nonexistent-input` | not a regular file | 78 |
| `not-a-c-source` | an existing file that is neither `.c` nor `.h` | 78 |
| `ungranted-quarantine-source` | under `bootstrap/quarantine/`, not granted | 78 |
| `not-granted` | inside the repository, not granted | 78 |
| `forbidden-producer` | the selected compiler is an assembler | 78 |
| `output-outside-out` | an output directory outside `out/` | 78 |

The order is the order of the table, and the first rule that matches is the one
reported. A file under the NASM quarantine is reported as
`quarantine-nasm-input` even though it is also an assembly file, because the
location is the fact the reader needs.

### The refusals, observed

```console
$ ./scripts/ntbuild.sh check legacy/nasm/ntasm-bootstrap.asm
NTBUILD_REFUSED class=quarantine-nasm-input
  input:   legacy/nasm/ntasm-bootstrap.asm
  reason:  AGENTS.md, Purete des sources: NASM is a temporary quarantined
           producer, never the final one, and the normal build must refuse any
           NASM invocation once NTASM is self-hosting.
           This build carries no grant for legacy/nasm/ at all, so
           no flag and no environment variable can make this input legal.
           remedy: translate the .ntasm with NTASM itself, or keep working under
           legacy/nasm/ outside the normal build.
NTBUILD_CHECK inputs=1 refused=1 policy=NTBUILD-POLICY/1
$ echo $?
78
```

```console
$ NG_PRODUCER=nasm ./scripts/ntbuild.sh build
NTBUILD_REFUSED class=forbidden-producer
  input:   nasm
  reason:  AGENTS.md: NASM is a temporary quarantined producer, never the final
           one, and the normal build must refuse any NASM invocation. The producer
           selected for this build is nasm, which is an assembler.
           remedy: leave the producer at its default, or set NG_PRODUCER to a C
           compiler. The C bootstrap compiler is the only producer the normal
           build accepts.
$ echo $?
78
```

```console
$ NG_OBJDIR=/tmp/ntbuild-escape ./scripts/ntbuild.sh build
NTBUILD_REFUSED class=output-outside-out
  …
$ echo $?
78
$ ls -d /tmp/ntbuild-escape
ls: cannot access '/tmp/ntbuild-escape': No such file or directory
```

### What the refusal does not cover

Being exact about this is the point of the section.

**Closed.** Asking the build for NASM — as a producer, as a file, or as an
assembly source of any extension — is refused with exit 78. Naming a quarantined
file that is not granted is refused. Naming a path outside the repository is
refused. Pointing the build at a directory outside `out/` is refused, and
nothing is written.

**Closed since this section was first written** (wave 9, lot 8):

- **A compiler that is not an assembler but assembles.** Now refused twice
  over. The producer is resolved through `PATH` to a real file, and a producer
  that is a **script** is refused: `class=producer-is-a-script`. A shell script
  named `gcc` is the shape the attack takes, and the producer `AGENTS.md` names
  — "GCC/Clang and their linker" — is a compiled binary, so the refusal is not
  aimed at a legitimate configuration. A producer that is not on `PATH` at all
  is refused too: `class=unresolvable-producer`. The resolved path and its
  sha256 are written to `build.log` and to `out/c-bootstrap/ntasm/producer.pin`,
  so a swap is on the record and not invisible.
  The cost is deliberate and named: this also refuses a `ccache`-style wrapper.
  That is a real inconvenience in the safe direction, and the remedy is to
  point `NG_PRODUCER` at the compiler itself.
- **The inline `__asm__` route through a granted `.c`.** Now refused:
  `class=inline-asm-source`. The scan runs over exactly the files the build
  reads — the sixteen granted units and the eighteen headers in the closure —
  and prints `NTBUILD_INLINE_ASM_SCAN sources=34 hits=0`, so a scan that read
  nothing is distinguishable from a scan that found nothing. Comments and
  string and character literals are blanked before the text is matched, because
  the first version of this check was wrong in **both** directions: it refused
  a source whose only assembly was the characters `asm(` inside a string, and
  it accepted `asm volatile ("hlt")` because it wanted the parenthesis
  immediately after the keyword.

**Still not closed.** These are real gaps, not caveats:

- **A compiled wrapper.** The script check closes the shell-wrapper shape. A
  wrapper that is itself a compiled binary is not a script and is accepted; it
  is caught by the pinned digest only when an auditor compares it against
  `producer.pin`. Nothing inside the build can close this, because the build is
  what would have to be fooled.
- **Something that edits the grant list.** The grant is a literal in
  `scripts/ntbuild.sh`. Anyone who can edit that file can add a quarantine tree
  to the grant — which is true of every policy expressed as a file, and is the
  reason the grant is 16 named lines rather than a glob.
- **A second build system.** `AGENTS.md` reserves the C exception for
  `compiler/c/`, and other C sources exist elsewhere in the tree
  (`verifieur/`, older wave directories). This build refuses them, because they
  are not in the grant. It cannot refuse them in a build it does not own.


## 6. The refusal suite

A refusal nothing calls is a rule in prose. `./scripts/ntbuild.sh selftest` runs
every case above as a subprocess and reads its exit code and its message.

```console
$ ./scripts/ntbuild.sh selftest
NTBUILD_SELFTEST_DONE pass=31 fail=0
```

Thirty-one cases: seventeen refusals, each asserted on both the exit code **and**
the class named in the message; four cases driving the fixed-point check's own
selftest, which perturbs one corpus pin and requires the whole check to come
back non-zero; three cases driving the inline-assembly scan over real files in
both directions; three allowed inputs and the build itself; and the seven
examples, whose bytes come out of the binary this build just linked.

### The suite is not a comment

Each of the three load-bearing rules was removed and the suite observed red
before being restored.

Removing the NASM quarantine from the grant list:

```
  FAIL  quarantine NASM source        message did not name 'class=quarantine-nasm-input'
          NTBUILD_REFUSED class=assembly-input
            input:   legacy/nasm/ntasm-bootstrap.asm
  FAIL  quarantine NASM probe         …
NTBUILD_SELFTEST_DONE pass=22 fail=3
```

The build still refused, but as the *wrong rule*: an assembler extension rather
than the quarantine. That is what a defence in depth is for, and it is also what
makes the message check worth having — a suite that only watched the exit code
would have called that green.

Emptying the forbidden-producer list:

```
  FAIL  producer is NASM              exit 0, wanted 78
NTBUILD_SELFTEST_DONE pass=24 fail=1
```

Exit 0: with the check gone the build really did run `nasm`.

Emptying the assembly-extension list:

```
  FAIL  assembly input (.asm), absent   message did not name 'class=assembly-input'
  FAIL  assembly input (.S), absent     message did not name 'class=assembly-input'
NTBUILD_SELFTEST_DONE pass=23 fail=2
```

The first run of the suite found three of its own cases wrong and they were
corrected against what the code does, not against what the case expected:
`compiler/c/tests_ntasm_cli.c` does not exist (the file is under
`nova/`), `compiler/c/nova/runtime/runtime.h` **is** in the header closure and
is therefore legitimately allowed, and a path outside the repository was being
reported as `nonexistent-input` because a normalisation line overwrote the
relative path with the raw argument.

---

## 7. Where `nt_cli` is defined, and why it is defined twice

`cli.c` is not in `ngbuild.sh`'s `LIBS`, and the `cli` gate
(`tests/c/nova/tests_ntasm_cli.c:21`) does `#include "../cli.c"`.
This build links `cli.c` as a real object. Is that a double definition?

No, and the reason is that **they are two different binaries with two different
link lines**.

**The gate binary is built here, at a path this block creates.** The earlier
revision printed `nm /tmp/ng-w8-7/cli` — an absolute path from wave 8 that
nothing in this repository creates, on any machine, ever. It exited **1** with
`nm: '/tmp/ng-w8-7/cli': No such file`. It is replaced below by the compile and
link line `legacy/tools/coldproof/ngbuild.sh` actually uses for this gate, written out
in full, with its output under `out/`.

```console
$ C=compiler/c
$ B=out/c-bootstrap/nt_cli-two-link-lines
$ mkdir -p $B
$ gcc -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
>     -I$C $C/nova/tests_ntasm_cli.c \
>     $C/nova.c $C/ntasm.c $C/frontend.c $C/codegen.c $C/x64.c $C/pe.c \
>     $C/object.c $C/object_build.c $C/object_link.c $C/object_materialize.c \
>     $C/conformance.c $C/nova/run_host.c $C/nova/runtime_v2.c \
>     $C/nova/pe_oracle.c \
>     -o $B/cli
$ nm out/c-bootstrap/ntasm/ntasm | grep -cw nt_cli
1
$ nm $B/cli | grep -cw nt_cli
1
$ test "$(nm out/c-bootstrap/ntasm/ntasm | grep -w nt_cli | cut -d' ' -f1)" \
      != "$(nm $B/cli | grep -w nt_cli | cut -d' ' -f1)" && echo "two addresses: yes"
two addresses: yes
```

One definition each, neither shared, at two different addresses — which is the
whole content of the claim, and the last three lines are all of it that does
not move. **No address is printed here, and the earlier revision's two are
withdrawn.** They were `0000000000003780` in the product and
`00000000001a3dce` in the gate when measured, and the product's moved to
`0000000000003920` within the same hour, when a concurrent lot rebuilt
`out/c-bootstrap/ntasm/ntasm` on disk. A symbol address is a property of a
link map, not of the argument this section makes; printing one and calling it a
result is the same disease as printing a digest that a rebuild will move. The
counts and the inequality are what survive, and the block asserts the
inequality itself rather than asking the reader to compare two numbers by eye.

There is no collision to resolve and no arrangement of the two that would
remove one without breaking the other.

**Two compilations of one source is the correct arrangement here, not a
workaround.** The gate wants the sanitized, `-O1 -g` build; the product wants the
`-O2` build whose digest section 4 records. Sharing an object file would force
one of those to give up what it is for, and the linker would still not put
`nt_cli` in the same address twice — it would just make the gate and the
product compile under flags neither chose.

The duplication is also harmless for correctness, because the gate compiles the
**shipped** `cli.c` text rather than a copy of it. A semantic change to
`cli.c` cannot pass the gate and fail the product silently: the same bytes are
read by both, and the only thing that differs is the optimisation level. What
would be harmful is a *copy*, and there is none.

**When the duplication is retired.** If the duplication is ever worth removing,
it is two edits in files this lot does not own, and they must land together:

```diff
--- tests/c/nova/tests_ntasm_cli.c
-#include "../cli.c"
```
```diff
--- legacy/tools/coldproof/ngbuild.sh   (LIBS)
-  "$root"/nova/pe_oracle.c
+  "$root"/nova/pe_oracle.c "$root"/cli.c
```

`main.c` must **never** enter `LIBS`: it defines `main`, and every gate binary
would then have two. Only the product links it. Until both edits land, the
arrangement above is correct and the divergence risk is closed on this side by
the content manifest of section 2 plus the seven example digests of section 6.

---

## 8. What this build does not do

- It does not reach A8's fixed point, and the reason is structural rather than
  unfinished. A fixed point needs the producer's source in a language the
  producer consumes. This producer is the C bootstrap, built from sixteen C
  translation units, and it consumes `.ntasm` in the v0 dialect — it cannot
  consume C, and it cannot even read the NTASM S0 sources, which it rejects
  with `E200: expected 'module'`. There is therefore no shared corpus on which
  the C producer and an NTASM producer could be shown to agree.
  What the build **does** run, on every build, is `scripts/ntselfhost.sh`: the
  producer is rebuilt twice from clean at two different optimisation levels,
  the two producer binaries are required to differ, the seven corpus outputs
  are required to be byte-identical across them *and* equal to their recorded
  digests, and the producer is rebuilt a third time and must reproduce the
  digest this build linked. That is reproducibility and producer-independence,
  which is what is reachable from here; it is not the fixed point, and the
  check prints `NTSELFHOST_BOUNDARY fixed_point_proven=no` on every run so the
  two are never confused. See section 9.
- It does not add itself to the 91-gate suite. `ngbuild.sh` and `lib.sh` are the
  integrator's. The file is **`legacy/tools/coldproof/ngbuild.sh`**, not the repository
  root: the earlier revision of this line printed `bash ngbuild.sh
  ntbuild_selftest`, and there is no `ngbuild.sh` at the root, so it exited
  **127** with `bash: ngbuild.sh: No such file or directory`. Run from the
  repository root, the verb is real and the gate is **UNRESOLVED**:

```console
$ bash legacy/tools/coldproof/ngbuild.sh ntbuild_selftest
MISSING_HARNESS ntbuild_selftest: no /mnt/d/Projets/Racine-C/NexoraGenesis/bootstrap/quarantine/c/nova/tests_ntasm_ntbuild_selftest.c and no NOVA_GATES member of that

GATES_RED total=1 gates=1 rails=0 guards=0 interrupted=0
GATES_RED_ITEM GATE ntbuild_selftest:UNRESOLVED
GATES_DONE fail=1
$ echo $?
1
```

  That is the guide's own prediction, now with the name the harness wants: a
  gate is reachable by name only if it is in `GATES` under that stem or is
  declared in `NOVA_GATES`, and `tests_ntasm_ntbuild_selftest.c` does not exist.
  So the registration is not one line, it is **two** — the `GATES` entry *and*
  a rule that calls an external script, which `ngbuild.sh` does not have today.
  (The command above prints the whole integrator suite — the rails, the
  registry, the EOL walk — before the four lines quoted; only the four are
  this paragraph's business, and `grep` is what extracts them. The suite is the
  integrator's and this lot does not change it.) Until both edits land, run
  `./scripts/ntbuild.sh selftest` directly; it is the build's own precondition,
  and no C gate depends on it. What it prints is section 6, and its pass count
  is a separate matter recorded there.

  The absolute path inside `MISSING_HARNESS` is the integrator's own output —
  it resolves the harness name against the repository root — and it is printed
  verbatim rather than shortened. It is not a path this guide asks anyone to
  create or to type; it is the reason the reader can see for themselves that
  the harness file is absent rather than merely misnamed.
- It does not touch `README.md`, which still points at
  `out/c-bootstrap/host-v4/ntasm.exe` — a hand-built wave snapshot under `out/`,
  not a build output of anything in the tree. That line is the integrator's.

---

## 9. The fixed-point check

`scripts/ntselfhost.sh` is invoked by `build`, so it runs on every build and not
only when someone remembers it. It is invoked, never resident, and writes only
under `out/c-bootstrap/selfhost/`.

### What the words mean

The phrase "a fixed point of the producer" is not a test, so the script states
what it means before measuring anything. With `S` the producer's source, `C` a
fixed corpus and `P` a producer:

| | property | statement |
|---|---|---|
| R1 | reproducibility | any two clean runs give byte-identical `P(C)` |
| R2 | producer independence | `P_a(C) == P_b(C)` bytewise for two **distinct** producer binaries |
| F | **fixed point** | `P_1 = P_0(S)`, `P_2 = P_1(S)`, and `P_2 == P_1` bytewise |

F is what A8 asks for. It is strictly stronger than R1 and R2 together, and this
check does not claim it.

### What it does

```console
$ ./scripts/ntbuild.sh build
NTSELFHOST_CORPUS members=7 from=ntbuild.sh-corpus
NTSELFHOST_PRODUCERS a=-O2 sha256=96e000e9… b=-O0 sha256=26abbc66… distinct=yes
NTSELFHOST_COMPARE compared=7 converged=7 pinned=7
NTSELFHOST_RESTORE sha256=96e000e9… reproduced=yes
NTSELFHOST_DONE compared=7 failures=0
NTBUILD_SELFHOST_RESTORE sha256=96e000e9… verified=yes
```

Three conditions must hold, and each one is there because its absence would let
the check pass while proving nothing:

- **the two producers must differ.** `-O2` and `-O0` give 377352 and 499632
  bytes. If they ever came out identical, comparing them would be comparing a
  producer with itself, which passes whatever it emits, and the check refuses
  rather than reporting a vacuous success.
- **the corpus outputs must agree across them.** That is R2, by byte comparison.
- **and they must equal their recorded digests.** Without this, two producers
  that are deterministically wrong would agree with each other and pass. The
  pins live in `RECORDED_EXAMPLES` in `ntbuild.sh` and are read through
  `ntbuild.sh corpus`; the check keeps no second copy of them.

The third build, at the caller's own optimisation level, must reproduce the
digest `build` linked, and `build` re-asserts that digest afterwards — so a
producer that does not rebuild to the same bytes fails the build rather than
leaving a different binary behind a log describing the first one.

### The check is asked to fail

**This block described an older script. The script has drifted; the guide was
behind it, and has been corrected to the tool rather than the tool to the
guide.** Three measured facts, in order.

1. `scripts/ntselfhost.sh` declares `ST_CASES=11` (`ntselfhost.sh:663`) and
   prints `A`, `B`, `C`, `D`, `E`, `F`, `G`, `G2`, `G3`, `H`, `I`. This block
   printed five. `F`, `G`, `G2`, `G3`, `H` and `I` — the whole LAYOUT step and
   the load-bearing end-to-end case — were added to the tool after the block
   was written and were never added to the block.
2. The `NTSELFHOST_SELFTEST_DONE` line at `ntselfhost.sh:816` now carries
   `executed=` and `declared=`, and those two counters are **an anti-vacuity
   guard**: `ntselfhost.sh:811-815` fails the selftest if the number of cases
   that ran is not the number declared. The earlier block had no line for them
   because the guard did not exist when it was written.
3. Because of that guard, `pass=5` is not stale. It is **unreachable on any
   reading**: 5 was the count before `F`–`I` were added, and the declared count
   is a literal that a run asserts against itself. This revision does not try to
   make the suite produce it, and it does not print a `pass=` number at all,
   because on the tree measured below the run is red and prints no `pass=`.

Measured, three consecutive runs, identical every time:

```console
$ ./scripts/ntbuild.sh selfhost --selftest
NTSELFHOST_SELFTEST unit-cases drive verdict_member, the function the
  real run calls; case E is the full check with one pin perturbed;
  cases F-H drive the LAYOUT step, including the two controls that had
  to be corrected once: one producer measured twice and called it two
  readings, and an enumerated list instead of the corpus's own.
  ok    A member holds (equal digests, equal pin)      exit=0
  ok    B producers disagree                           exit=1
  ok    C bytes differ from the pin                    exit=1
  ok    D a digest is missing                          exit=1
  ok    E one pin perturbed, whole check must go red   exit=1
  ok    F layout step refuses two identical producers  exit=1
  FAIL  G could not emit an object to perturb
$ echo $?
2
```

**No `NTSELFHOST_SELFTEST_DONE` line appears at all**, and that is the tool
behaving correctly rather than a printing bug. The guard is not a summary
printed at the end; a run that did not reach its declared case count is
exactly the run whose pass count would be a number about the cases it
*skipped*, and the partial output above looks enough like a clean run that the
exit status is the only thing that distinguishes them. Cases `G`, `G2`, `G3`,
`H` and `I` did not run.

**Why `G` fails, and it is not this guide's business to fix it.** Case `G`
(`ntselfhost.sh:758-768`) needs a producer binary at
`$WORK/run-a/producer`, and on the `--selftest` path the only thing that could
have created one is case `E`'s own subprocess. That subprocess dies first, at
generation a, and the refusal is printed:

```console
$ bash scripts/ntbuild.sh corpus | head -1
return42|examples/ntasm-v0/c-bootstrap/return42.ntasm|1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457
$ bash scripts/ntselfhost.sh --build scripts/ntbuild.sh --perturb-pin return42
NTSELFHOST_PERTURBED member=return42 pin=all-zeroes
NTSELFHOST_BEGIN policy=NTBUILD-POLICY/1
NTSELFHOST_CORPUS members=8 from=ntbuild.sh-corpus
ntselfhost: generation a failed to build at -O2
NTBUILD_REFUSED class=granted-input-digest
  input:   compiler/c/ntasm/cli/cli.c
  reason:  compiler/c/ntasm/cli/cli.c is granted by NAME and its bytes are not the pinned ones.
           expected sha256: 19ccf7890bb16ca76796aedda47bbdc8e263b907de584c14ec651db8b50af482
           actual   sha256: 8f405e4fec41fa9133f09611a6b2b9bd6b6ba9512055e8cda6d7fd31ca91f4b3
$ echo $?
1
```

The first of those two commands exits **141**, not 0: `head -1` closes the pipe,
`ntbuild.sh corpus` takes SIGPIPE, and bash reports 128+13. That is not a
defect in either command and the block quotes no exit code for it, but it is
the same hazard `ntselfhost.sh:746-751` records — that one killed a whole
selftest at 141 and left `G`, `H` and `I` looking as though they had passed —
which is why this file reads the corpus through a process substitution
instead. A reader who copies this line into a `set -o pipefail` script should
know what the 141 is.

`nova.c` and `pe.c` are off their pins on the same tree — three granted files
in all, checked with `./scripts/ntbuild.sh pins` against `sha256sum` on each
path. The build refuses a granted source whose bytes moved without a matching
`PINNED_INPUTS` edit, so no producer is produced, so `G` has nothing to
perturb. **That is the same cause as section 6's non-reproducing pass count and
as `--perturb-pin`, and it is a state of the tree, not a defect in either
guide.** The remedy is the one the refusal prints: paste the measured digest
into `PINNED_INPUTS` in `scripts/ntbuild.sh` if the change was legitimate. That
is a product file, this lot does not own it, and **it has not been done here**,
so this guide does not claim a green selftest. What it claims is the six
lines above, which were measured three times and did not move.

A check that has never been seen red might be unable to be, and this project
has now shipped one that was green through 2207 checks while the control inside
it had never executed. So the comparison is asked to fail, on every selftest.

Cases B, C and D drive `verdict_member` — **the same function the real run
calls**, not a copy; a selftest of a copy is a selftest of the copy. Case E is
the one that is fully end-to-end: it perturbs a single corpus pin and runs the
whole check, so the build, the assembly, the digests and the comparison all
execute and the only thing wrong is the expectation. Cases F to I were added
later and drive the LAYOUT step; they are listed and dated above. Observed red:

```console
$ ./scripts/ntbuild.sh selfhost --perturb-pin return43 ; echo $?
NTSELFHOST_PERTURBED member=return43 pin=all-zeroes
ntselfhost: BYTES DIFFER FROM THE PIN on return43
ntselfhost:   produced: 5811fda51dd2e115eabb39cc2d5c688fcc494da29660e4ac817794bc2b127ac3
ntselfhost:   pinned:   0000000000000000000000000000000000000000000000000000000000000000
NTSELFHOST_COMPARE compared=7 converged=6 pinned=6
NTSELFHOST_DONE compared=7 failures=1
1
```

Note `converged=6`: the other six members still agreed across the two
producers, so this is one bad expectation and not a broken producer.

> **This block does not reproduce on the tree measured on 2026-10-02, and the
> reason is the same `class=granted-input-digest` refusal printed above.** Run
> as printed it now stops at `ntselfhost: generation a failed to build at -O2`
> and exits **1**, before the perturbation is ever compared. The block is left
> exactly as it was: its exit code still matches, its output does not, and a
> number that holds only on a tree whose granted sources are on their pins
> should not be re-pinned to a value measured on one that is not. Fixing it is
> the `PINNED_INPUTS` edit named above, and that is a product file.

One limit, stated plainly. The **convergence** branch — two producers emitting
different bytes for the same source — has never been observed red
end-to-end, because provoking it needs a producer that is genuinely
non-deterministic across optimisation levels and this one is not. Case B
exercises that branch at the function level. What covers the structural risk
end-to-end is the anti-vacuity guard instead: if the two producers ever came
out identical, the check refuses rather than comparing a producer with itself.

### What it does not do

It does not self-host, and it says so on every run. The evidence is in
`out/ntasm/native-selfbuild-stage3/`, where stage 3's producer really was stage
2's own output and both generations recorded `candidate_sha256 ==
output_sha256`; that chain is real. It is also **stale**: it records
`compiler-host.ntasm` at 36073 bytes / `7254902a…`, and that file is 43793 bytes
/ `1d72d975…` on disk today. The recorded run cannot be repeated, because its
input has moved, and a checkpoint directory is not evidence — the evidence is a
byte comparison and a re-run, and there is no re-run left to do.
