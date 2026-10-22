# ntasm — the NTASM command line, end to end

Current entry point (14 October 2026): [French quickstart](ntasm-quickstart.md).
Current evidence: [A9 acceptance](../status/ntasm-a9-acceptance.md). Dated transcripts
below retain their historical hashes; the current binary is identified by its
build log and integration receipt.

Status: written against the tree of 2026-09-27, **re-executed end to end on
2026-09-28** after section 1 was rewritten around the real build. Every
command, every exit code and every digest below was executed on the tree
named next to it; nothing here is transcribed from an earlier revision of the
tool. Where a run is quoted, its output directory is named with it.

What the gate does and does not police: it reads the fenced blocks of this
file, runs them, and fails when the code and this text disagree. It covers the
worked example, the seven single-module examples of section 4, the exit codes
and the option surface. **The multi-module example in section 4.1 is separate from this gate.**
As of 14 October 2026, the gate checks the single-module example directory in
both directions: seven promised files plus the named call-private-stmt.ntasm
experiment, with controls for an unlisted file and a missing file. The full
corpus census remains `bash scripts/ntbuild.sh census` (section 4).

`ntasm` is the NTASM assembler. It reads `.ntasm` source, emits an NXO object or
a PE32+ EFI application, and describes either back. It is written in C under
`compiler/c/` and is the **external bootstrap producer**
(`provenance=BOOTSTRAP_EXTERNAL_C`), not the final self-hosted tool. Nova is the
target it is being ported to; this guide describes the C tool as it exists now.

The gate `tests/c/nova/tests_ntasm_cli.c` checks this guide
against the binary: it extracts the blocks below, runs the commands, and fails
if the code and this text disagree.

---

## 1. Building the binary

There is no binary checked in, and there is a build. Use it. `scripts/ntbuild.sh`
is the build `AGENTS.md` calls "le build normal": it compiles the sixteen
translation units of `compiler/c/`, links
`out/c-bootstrap/ntasm/ntasm`, and refuses — with exit 78 — to be fed NASM, a
quarantined source, an ungranted file, or a compiler that is an assembler or a
wrapper script.

```bash
bash scripts/ntbuild.sh clean      # remove out/c-bootstrap/ntasm
bash scripts/ntbuild.sh build      # compile, link, check, restore
```

`build` runs the fixed-point check itself, so the check is not something you
have to remember. The host C compiler compiles the tool's own C; it never
translates NTASM. The build refuses to finish unless the linked binary prints
`provenance=BOOTSTRAP_EXTERNAL_C`, and it restores that same binary afterwards
and re-asserts its digest. The full policy, the granted files and the twelve
refusal classes are in `docs/guides/ntasm-build.md`; the same policy, printed, is:

```bash
bash scripts/ntbuild.sh policy
```

On the tree of 2026-09-28 that build produced, from a directory that `clean`
had just removed:

```console
$ sha256sum out/c-bootstrap/ntasm/ntasm
96e000e98687c4aa32cec02a0c762e49a2864ee4593ec11c6a56bcb92e3b5531  out/c-bootstrap/ntasm/ntasm
```

377 352 bytes, built by `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1` at
`-std=c11 -O2`. **That digest is a property of the tree, not a constant.** It
moves whenever one of the sixteen units or eighteen headers moves, and this
repository is under active edit. Quote it only together with the source
revision it was built from. (`docs/guides/ntasm-build.md` carries a per-optimisation
digest table; on 2026-09-28 its `-O2` row did not reproduce and the divergence
is reported, not silently reconciled.)

### What the build does, if you need to do it by hand

The normal build is a loop over the same sixteen files. It is printed here
because the gate for this guide links the same fourteen compiler units plus the
same `cli.c` and `main.c`, and because the loop is the shortest way to see that
`main.c` is two lines and `cli.c` is the whole command surface.
**Prefer `ntbuild.sh`; this loop has no policy and no provenance check, and it
will happily overwrite the product binary without recording anything.**

```bash
C=compiler/c
B=/tmp/ntasm-build
mkdir -p $B out/c-bootstrap/ntasm
for s in nova ntasm frontend codegen x64 pe object object_build object_link \
         object_materialize conformance nova/run_host nova/runtime_v2 \
         nova/pe_oracle cli main; do
  gcc -std=c11 -O2 -I$C -c $C/$s.c -o $B/$(basename $s).o || exit 1
done
gcc -std=c11 -O2 -I$C $B/*.o -o out/c-bootstrap/ntasm/ntasm
```

`main.c` is two lines: it calls `nt_cli`. `cli.c` is
the whole command surface. The other fourteen are the compiler, the frontend,
the x86-64 backend, the PE writer and the NXO object codec; they are exactly
the fourteen the C gates link, so the tool and the oracle are the same code.
`$(basename $s)` matters: three of the sources live in the `nova/` subdirectory
and `-o $B/$s.o` would look for a subdirectory that does not exist.

Run on 2026-09-28 with `gcc` at the same `-O2`, this loop linked a binary whose
sha256 is `96e000e9…` — the value above. The hand loop and `ntbuild.sh` agree
on the bytes; they do not agree on how much is checked.

Verified toolchain, on which every digest in this guide was produced:

| component | version |
| --- | --- |
| gcc (Ubuntu) | 13.3.0-6ubuntu2~24.04.1 |
| qemu-system-x86_64 | 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.16) |
| OVMF | `/usr/share/OVMF/OVMF_CODE_4M.fd` (3 653 632 bytes), `OVMF_VARS_4M.fd` (540 672 bytes) |
| mtools | `mkfs.vfat`, `mmd`, `mcopy` (WSL Ubuntu 24.04) |

Artefacts this guide produces, and where they live:

- the product binary: `out/c-bootstrap/ntasm/ntasm` (a build output, rebuilt at
  will, never a source);
- the PEs you assemble: wherever you pass `-o`;
- the ESP image and serial log of a QEMU run: under `out/`, because a QEMU
  orchestration script is a host runner, never a source, a build input, a
  dependency or a release artefact.

---

## 2. The surface

The examples below write `ntasm` on its own. After section 1 the binary is at
`out/c-bootstrap/ntasm/ntasm`, so either put that directory on `PATH`:

```bash
export PATH="$PWD/out/c-bootstrap/ntasm:$PATH"
```

or replace `ntasm` with the full path. Nothing else in the guide depends on
which of the two you chose.

This is the verbatim output of `ntasm --help`. `--help` writes to **stdout** and
exits **0**; a command line the tool cannot read writes the same text to
**stderr** and exits **2**.

```text
usage: ntasm assemble SOURCE.ntasm [MORE.ntasm ...] -o OUTPUT.efi
       ntasm check SOURCE.ntasm [MORE.ntasm ...]
       ntasm run SOURCE.ntasm [MORE.ntasm ...] --expect RESULT
       ntasm inspect PROGRAM.efi|UNIT.nxo
       ntasm object SOURCE.ntasm [MORE.ntasm ...] -o UNIT.nxo
       ntasm link UNIT.nxo [MORE.nxo ...] -o OUTPUT.efi

options:
  -h --help  write this text to stdout and exit 0
  --version  write the version and provenance to stdout and exit 0
  -o PATH    write PATH; assemble, object and link require it, and it must be
             the argument immediately before PATH
  --backend c|mir  producer for assemble, object, link and check; c (the default)
             is the frozen C reference and mir is the Nova Machine IR chain.
             There is NO fallback: a Machine IR refusal is a refusal, and run
             refuses --backend mir because it has no Machine IR form.
  --root DIR the tree holding compiler/nova and bootstrap/quarantine;
             taken exactly, never searched upwards. Without it the tool walks
             up from its own executable and then from the working directory.
  --expect N required by run, as the argument immediately before N: the
             u64 the executed image must return, and the tool exits 4 when it
             returns anything else
```

### Verbs

| verb | inputs | output | what it does |
| --- | --- | --- | --- |
| `check` | 1 to 64 `.ntasm` files | none | parses, expands, type-checks and verifies effects, clobbers and calls. Prints `NTASM_C_CHECK_OK phase=frontend` on success. Writes no file. |
| `assemble` | 1 to 64 `.ntasm` files | a PE, via `-o` | the whole pipeline in one step: check, codegen, PE. Prints `NTASM_C_ASSEMBLED bytes=<n> provenance=BOOTSTRAP_EXTERNAL_C`. |
| `object` | 1 to 64 `.ntasm` files | an NXO unit, via `-o` | check and codegen only. Imports stay unresolved, so several units can be produced independently. Prints `NTASM_C_OBJECT bytes=<n> provenance=BOOTSTRAP_EXTERNAL_C`. |
| `link` | 1 to 64 `.nxo` files | a PE, via `-o` | resolves imports, materialises relocations, writes the PE. Prints `NTASM_C_LINKED bytes=<n> provenance=BOOTSTRAP_EXTERNAL_C`. |
| `inspect` | exactly 1 file | a JSON line on stdout | validates a PE or an NXO unit without executing it. |
| `run` | 1 to 64 `.ntasm` files, plus `--expect N` | a result line on stdout | the same build `assemble` performs, then the image is mapped and **called**, and the value it returns is compared with `N`. Writes no file. Prints `NTASM_C_RUN result=<n> expected=<n>`; exits **4** when the two differ. |

For a **single** module, `assemble a.ntasm -o out.efi` and `object a.ntasm -o
a.nxo` followed by `link a.nxo -o out.efi` produce the **same bytes**, and the
gate asserts that equality. For several modules they do not: section 3 gives
the measured difference. `object`+`link` is the route that matters when modules
are compiled separately.

### `inspect` output

On a PE, one line of JSON:

```console
$ ntasm inspect count_to_42.efi
{"format":"PE32+","machine":"x86_64","subsystem":"UEFI","entry_rva":4487,"image_base":5368709120,"image_size":20480,"sections":4,"dir64_count":1}
```

On an NXO unit, `format` is `NXOV0001` and the summary carries `target`,
`symbols`, `relocations` and `entry_symbol` instead.

`entry_rva` is where the loader must jump. The value the image is *loaded* at
is not `image_base`: OVMF picks the address, and the loader in section 6
relocates the image to wherever it fits. The entry is a position independent
`ms_abi` function of no arguments returning a `u64` in `RAX`.

### `run`: the verb that calls the image

`assemble` writes a PE and stops there. `run` does the same build, then maps
the image and jumps to its entry, and compares what comes back in `RAX` with
the value you named. It is the verb that makes "source → executable" a
measured claim instead of a byte count.

```console
$ ntasm run examples/ntasm-v0/c-bootstrap/return42.ntasm --expect 42
NTASM_C_RUN result=42 expected=42
$ echo $?
0
$ ntasm run examples/ntasm-v0/c-bootstrap/return42.ntasm --expect 43
NTASM_C_RUN result=42 expected=43
E702: image returned 42, --expect named 43
$ echo $?
4
```

`--expect` is **required**, and that is the design, not a limitation. A `run`
with nothing to compare against has no way to say "ran wrong", and a verb that
can only ever return 0 is a verb that can be satisfied by doing nothing. Making
the expectation mandatory is what lets exit 4 mean something.

Every single-file corpus member runs. The values below were measured on
2026-10-02 and are the values the *code* computes, not immediates read back
out of the source: `--expect 0` is wrong for all of them, and each returned a
different number.

| source | `run … --expect 0` returns | exit |
| --- | --- | --- |
| `call-private-stmt.ntasm` | 21 | 4 |
| `comptime-macro.ntasm` | 42 | 4 |
| `helper-first.ntasm` | 42 | 4 |
| `mutable-data.ntasm` | 42 | 4 |
| `return42.ntasm` | 42 | 4 |
| `return43.ntasm` | 43 | 4 |
| `returnmax.ntasm` | 18446744073709551615 | 4 |
| `static-data.ntasm` | 42 | 4 |

`returnmax` is the one that rules out a constant: a tool that printed a
hard-coded 42 could not print `2^64 - 1`, and the value is read out of the
mapped image after the call returns.

`run` takes several sources the same way `assemble` does, and executes the
whole program:

```console
$ ntasm run examples/ntasm-v0/c-bootstrap-multi/app.ntasm examples/ntasm-v0/c-bootstrap-multi/math.ntasm --expect 42
NTASM_C_RUN result=42 expected=42
```

**What `run` executes, precisely.** It calls `nova_host_map`
(`compiler/c/nova/runtime/run_host.c`) — the same mapping
`tests/c/ntasm/tests.c:30` uses — which lays the artifact out as
text / anchor / rdata / data, seals text `RX` and rdata `R`, and hands back the
entry address; `run` then calls it through the `ms_abi` pointer that mapping
returns and reads the `u64` in `RAX`. **This is native execution of the image
on the host that built it. It is not a UEFI boot and it is not QEMU/OVMF.**
No real hardware is involved, which is what the "stay under QEMU/OVMF" rule
asks for; but the UEFI path of section 6 — firmware, an ESP image, a serial
log — is *not* what `run` does, and `run` is no evidence about it.

### Flags

| flag | accepted by | effect |
| --- | --- | --- |
| `-h`, `--help` | alone, i.e. `ntasm -h` | writes the surface to stdout, exits 0. |
| `--version` | alone, i.e. `ntasm --version` | writes `ntasm 0.0.1-c-bootstrap provenance=BOOTSTRAP_EXTERNAL_C B2.1=not-delivered`, exits 0. |
| `-o PATH` | `assemble`, `object`, `link` | writes `PATH`. Required by those three verbs, and it must be the argument **immediately before** `PATH`. |
| `--expect N` | `run` | required by `run`, and it must be the argument **immediately before** `N`. `N` is the `u64` the executed image must return; the tool exits 4 when it returns anything else. |
| `--backend NAME`, NAME `c` or `mir` | `assemble`, `object`, `link`, `check`; refused by `run` | selects the producer. `c`, the default, is the frozen C reference; `mir` is the Nova Machine IR chain of section 2.1. There is no fallback in either direction: a Machine IR refusal is a refusal, and `run --backend mir` exits 2 with `E605`. Any other value is a usage error. |
| `--root DIR` | with `--backend mir` | the tree that holds `compiler/nova` and `bootstrap/quarantine`, taken exactly and never searched upwards; a directory without both is refused (exit 1). Without it the tool walks up from its own executable, then from the working directory. |

`ntasm help` is also accepted and behaves like `--help`. There is no option
parser: `-o` is recognised only in that one position, so
`ntasm assemble -o out.efi a.ntasm` is a usage error (exit 2) even though it
looks reasonable. The tool does not silently reinterpret it.

### 2.1 The Machine IR chain: `--backend mir`

`--backend mir` sends `assemble`, `object`, `link` and `check` through the
common chain written in Nova instead of the C reference: parse, one macro
expansion, validation of the expanded tree, NTIR, Machine IR (`machine_ir.nova`,
verified), x86-64 emission from the Machine IR (`machine_emit.nova`), an NXO
container, and for `assemble` and `link` the Nova linker and PE writer. The
markers name the route: `NTASM_MIR_PE`, `NTASM_MIR_OBJECT` and
`NTASM_MIR_CHECK_OK phase=machine_ir`, with `provenance=NEXORA_MIR`;
`link --backend mir` prints `NTASM_MIR_LINKED provenance=NEXORA_NOVA_LINKER`,
because it names the linker and not the producer of the objects it read.
Several sources given to `assemble --backend mir` become one object each and
one link. `check --backend mir` checks each module on its own, without
resolving one module's imports against another.

```console
$ ntasm assemble --backend mir count_to_42.ntasm -o count_to_42.mir.efi
NTASM_MIR_PE bytes=<n> provenance=NEXORA_MIR
```

The default stays `c` for one measured reason: `c-bootstrap-multi/app.ntasm`,
whose macro names the imported `add` inside its template, assembles with the C
reference and is refused by the Nova macro expander with `E374` (capture of a
caller symbol, `spec/ntasm/ntasm.md` section 13). The equivalence of the two routes is
measured by `tests_ntasm_machine_corpus.c`, which builds and executes the
corpus through both and compares results and symbol tables, and by
`tests_ntasm_machine_producer_exec.c`. What the Machine IR emitter refuses, and
why, is in `spec/formats/machine-ir-v0.md` section 12.

### Exit codes

```text
exit 0  the request succeeded
exit 1  a source, an object or an image was rejected
exit 2  the command line could not be read
exit 3  a file could not be read or written
exit 4  the image ran, and returned something other than --expect
```

| code | cause | diagnostic on stderr |
| --- | --- | --- |
| 1 | a `.ntasm` source that does not parse, type-check or verify | `FILE:LINE:COLUMN: Exxx: message` |
| 1 | `inspect` on a file that is neither a valid PE nor a valid NXO | `FILE:offsetN: Exxx: message` |
| 1 | `link` on bytes that are not an NXO unit | `FILE:0:0: Exxx: message` |
| 1 | `run` on a source the build refused — the same code a rejected source gets, and no image is mapped | `FILE:LINE:COLUMN: Exxx: message` |
| 2 | unknown verb, missing inputs, `-o` or `--expect` in the wrong position, more than 64 inputs | the usage text |
| 3 | an input cannot be opened | `FILE: E001: <errno text>` |
| 3 | the output already exists | `FILE: E700: File exists` |

`ntasm` **never overwrites an output file.** `assemble`, `object` and `link`
open their output with an exclusive create and fail with `E700` if the path is
taken. Pick a fresh path, or remove the old one yourself. This is deliberate: a
half-written PE that overwrote a good one is worse than a failed command.

---

## 3. The worked example

A complete program, ending in a value computed by the executed code and not an
immediate planted at the return. Paste it as `count_to_42.ntasm`:

```ntasm
module demo.count_to_42
target x86_64-nexora-uefi

section .text {
    fn seed() -> u64
    effects {}
    clobbers { rax } {
        return 2
    }

    fn double() -> u64
    effects {}
    clobbers { rax } {
        return seed() * 2
    }

    export fn main() -> u64
    effects {}
    clobbers { rax } {
        let base: u64 = double() * 10;
        return base + 2;
    }
}
```

`main` is the exported entry point. It calls `double`, which calls `seed`;
`seed` returns 2, `double` returns 4, `main` computes 4 * 10 + 2 and returns
**42**. Two real `call`s, one `let` binding, and arithmetic in the executed
path.

`check` it, then assemble it, then read it back:

```console
$ ntasm check count_to_42.ntasm
NTASM_C_CHECK_OK phase=frontend
$ ntasm assemble count_to_42.ntasm -o count_to_42.efi
NTASM_C_ASSEMBLED bytes=4096 provenance=BOOTSTRAP_EXTERNAL_C
$ ntasm inspect count_to_42.efi
{"format":"PE32+","machine":"x86_64","subsystem":"UEFI","entry_rva":4487,"image_base":5368709120,"image_size":20480,"sections":4,"dir64_count":1}
```

The image is 4096 bytes here and the single-function examples are 3072. The
section table is the reason, not the code: `return42` needs 11 bytes of `.text`
(`0x0b`), this program needs 1132 (`0x46c`). A section is stored in 0x200-byte
file slots, so crossing 512 bytes costs one extra slot and the whole image
grows by 0x200. The digest is stable — the same source assembles to the same
bytes on every run and from a clean rebuild:

```text
sha256  d48e84b6e0d20810dfbf991cd6c91940c38d5c3da84408662d0fe669d7d485c8
```

That line is a contract, not a note. The gate reassembles the example above and
fails if the bytes do not hash to it. **Changing the backend means changing this
line, in the same commit.**

### Several modules

A library and the program that uses it, as `math.ntasm` and `app.ntasm`:

```ntasm
module math
target x86_64-nexora-uefi
section .text {
    export fn add(in a:u64 @rcx,in b:u64 @rdx)->u64
    effects {}
    clobbers {} {
        return a+b
    }
}
```

```ntasm
module app
target x86_64-nexora-uefi
import math.add as add: fn(in a:u64 @rcx,in b:u64 @rdx)->u64
effects {}
clobbers {}
section .text {
    export fn main()->u64
    effects {}
    clobbers {} {
        return add(20,22)
    }
}
```

The import declaration has to repeat the callee's contract exactly. A
signature that differs in any part is `E302: import contract mismatch`, named
at the `import` line.

`assemble` takes every module of a program on one command line and resolves the
imports between them:

```console
$ ntasm check app.ntasm math.ntasm
NTASM_C_CHECK_OK phase=frontend
$ ntasm assemble app.ntasm math.ntasm -o app.efi
NTASM_C_ASSEMBLED bytes=3584 provenance=BOOTSTRAP_EXTERNAL_C
```

To compile them independently, use `object` then `link`:

```console
$ ntasm object app.ntasm -o app.nxo
NTASM_C_OBJECT bytes=1168 provenance=BOOTSTRAP_EXTERNAL_C
$ ntasm object math.ntasm -o math.nxo
NTASM_C_OBJECT bytes=896 provenance=BOOTSTRAP_EXTERNAL_C
$ ntasm link app.nxo math.nxo -o app.efi
NTASM_C_LINKED bytes=3584 provenance=BOOTSTRAP_EXTERNAL_C
```

A module without a `main` is a library: `check` accepts it, and `object` emits
it. Only `assemble` and `link` need an entry point.

**For one module the two routes are the same bytes. For several modules they
are not**, and that is a property of the tool, not a caveat on this page. On the
tree of 2026-09-27, `assemble app.ntasm math.ntasm` and
`link app.nxo math.nxo` both write 3584 bytes and both boot and return 42, but
352 of those bytes differ: the whole-program path puts `math.add` at a
`.text` offset eight bytes before the path that links two independently encoded
objects does, and the `call rel32` that reaches it is patched to match
(`.text` virtual size `0x31e` against `0x326`). The code that runs is the same
code; the layout around it is not. The gate therefore checks the byte equality
on a single module, which is the case the tool does make identical, and does
not pretend to check the multi-module case.

**The two sources above are written out here on purpose, and they are not the
files in the tree.** There is a versioned two-module example at
`examples/ntasm-v0/c-bootstrap-multi/`, and it is a *different program* under
the same two filenames: its `app.ntasm` adds a `comptime` block and a macro, so
it computes `add(21,21)` by expansion rather than calling with the literal
`add(20,22)`. Assembling the pair printed here on 2026-09-28 gave
`945028810207e5a2219c88e38cd8a01ef07b8fab7b24129b5e1bc2d226ac8234`; assembling
the versioned pair gave `c9d9786d9edd2210b3b9d90c96f3da7997d3b260d286dd219e7ef174f526c08d`.
Both are 3584 bytes and both return 42; they differ in two bytes. Section 4.1
names the tree files, so that a reader who wants the versioned example is not
left guessing which of the two a digest belongs to.

---

## 4. The complete examples in the tree

> **Three words, three lists, one definition — read this before using the word
> "corpus" anywhere on this page.** *Corpus* was one word with three referents
> in three files, and the counts disagreed because they were counting different
> things. The single definition is in `scripts/ntbuild.sh`, in the block headed
> `THE DEFINITION OF "CORPUS"`, next to the list it defines because that is
> where the list lives. In short: the **pinned corpus** is the eight rows of
> `bash scripts/ntbuild.sh corpus`, one sha256 of a PE per program; the
> **coverage corpus** is the seven-member `CORPUS[]` array in
> `tests/c/nova/nova_corpus_convergence.c`, a deliberate subset
> that asks whether the Nova producer converges and omits `multi-app-math`
> because it has not measured a two-module program; and the **boundary shapes**
> are that file's 13-row `BOUNDARY[]` table, which counts *shapes*, most of them
> source literals in no directory at all. The table below is the pinned corpus
> **rendered and restricted to its single-file rows**, which is why it has seven
> lines where the target prints eight.

`examples/ntasm-v0/c-bootstrap/` holds **eight** `.ntasm` files, of which
**seven** are the single-file pinned rows tabulated below. Each of the seven is
a **complete program**, not a fragment: a `module`, a `target`, and an exported
`main`, in a file that is a whole compilation unit on its own. All seven pass
`check`, `assemble` and `inspect` on this tree, and all seven **boot under QEMU
and return the value in the last column** (section 6).

**The eighth file, `call-private-stmt.ntasm`, is deliberately not a pinned row,
and the reason is written down rather than left to be rediscovered.** It is a
complete program — a `call` to a private function written as a statement, whose
result is returned — so it is the file of this directory that most resembles
`helper-first`.
>
> **A retraction, in place.** An earlier revision of this page said the file
> was unpinned because *"pinning it needs a digest this page cannot produce"*.
> **That was false, and it is false in the checkable direction**: the digest is
> producible, and two independent routes produce the same one —
> `b1e549ffb105d1a4daef4efb1935b29a881ec899cf90db98f87a65dab47b943e`, 3584
> bytes, measured on 2026-09-30 by the shipped binary and, independently, by
> the C reference inside `nova_corpus_convergence.c`. The file was never in
> `scripts/ntbuild.sh`; the sentence described a limitation of the page and
> dressed it as a property of the file.
>
> So why is it still not a row? Not feasibility. A pinned row is a **product
> promise** — re-checked on every `ntbuild.sh selftest` *and* booted under QEMU
> per section 6 — and this program has **no QEMU run and no boot record**, so
> adding it would assert evidence that does not exist. It is not unpinned and
> not unowned either: it is **row `call_private_stmt_body` of the boundary
> shapes**, checked byte for byte on every run of that gate, which is a
> different promise and one it is already kept to.
>
> The exclusion is written where the next person will read it, in
> `CORPUS_EXCLUSIONS` in `scripts/ntbuild.sh`, and it is **enforced**: see the
> census note below.

> **The census, and why this page does not carry the check itself.** The gate
> that reads this file asserts `examples.count >= 7` — a **floor**, and a floor
> cannot detect the defect named above: a ninth file in the corpus directory
> does not lower the count, so the guide table would still hold its seven rows
> and still go green. Measured on 2026-09-30, **no gate anywhere enumerates that
> directory**: `tests_ntasm_cli.c` names it only to build a path, and
> `nova_corpus_convergence.c` lists *programs*, not files. So the floor was not
> a deliberate tolerance of unpinned files — it is the only check that existed,
> and a check that cannot fail on a defect is not a tolerance of it.
>
> The check is therefore `bash scripts/ntbuild.sh census`, in the file that
> owns the pin, and it is an **equality in both directions**: every `.ntasm`
> under the two corpus directories is either a source of a pinned row or a named
> entry of `CORPUS_EXCLUSIONS`, **and** every entry of `CORPUS_EXCLUSIONS` still
> exists on disk. The second direction is the one a reader forgets, and without
> it the exclusion table could rot into a list of files that were once here. It
> is exercised on every `ntbuild.sh selftest` with three controls, including one
> that plants a ninth file in a shadow of the directory and requires the census
> to refuse it **by name**.

The digests below are the product's, computed from the emitted files. Every one
of them was **re-assembled and re-booted on 2026-09-28** from the binary of
section 1, each from a cold directory named `out/c-bootstrap/qemu/w11-a9-<name>/`
built by the section 6.1 recipe, each carrying its own `EXPECT.BIN`. All seven
returned the value in the last column, at the digest printed here. `helper-first`
additionally has its negative control, section 6.3.

> **A gap in the recorded evidence, now closed by those runs.** The per-example
> records under `out/c-bootstrap/uefi/*-green/` were made against a *Windows
> hand-built snapshot*, and three of them name an image the current product does
> not produce: `helper-first-green/` records `d9e00f47…` where this table says
> `c74c7db2…`, `static-data-green/` records `22dd1d3e…` against `43fddd77…`, and
> `mutable-data-green/` records `e04bf864…` against `42f6e345…`. Those three rows
> were therefore **not** backed by a recorded run at the shipped digest. The
> claim was still true — the runs above are the evidence — but it was true by
> assertion, not by artefact, and that is worth knowing before anyone rebuilds
> `out/c-bootstrap/uefi/`.

```text
example         sha256                                                           returns
---------------+----------------------------------------------------------------+---------
return42       1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457   42
return43       5811fda51dd2e115eabb39cc2d5c688fcc494da29660e4ac817794bc2b127ac3   43
returnmax      f91e4ba4a0aa3901baebf42f227b05fc97439368584b00737e88ae944cd2bbb5   18446744073709551615
helper-first   c74c7db2e1cf0e6f21e96eac129fee50ef77f705d2bbe9e8ee477c6ea4e5e9c3   42
static-data    43fddd77fe59b29b11e6e1d0d05ec05e02d159a357484da8090bfe5fe1dc207a   42
mutable-data   42f6e3459bdf7bf32280dbea534165d453c361a5fe9228135ae7562f48420690   42
comptime-macro 1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457   42
```

What each one is for:

- `return42` — the smallest program that produces an image; the oracle for the
  green run of section 6.
- `return43` — the same program one value apart; the oracle for the negative.
- `returnmax` — the full 64-bit range, so the reader knows an immediate is not
  truncated to 32 bits.
- `helper-first` — a `call` to a second function, then arithmetic in the caller.
- `static-data` — an initialised `.rdata` datum loaded through a typed pointer.
- `mutable-data` — a `.data` datum stored to and loaded back at run time.
- `comptime-macro` — a `comptime` block and a macro expansion. It shares
  `return42`'s digest because the macro expands to the same program; that is
  the point of the pair, the metaprogramming path produces the bytes rather
  than claiming them.

### 4.1 The versioned two-module example

The seven rows above are the whole of the **pinned single-file** corpus.
**`bash scripts/ntbuild.sh corpus` prints eight rows, not seven** — measured
on 2026-09-30, the command as it stands: the seven above plus one row,
`multi-app-math`, whose two sources live in
`examples/ntasm-v0/c-bootstrap-multi/`. **So that second directory IS in the
corpus target, by exactly one row**, and the earlier revision of this page
said it was not in it at all. That sentence was wrong and is withdrawn: the
directory is pinned, through the pair that works, and **not** through the
pair that does not assemble (section 4.1). `scripts/ntbuild.sh` re-checks all
eight rows on every `selftest`. The multi-module example is **not** covered by
`tests_ntasm_cli.c`, which reads only the single-file table above.

That directory holds four sources in two pairs, and the two pairs do not stand
in the same place:

**`app.ntasm` + `math.ntasm` — functions, and it works.** Any fresh output
directory will do, and this block makes one: the first line creates it, and
every `-o` below is inside it. The earlier revision of this block said the same
thing in prose and then printed `/tmp/ng-w11-a9-ex/` in all six commands
without ever creating it — `grep` finds no `mkdir` for that path anywhere in
this document, and nothing in the repository creates it either. Run verbatim on
a fresh machine, `ntasm assemble` failed with
`/tmp/ng-w11-a9-ex/multiA.efi: E700: No such file or directory` and **exit 3**;
both `object` commands failed the same way, `link` failed with `E001` and exit
3, `sha256sum` exited **1**, and `cmp` exited **2** while printing `0` — a
number that looks like a result and is the byte count of two files that do not
exist. Six commands, none of them doing what it claims. Run from the repository
root:

```console
$ mkdir -p out/c-bootstrap/multi-example
$ ntasm check examples/ntasm-v0/c-bootstrap-multi/app.ntasm examples/ntasm-v0/c-bootstrap-multi/math.ntasm
NTASM_C_CHECK_OK phase=frontend
$ ntasm assemble examples/ntasm-v0/c-bootstrap-multi/app.ntasm examples/ntasm-v0/c-bootstrap-multi/math.ntasm -o out/c-bootstrap/multi-example/multiA.efi
NTASM_C_ASSEMBLED bytes=3584 provenance=BOOTSTRAP_EXTERNAL_C
$ ntasm object examples/ntasm-v0/c-bootstrap-multi/app.ntasm -o out/c-bootstrap/multi-example/a.nxo
NTASM_C_OBJECT bytes=1168 provenance=BOOTSTRAP_EXTERNAL_C
$ ntasm object examples/ntasm-v0/c-bootstrap-multi/math.ntasm -o out/c-bootstrap/multi-example/m.nxo
NTASM_C_OBJECT bytes=896 provenance=BOOTSTRAP_EXTERNAL_C
$ ntasm link out/c-bootstrap/multi-example/a.nxo out/c-bootstrap/multi-example/m.nxo -o out/c-bootstrap/multi-example/multiA-link.efi
NTASM_C_LINKED bytes=3584 provenance=BOOTSTRAP_EXTERNAL_C
```

```console
$ sha256sum out/c-bootstrap/multi-example/multiA.efi out/c-bootstrap/multi-example/multiA-link.efi
c9d9786d9edd2210b3b9d90c96f3da7997d3b260d286dd219e7ef174f526c08d  out/c-bootstrap/multi-example/multiA.efi
c246f75dbfe126d5e5b7b04545d70e4aa0e3c639883389e4dca52077fde4631f  out/c-bootstrap/multi-example/multiA-link.efi
$ cmp -l out/c-bootstrap/multi-example/multiA.efi out/c-bootstrap/multi-example/multiA-link.efi | wc -l
352
```

Both digests and the 352 are re-measured above from a cold directory this
block created; they are not carried over from the 2026-09-28 run. **`cmp`
exits 1 when two files differ, and they are supposed to**, so the 352 is the
number and a non-zero status is the expected one — the earlier block quoted the
byte count without that, which is how a reader can tell a real difference from
`cmp` failing to find its inputs.

Same size, 352 bytes of difference, the same 42 — the 352 and the
`.text` offsets of section 3 were re-measured here, not carried over. The
whole-program image was then booted exactly as section 6.1 boots a
single-module one, from `out/c-bootstrap/qemu/w11-a9-multi/`:

```console
$ tr -d '\033' < out/c-bootstrap/qemu/w11-a9-multi/serial.log | grep -a 'NG_NTASM\|BOOTSTRAP_C_TEST'
BOOTSTRAP_C_TEST NTASM_RESULT_CONSUMER
NG_NTASM_C_LOADED base=0x000000000e3df000 size=0x0000000000005000 entry=0x0000000000001000
NG_NTASM_C_RETURN got=0x000000000000002a expected=0x000000000000002a
NG_NTASM_C_RESULT_OK
```

This is the strongest artefact A9 has: a two-module program, built two
different ways, that a real firmware loads and runs to the right answer.
>
> **A second retraction, in place.** This paragraph used to say the multi-module
> example was *"the only artefact in this guide that lies outside the pinned
> corpus, so nothing re-checks it automatically"*. **Both halves were false, and
> they were false about the same row.** `multi-app-math` **is** the eighth row
> of the pinned corpus — `bash scripts/ntbuild.sh corpus` prints it, and
> `scripts/ntbuild.sh selftest` re-assembles it and compares the digest on
> every run (measured 2026-09-30: `ok example multi-app-math c9d9786d9edd2210`).
> So it is inside the pin, and something does re-check it automatically. What
> is true, and narrower, is that **the `object`+`link` route below is what
> nothing re-checks**: those two verbs producing a *different* 3584 bytes is
> recorded on this page and measured by no gate, which is why section 4.1's
> second digest is stated with its date rather than as a standing pin.
> Its `entry_rva` is `0x1000`, not the `0x100b` of `helper-first`, which is the
> layout difference in one number.

**`app-data-import.ntasm` + `math-data.ntasm` — an imported datum, and it does
not assemble today.** The pair declares `import math_data.step as step: u64`
against an `export data step:u64=2`. The C frontend reads an import as a
function signature and nothing else:

```console
$ ntasm check examples/ntasm-v0/c-bootstrap-multi/app-data-import.ntasm examples/ntasm-v0/c-bootstrap-multi/math-data.ntasm
examples/ntasm-v0/c-bootstrap-multi/app-data-import.ntasm:3:32: E200: expected 'fn'
$ echo $?
1
```

`object` refuses the same file the same way. This is a scope decision about
what an import may denote, not a miscompilation, and it is exactly the "moitié
données" A3 records as open. **It is stated here because the files are in the
tree**: a reader who finds `examples/ntasm-v0/c-bootstrap-multi/` and assumes
all four sources assemble will hit this with no warning from the guide.

`examples/nova-bootstrap/` holds `.nova` sources. They are **not** NTASM and
`ntasm` does not read them; they belong to the Nova toolchain and to
`compiler/nova/`.

---

## 5. Reading a diagnostic

A rejected source names itself, the position, and a stable code. This source
stops after `effects {}`, so the function header is never closed:

```console
$ cat broken.ntasm
module broken
target x86_64-nexora-uefi
section .text {
export fn main() -> u64
effects {}
$ ntasm assemble broken.ntasm -o broken.efi
broken.ntasm:6:1: E200: expected 'clobbers'
$ echo $?
1
```

and it creates no file. The `E` codes are documented in `spec/ntasm/ntasm.md`. The
format is `FILE:LINE:COLUMN: ECODE: message` for sources and
`FILE:offsetN: ECODE: message` for artefacts, because an artefact has offsets
and not lines.

The refusals that are not about the source text:

| situation | stderr | exit |
| --- | --- | --- |
| the input is not a readable file of at most 16 MiB, a directory among them | `E002: invalid source size` | 3 |
| the inputs together exceed 64 MiB | `E002: input unit exceeds 64 MiB` | 3 |
| an empty file | `FILE:1:1: E200: expected 'module'` | 1 |
| more than 64 inputs | the usage text | 2 |
| the same module name twice on one command line | `FILE:1:8: E300: duplicate module '...'` | 1 |

---

## 6. Source to a booting PE, under QEMU

This is the part that makes "executable" mean something. The image above is
loaded by real UEFI firmware and called; the value it returns in `RAX` is
compared against an 8-byte oracle on the same volume.

`ntasm` does not boot anything, and it does not need to. The loader is a
**test harness**, not a product: an EFI application, 6144 bytes, already in the
tree at

```console
$ sha256sum out/c-bootstrap/uefi/consumer-v1/BOOTX64.EFI
38d58878da0ea99d184db58a3dff5369af874f29cf5fc879f1d90c05260abed3  out/c-bootstrap/uefi/consumer-v1/BOOTX64.EFI
```

Verify that digest before trusting a run. The harness reads `NTRESULT.EFI` and
`EXPECT.BIN` from the volume, validates the image, calls its entry point as a
`ms_abi` `u64` function of no arguments, prints what it got and what it
expected, and prints `NG_NTASM_C_RESULT_OK` only when they are equal.

### 6.1 Build the ESP

```bash
mkdir -p out/c-bootstrap/qemu/green
cd out/c-bootstrap/qemu/green
ntasm assemble ../../../../examples/ntasm-v0/c-bootstrap/helper-first.ntasm \
  -o NTRESULT.EFI
printf '%b' '\x2a\x00\x00\x00\x00\x00\x00\x00' > EXPECT.BIN   # 42, little endian
dd if=/dev/zero of=esp.img bs=1M count=64 status=none
mkfs.vfat -n NGESP esp.img
mmd -i esp.img ::/EFI
mmd -i esp.img ::/EFI/BOOT
mcopy -i esp.img ../../uefi/consumer-v1/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI
mcopy -i esp.img NTRESULT.EFI ::/NTRESULT.EFI
mcopy -i esp.img EXPECT.BIN ::/EXPECT.BIN
sha256sum NTRESULT.EFI
```

`green/` is the recorded case. This section was **re-executed on 2026-09-28
from a cold directory**, `out/c-bootstrap/qemu/w11-a9-green/`, created by the
same commands; the last line printed

```console
$ sha256sum NTRESULT.EFI
c74c7db2e1cf0e6f21e96eac129fee50ef77f705d2bbe9e8ee477c6ea4e5e9c3  NTRESULT.EFI
```

The paths are relative to the directory you are in: four levels up from
`out/c-bootstrap/qemu/green` is the repository root, two levels up is
`out/c-bootstrap`, where the harness lives. The last line prints
`c74c7db2e1cf0e6f21e96eac129fee50ef77f705d2bbe9e8ee477c6ea4e5e9c3`, the
digest `helper-first` has in the table of section 4.

`EFI/BOOT/BOOTX64.EFI` is the removable-media boot path, so the firmware
finds and runs the harness without a boot option being configured.

### 6.2 Boot it

```bash
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd
qemu-system-x86_64 -machine q35,accel=tcg -cpu max -m 256M \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=vars.fd \
  -drive if=virtio,format=raw,file=esp.img \
  -boot order=c,menu=off -nic none -display none -serial file:serial.log &
QPID=$!
for i in $(seq 1 900); do grep -aq NG_NTASM_C_RESULT_ serial.log 2>/dev/null && break; sleep 0.1; done
sleep 1; kill $QPID; wait $QPID 2>/dev/null
tr -d '\033' < serial.log | grep -a 'NG_NTASM\|BOOTSTRAP_C_TEST'
```

The loop exists because the firmware falls through to its own shell after the
harness returns; it does not power off by itself. The 2026-09-28 cold run in
`out/c-bootstrap/qemu/w11-a9-green/` took six seconds end to end under TCG,
firmware start-up included, and printed exactly the four lines below.

```console
$ tr -d '\033' < serial.log | grep -a 'NG_NTASM\|BOOTSTRAP_C_TEST'
BOOTSTRAP_C_TEST NTASM_RESULT_CONSUMER
NG_NTASM_C_LOADED base=0x000000000e3df000 size=0x0000000000005000 entry=0x000000000000100b
NG_NTASM_C_RETURN got=0x000000000000002a expected=0x000000000000002a
NG_NTASM_C_RESULT_OK
```

`got=0x2a` is 42, computed by the code `ntasm` emitted. `NG_NTASM_C_RESULT_OK`
is the marker to look for.

### 6.3 The negative

Same PE, same bytes, same digest. Only the oracle changes, to 43. The image is
**not** reassembled — that is what makes this a control — but the volume *is*
rebuilt, because the oracle is read from it. A second directory, the same five
`mcopy` lines, and section 6.2 again:

```bash
mkdir -p out/c-bootstrap/qemu/negative
cd out/c-bootstrap/qemu/negative
cp ../green/NTRESULT.EFI .
printf '%b' '\x2b\x00\x00\x00\x00\x00\x00\x00' > EXPECT.BIN   # 43, little endian
dd if=/dev/zero of=esp.img bs=1M count=64 status=none
mkfs.vfat -n NGESP esp.img
mmd -i esp.img ::/EFI
mmd -i esp.img ::/EFI/BOOT
mcopy -i esp.img ../../uefi/consumer-v1/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI
mcopy -i esp.img NTRESULT.EFI ::/NTRESULT.EFI
mcopy -i esp.img EXPECT.BIN ::/EXPECT.BIN
sha256sum NTRESULT.EFI EXPECT.BIN
```

Run on 2026-09-28 from a cold directory, `out/c-bootstrap/qemu/w11-a9-negative/`:

```console
$ sha256sum NTRESULT.EFI EXPECT.BIN
c74c7db2e1cf0e6f21e96eac129fee50ef77f705d2bbe9e8ee477c6ea4e5e9c3  NTRESULT.EFI
8bf3cd6bb2af61dde37441d65f1b1f6b1d2f20e07b243fbb80a19d6bef508abb  EXPECT.BIN
```

```console
$ tr -d '\033' < serial.log | grep -a 'NG_NTASM\|BOOTSTRAP_C_TEST'
BOOTSTRAP_C_TEST NTASM_RESULT_CONSUMER
NG_NTASM_C_LOADED base=0x000000000e3df000 size=0x0000000000005000 entry=0x000000000000100b
NG_NTASM_C_RETURN got=0x000000000000002a expected=0x000000000000002b
NG_NTASM_C_RESULT_BAD code=0x0000000000000032 status=0x0000000000000000
```

`got` is 42 in both runs. The program did not change; the comparison is live.
Without this second run, `NG_NTASM_C_RESULT_OK` would be consistent with a
harness that prints OK unconditionally.

On 2026-09-28 the single-example run of 6.1 was repeated for each of the other
six examples, each in its own cold `out/c-bootstrap/qemu/w11-a9-<name>/`, and
each printed `NG_NTASM_C_RESULT_OK` at the digest its section 4 row claims.
`returnmax` is the one that proves the immediate is not truncated: it returned
`got=0xffffffffffffffff` against an eight-byte oracle of all ones.

### 6.4 The recorded evidence

The two runs of this section are in the tree, with digests, under
`out/c-bootstrap/qemu/`:

```text
c74c7db2e1cf0e6f21e96eac129fee50ef77f705d2bbe9e8ee477c6ea4e5e9c3  green/NTRESULT.EFI
ed049108bc18f2c64369e8d0ea42850bdd1a7d1dd340cfde716315579702a76c  green/EXPECT.BIN
1eb33cbd56cbb213531669c1811665ccada33c75c8cfb090930f0ce740ddf2f6  green/serial.log
8bf3cd6bb2af61dde37441d65f1b1f6b1d2f20e07b243fbb80a19d6bef508abb  negative/EXPECT.BIN
add3a3879dea69b09194a7963af0eecf427d894095df4a355a3ce25b1bc898cd  negative/serial.log
```

**Which of those digests is a contract, and which is not.** `NTRESULT.EFI` and
`EXPECT.BIN` are contracts: re-running section 6.1 and 6.3 on 2026-09-28
reproduced `c74c7db2…`, `ed049108…` and `8bf3cd6b…` exactly. `serial.log` is
**not** one: the green log recorded above is `1eb33cbd…`, and the 2026-09-28
cold run in `out/c-bootstrap/qemu/w11-a9-green/` produced `2428423d…` for the
same image and the same oracle. A serial log carries firmware timestamps and
absolute load addresses, so a reader must not treat its digest as a promise.
The digest that matters for the negative is the one on the *image*, which did
not move.

The 2026-09-28 cold runs, with the directories named:

```text
c74c7db2e1cf0e6f21e96eac129fee50ef77f705d2bbe9e8ee477c6ea4e5e9c3  w11-a9-green/NTRESULT.EFI
ed049108bc18f2c64369e8d0ea42850bdd1a7d1dd340cfde716315579702a76c  w11-a9-green/EXPECT.BIN
c74c7db2e1cf0e6f21e96eac129fee50ef77f705d2bbe9e8ee477c6ea4e5e9c3  w11-a9-negative/NTRESULT.EFI
8bf3cd6bb2af61dde37441d65f1b1f6b1d2f20e07b243fbb80a19d6bef508abb  w11-a9-negative/EXPECT.BIN
c9d9786d9edd2210b3b9d90c96f3da7997d3b260d286dd219e7ef174f526c08d  w11-a9-multi/NTRESULT.EFI
1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457  w11-a9-return42/NTRESULT.EFI
5811fda51dd2e115eabb39cc2d5c688fcc494da29660e4ac817794bc2b127ac3  w11-a9-return43/NTRESULT.EFI
f91e4ba4a0aa3901baebf42f227b05fc97439368584b00737e88ae944cd2bbb5  w11-a9-returnmax/NTRESULT.EFI
43fddd77fe59b29b11e6e1d0d05ec05e02d159a357484da8090bfe5fe1dc207a  w11-a9-static-data/NTRESULT.EFI
42f6e3459bdf7bf32280dbea534165d453c361a5fe9228135ae7562f48420690  w11-a9-mutable-data/NTRESULT.EFI
1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457  w11-a9-comptime-macro/NTRESULT.EFI
```

The `esp.img` and `vars.fd` of each are not kept, and section 6.1 rebuilds them
in under a second.

`NTRESULT.EFI` hashing to the same value in both the green and the negative
directory is the point of the control: the negative case changed eight bytes of
oracle, not the image.

---

## 7. What this guide does not claim

- The tool is the external C bootstrap producer, not the self-hosted NTASM of
  B2.1. `ntasm --version` says so, and says `B2.1=not-delivered`.
- **`run` demonstrates A9's last clause, and nothing more.** It shows that a
  source goes to an executable that returns a computed value. It does **not**
  show that the Nova chain runs from the tool. The tool's compile path is the
  C reference — `cli.c` calls `nt_compile_many`, and `compiler/c/nova/cli/cli.c`
  is declared `NOVA_NOT_A_GATE` with the reason *NOT LINKED BY ANY BUILD*. A
  green `run` must never be read as "Nova produced this".
- `run` is native host execution of the mapped image, not a UEFI boot. It is
  not QEMU/OVMF and it says nothing about section 6.
- The C frontend accepts a narrower language than `spec/ntasm/ntasm.md` describes. It
  has `let`, `return`, `call`, `if`/`else`, labels, macro expansion and raw
  instruction statements; it has no `while`, no `for`, no `match`, and no
  assignment to an existing local. Each of those four is rejected where it is
  used, with `E200: expected newline or semicolon` or
  `E200: expected expression`, not miscompiled.
- A body of raw instructions has to declare what the body does, and the check
  is exact in both directions. `mov rax, 40; add rax, 2; return rax;` needs
  `effects { changes_flags }` and `clobbers { rax, rflags }`; leave the effect
  out and it is `E501: function 'main' omits an inferred effect`, leave
  `rflags` out of the clobbers and it is `E502: function 'main' omits an
  inferred clobber`. A declaration wider than the body is accepted.
- The image is a UEFI application loaded by firmware. Nothing here says
  anything about a kernel loading it.
- An `import` denotes a function, and only a function. `import M.s as s: u64`
  is `E200: expected 'fn'` at the import (section 4.1). An `export data` in the
  callee is not importable today, so one of the two pairs in
  `examples/ntasm-v0/c-bootstrap-multi/` is a source that does not assemble.
- The target is a declaration inside the source, not a command-line option. There
  is no `--target`, no `--emit`, and no install step: `target
  x86_64-nexora-uefi` is the first line of the program, and the verb chooses
  between NXO and PE. `docs/architecture/ntasm-v0-work-package.md` §3 proposes `--target` and
  `--emit` as part of the A9 acceptance; **the delivered surface has neither,
  and this guide does not claim it does.** That divergence is for the bearer of
  the criteria to settle, not for this page to paper over.
- The seven examples of section 4 are the pinned corpus **restricted to its
  single-file rows** and nothing more; the pinned corpus itself carries an
  eighth row, `multi-app-math`, and `examples/ntasm-v0/c-bootstrap/` holds an
  eighth file that is deliberately **not** a row
  (`call-private-stmt.ntasm`, section 4). Three lists answer three different
  questions and are not versions of one another — the **pinned corpus** (this
  page's table plus `multi-app-math`), the **coverage corpus** (7 members,
  `nova_corpus_convergence.c`, does the Nova producer converge), and the
  **boundary shapes** (13 rows, same file, does the producer converge or refuse
  for a given shape). *Corpus* unqualified means only the first; the definition
  is in `scripts/ntbuild.sh`. The seven are programs of
  one shape — an entry point that returns a constant, a
  call, a static datum, a mutable datum, a macro. They are **not** a
  conformance suite, and section 4.1's two-module example is the only artefact
  that exercises an intermodule import end to end.
- The harness is a test fixture in `out/`. It is pinned by its digest and is
  never a build input of `ntasm`.
- Section 6 was run under TCG emulation, on one machine, with one firmware
  build. No hardware, no other architecture, no other OS ABI.
- `inspect` validates structure. It does not execute, and it does not prove the
  code does what you meant.

---

## 8. Where the checks are

| what | where |
| --- | --- |
| the guide is the specification, the code must match it | `tests/c/nova/tests_ntasm_cli.c` — but see the coverage limit named at the top: section 4.1 is outside it |
| the command surface | `compiler/c/ntasm/cli/cli.c`, declared in `cli.h` |
| the C compiler the tool is built from | `compiler/c/ntasm/frontend/frontend.c`, `codegen.c`, `x64.c`, `pe.c`, `object*.c` |
| the language | `spec/ntasm/ntasm.md` |
| how the binary is actually built, and what it refuses | `scripts/ntbuild.sh`, `docs/guides/ntasm-build.md`, and the short version in `legacy/docs/bootstrap/producer-usage.md` |
| the acceptance criteria this guide answers | `docs/status/ntasm-completion.md`, A9; the proposed acceptance that does **not** match the delivered flags is `docs/architecture/ntasm-v0-work-package.md` §3 |
| the QEMU evidence of section 6 | `out/c-bootstrap/qemu/`, per run; the harness is `out/c-bootstrap/uefi/consumer-v1/BOOTX64.EFI`. The older `out/c-bootstrap/uefi/*-green/` records predate the current product — see the note in section 4 |
