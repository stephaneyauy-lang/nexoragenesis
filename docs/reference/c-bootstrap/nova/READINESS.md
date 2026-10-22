# Nova Bootstrap ABI2 — ready to begin the full NTASM port

Verified on **6 September 2026**. Immutable handoff:
`out/c-bootstrap/nova/readiness-v6/`.

The compiler-writing bootstrap requirements in `spec/nova/nova-bootstrap.md` are
demonstrated. This clears the start of the full NTASM migration; it does not
claim that the migration, Nova self-hosting, GPU profile or NTASM B2.1 is done.

## Requirement audit

| Required capability | Implemented behavior and proof |
|---|---|
| Direct compilation | `.nova` is parsed/type-checked into typed IR and encoded by our backend; no generated C or external assembler step |
| Integer/types foundation | u8/u16/u32/u64, i8/i16/i32/i64, bool, nominal records/references, generic bounded buffers; 45 integer tests including actual typed-memory widths |
| Compiler control flow | named/forward functions, 64 scalar ABI slots, typed locals/mutation, if/else/while/break/continue and lexical scope |
| Strings/arrays/aggregates | byte strings/escapes/NUL, mutable byte literals, generic arrays, records with fields, null/recursive references, buffer and record returns |
| Modules | multi-file module/import/export resolution, qualified calls/types and visibility; 15 tests |
| Safe storage and errors | generation-tagged owned/borrowed handles and views; readonly and freed aliases checked before actual access; independent sticky errors propagate through u8/u64 calls before later effects |
| Runtime | versioned memory, file, diagnostics callbacks; source programs perform computations; host and QEMU/OVMF adapters tested |
| Compiler-sized input | 513 functions and 4096 declared locals compile to470406 text bytes and execute36 under ASan/UBSan; the lowerer's additional temporaries exceed the old cap |
| Wide-call ABI | full64-argument sum2080, public64-slot entry,65-slot transactional rejection and narrow/signed argument boundary checks; native Linux/Windows tests and real QEMU8-argument call |
| Genuine NTASM component | compiled decimal parser versus independent1271-case reference corpus in **final ABI2**,8925 checks; exact positions/full u64 and guarded outputs |
| Genuine producer port | `.nova` four-section PE writer takes dynamic42/43/u64max, produces bytes identical to the existing C reference, and its generated PE executes42 in QEMU |
| Usable/reproducible tool | Windows `nova.exe check/build/run`, explicit input modules, safe output publication, source manifest; GCC/Clang produce an identical17408-byte decimal PE |

The final compiler/core gates are in `../readiness-v5/`:47 v2,30 aggregate,
15 module,45 integer,16 boundary,6 capacity and8925 component checks, all zero
failures with GCC ASan+UBSan. Windows boundary16 and CLI7 also pass. The v6
delta is a tested CLI cleanup-report fix; the compiler/core sources are unchanged.

The final ABI route in `../readiness-v5/uefi-files` creates and rereads a real
ESP file, returns42/error0, then reports zero owned pools/files. Raw readback
bytes are52,50; firmware return, HMP peer closure, QEMU exit0 and empty error
logs are verified. `uefi-stack` independently executes8 scalar arguments.
Earlier lifetime and deliberately wrong-oracle UEFI tests remain preserved.

## Explicit supported limits

- Source:64 supplied files,4MiB each;262143 stored tokens including EOF.
- IR:1024 functions including the public entry wrapper;65536 variables
  including compiler temporaries;262144 expression and statement nodes each.
- Types/fields:4096 type slots/record fields total,64 fields per record.
- Nesting:128. Identifiers:79 bytes. Literal data:16MiB.
- Functions:64 scalar slots under `efi-x64-v0`; a buffer uses handle plus
  element count. Public entry remains `(context,flat_args,count)`.
- Runtime:65536 buffer/view handles,128 files,16MiB per allocation,
  64MiB live payload total. UEFI test paths are ASCII, maximum4096 bytes.
- Native artifacts retain the existing16MiB text/section and PE-profile bounds.

The large input test demonstrates headroom for the current NTASM inventory;
these are finite contracts, not a promise that any future generated program
fits. Port modules incrementally and retain exact diagnostics for a cap hit.

## Build/run contract

Use `nova_compile_many_v2` and `nova_check_many_v2`; the legacy entry points
remain for historical ABI1 replay. The source set is the coherent machine-v5
backend plus Nova. `conformance.c` is a required link dependency.

```text
clang -std=c11 -D_CRT_SECURE_NO_WARNINGS -Wall -Wextra -Werror -O1 nova.c nova/runtime_v2.c nova/run_host.c nova/cli.c ntasm.c frontend.c codegen.c x64.c conformance.c -o nova.exe
nova.exe check module.nova
nova.exe run app.nova dependency.nova -- --text argument --u64 42
nova.exe build app.nova dependency.nova -o NEW.efi
```

`--buffer N` supplies writable managed storage and prints its bytes as hex for
small buffers. Run JSON is emitted **after** owned runtime cleanup. An injected
close failure now yields `ok:false,error:8,cleanup_ok:false,exit1`; an injected
PE temporary close failure publishes no final output. No existing output is
replaced. Tests are in `cleanup-red/cleanup-green` and v6 CLI results.

## Next work, distinct from readiness

The user authorized moving **all NTASM** to Nova. Port the general PE writer,
encoder, frontend/checker, NTIR/NXO, linker/build and CLI with the C version as
an oracle. Run each component's full existing corpus and then end-to-end
programs/reconstructions. The constant-return PE witness does not cover the
general writer's relocation tables, multiple pages or arbitrary sections.

Only verified parity and reconstruction can justify retiring a C producer.
The current Nova compiler/runtime are still C bootstrap tools; complete C
withdrawal also needs the later verified native/Nova compiler reconstruction
route. None of these later milestones is inferred from this readiness gate.
