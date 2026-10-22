# Historical port-prep-v4 checklist

The three bootstrap-readiness gaps below were closed on 6 September; see [READINESS.md](READINESS.md) for current evidence and the separate NTASM migration work.

# Nova Bootstrap — port preparation, 5 September 2026

Status: **the whole NTASM migration is not yet cleared**. The user has chosen
to move every NTASM producer to Nova when Nova is ready. Do not substitute a
successful decimal parser or PE witness for that decision.

Current immutable package: `out/c-bootstrap/nova/port-prep-v4/`.
Previous `bootstrap-v2` is preserved and describes historical execution ABI1.

## Implemented and exercised

| Requirement | Current evidence |
|---|---|
| Direct Nova to typed IR/x64/PE | `nova_compile_many_v2`; no generated-C step |
| u8/u16/u32/u64 and i8/i16/i32/i64/bool | 45 integer tests; signed compare/div/rem/arithmetic shift, widths in arrays/records, divide overflow and invalid shift guarded |
| Functions, parameters, returns, locals, mutation | v2 and aggregate suites; named parameters are entry snapshots |
| if/else/while/break/continue | actual native execution; outside-loop controls rejected |
| Strings, escapes, NUL, arrays and records | strings/byte literals, generic `buf<T>`, checked fields, recursive record references, null, buffer/record returns |
| Multi-file modules/imports | 15 module tests: qualified calls, visibility, missing imports, cycles, same names in different modules |
| Bounds and lifetime discipline | generation-tagged handles; borrowed readonly storage, freed aliases/views, RHS releasing assignment target before store |
| Independent propagated errors | Context ABI2; u8 callees propagate errors without narrowing/colliding with a u64 result; stops later caller effects |
| Memory/files/diagnostics runtime | versioned callbacks; capped allocation registry, exclusive new files, stale handle checks, cleanup |
| Usable compiler/run tool | native Windows `nova.exe check/build/run`; 7 CLI cases plus library-only check |
| UEFI runtime route | real `.nova` -> PE -> LoadImage -> ABI2 entry -> file write/read -> 42; checked raw readback `42`, zero pools/files, firmware/HMP/exit0 |
| Genuine component port | decimal parser independent 1271-case corpus (historical ABI1); a bounded four-section PE writer implemented in `.nova`, dynamic 42/43/u64max identical to C, produced PE runs in QEMU |
| High-level backend mode | explicit `NtFFunction.high_level_expressions=1`; machine-v5; NTASM default mode remains 0 |

The final integrated v4 ASan/UBSan run is: v2 47, aggregates 30, modules 15,
integers 45 checks, all zero failures. Windows CLI 7/7 passes. The same real UEFI
file program shrank from 254464 to 23040 PE bytes (11.04x) after the explicit
expression-mode integration and still returns 42 with correct file readback.

## Exact remaining work before declaring the full-port preparation finished

1. **Scale limits to the real NTASM source inventory and prove them.** Current
   compiler caps remain 65535 tokens, 256 functions, 4096 total variables
   including lowering temporaries, 32768 expressions and 32768 statements.
   Those are tested limits, not evidence that the entire port fits. The real C
   tree has at least 105 static frontend functions, 57 codegen helpers and 14
   x64 helpers, plus public/format/CLI functions. A representative module-size
   build and then an actual substantial NTASM translation must settle capacity.
2. **Settle larger parameter lists.** Nova still permits four scalar ABI slots;
   a buffer consumes two. Records allow argument packing, but the complete port
   has not been audited against that convention. Machine-v5 now supports the
   standard EFI scalar stack ABI up to 64 parameters; Nova has not opted into
   that extension or tested it yet.
3. **Run the decimal reference corpus on the final ABI2 package.** Its original
   ABI1 corpus and newer ABI2 CLI max-value case are distinct evidence. Do not
   claim the 5107 historical checks were rerun in ABI2.
4. **Freeze the final readiness contract and regression recipe against those
   scale/API results.** The current package is reproducible port preparation,
   not an assertion that every C module already translates to Nova.
5. **Then port all NTASM modules** (frontend/checker, encoder, NTIR/NXO/PE,
   linker/build/CLI) with module-by-module reference parity and full end-to-end
   suites. The current PE witness only covers the constant-return four-section
   image profile; it is not the whole general PE/NXO writer.

Nova compiler self-hosting/GPU are later profiles in the current bootstrap
specification. The current Nova compiler and host runtime still require the C
bootstrap toolchain. Removing C from normal production ultimately needs a
verified native/Nova compiler reconstruction route; three PE byte matches do
not establish that.

## API and execution

- `nova_compile_many_v2(NtFInput*,count,NtArtifact*)` builds code; `nt_make_pe`
  packages it. `nova_check_many_v2` also supports library-only inputs.
- The public generated entry is `u64 entry(NovaContextV2*, const u64*args,
  u64 scalar_count)`. Context is 48 bytes, version 2. R15 is private context
  state inside generated functions and is preserved at the public ABI boundary.
- Buffers cross that boundary as generation-tagged handle/element-count pairs,
  not raw pointers. The host registers borrowed memory with `nova_borrow_v2`.
- Runtime descriptor ABI2 has version/size, 12 four-slot callbacks and state.
  Callback indexes and the execution context are in `runtime_v2.h`.
- Runtime errors are sticky and separate from the full u64 result: bounds4,
  division-by-zero5, descriptor/allocation6, lifetime7, I/O8, readonly9,
  argument10, signed-division overflow11, invalid shift12. Compiler diagnostics
  retain source/line/column; runtime errors retain source/byte offset.
- Records use eight-byte field slots (managed fields contain handles); typed
  arrays use their element width. References and views are checked on access.
  Freeing a record does not recursively free separately owned child handles;
  context destruction releases remaining owned allocations and files.

## Build the frozen package

In `port-prep-v4/sources`, the native Windows command used is:

```text
"C:\Program Files\LLVM\bin\clang.exe" -std=c11 -D_CRT_SECURE_NO_WARNINGS -Wall -Wextra -Werror -O1 nova.c nova/runtime_v2.c nova/run_host.c nova/cli.c ntasm.c frontend.c codegen.c x64.c conformance.c -o ../nova.exe
```

The package contains the coherent machine-v5 sources. `conformance.c` is a real
link dependency of that frontend version. GCC uses the same files and can add
`-fsanitize=address,undefined -fno-omit-frame-pointer -g` for the included tests.

```text
nova.exe check examples/pe-writer-v2.nova
nova.exe run examples/hello.nova
nova.exe run examples/decimal-u64.nova -- --text 18446744073709551615 --buffer 16
nova.exe run examples/pe-writer-main-v2.nova examples/pe-writer-v2.nova -- --text NEW.efi --u64 42
nova.exe build examples/uefi-runtime-v2.nova -o NEW-NOVA.efi
```

CLI build writes a complete sibling temporary, then publishes without replacing
an existing output. Native execution maps text RX, read-only data R, and writable
data RW. The UEFI adapter is deliberately `BOOTSTRAP_C_TEST`, only tested under
QEMU/OVMF, and remains separate from final OS code.
