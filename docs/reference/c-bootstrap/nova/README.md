# Current Nova Bootstrap

Current bootstrap readiness and the separately outstanding full NTASM migration are documented in [READINESS.md](READINESS.md). The material below is historical ABI1 documentation preserved for proof replay.

# Nova Bootstrap C — ABI 1

This is `BOOTSTRAP_EXTERNAL_C`, a temporary compiler/runtime tool, not the OS
or the final Nova compiler. `nova_compile[_many]` in `../nova.h` parses Nova,
checks types and lexical scope, builds typed `NtFProgram`, and calls the
shared `nt_codegen_x64` encoder directly. No Nova source is converted into C
or sent to GCC/Clang. Results use `NtArtifact` ownership and `nt_make_pe`.

The useful component is `examples/nova-bootstrap/decimal-u64.nova`: its
machine code parses decimal u64 values with checked overflow and exact byte
positions. A separate status result preserves every possible u64 value,
including `18446744073709551615`. Its independent reference corpus contains
1271 cases; the host reference does not perform the compiled computation.

## Current language

- `fn name(arg:type,...) -> type { ... }`, forward calls and up to 64 input
  files in one global function namespace. A declaration cannot cross files.
- `u8`, `u64`, `bool`, `buf<u8>`, opaque `runtime`. Integer operations wrap;
  `u8(expr)` explicitly truncates and `u64(expr)` widens. No implicit narrowing.
- `let`, `let mut`, assignment, lexical blocks/shadowing, return, if/else,
  while. Variables require an initializer and all functions require a return
  path. Calls/expressions run left to right; an assignment evaluates and checks
  its indexed target before the assigned expression.
- Bounded buffer read/write, `len`, `slice`, `alloc`. Buffer parameters occupy
  pointer and length slots; ordinary values occupy one slot. Maximum four
  ms_abi slots per function. Buffers may be aliased locally, not returned.
- `//` comments, decimal and hexadecimal u64 literals, positioned errors,
  transactional compile failure. Limits: 4 MiB per source, 65535 tokens,
  256 functions, 4096 variables including temporaries, 32768 expression and
  statement nodes each, nesting 128.

## Runtime

`runtime.h` declares the 88-byte version-1 descriptor: version, size, opaque
context and eight ms_abi callbacks. Every callback has four machine slots
`(context,a,b,c)`. Generated calls verify a nonnull descriptor, version 1,
size at least 88, and a nonnull selected callback before invoking it.

| Nova operation | Callback arguments after context | Result |
|---|---|---|
| `alloc(rt,capacity)` | capacity,0,0 | pointer; 0 means failure |
| `rt_free(rt,buffer)` | pointer,length,0 | 0 or UINT64_MAX |
| `rt_open_read(rt,path)` | pointer,length,0 | handle or UINT64_MAX |
| `rt_open_new(rt,path)` | pointer,length,0 | fresh writer or UINT64_MAX |
| `rt_read(rt,handle,buffer)` | handle,pointer,length | bytes or UINT64_MAX |
| `rt_write(rt,handle,buffer)` | handle,pointer,length | bytes or UINT64_MAX |
| `rt_close(rt,handle)` | handle,0,0 | 0 or UINT64_MAX |
| `rt_diag(rt,message)` | pointer,length,0 | 0 or UINT64_MAX |

The host adapter zeroes allocations, caps one allocation at 16 MiB and total
live allocation bytes at 64 MiB, tracks 128 allocations and 128 generation-tagged
file handles, rejects non-owned I/O buffer ranges and double/stale releases,
and creates files exclusively. Paths reject NUL and exceed-4096 lengths.
`nova_runtime_destroy` releases its remaining resources; it does not release
borrowed arguments. Initialize an unused descriptor once, destroy before reuse.

The runtime uses host libc only for memory/files/diagnostic transport. Generated
Nova code performs all character classification, loops, arithmetic and buffer
mutation. `runtime-roundtrip.nova` demonstrates the separation.

## Explicit limits still open

This is a useful bootstrap subset, not complete Nova or NTASM B2.1. There are
no string literals, aggregate/user-defined types, module imports, buffer return
ABI, self-hosting, GPU support, or UEFI runtime adapter yet. Native Linux and
selected Windows executions are evidence; no UEFI runtime proof is implied.

Buffers carry bounds, not a borrow checker. Host ABI callers must provide live
readable/writable storage matching the advertised length. After explicit free,
Nova aliases must not be used. Runtime file I/O validates ownership, but ordinary
generated loads/stores do not consult an allocation registry.

Bounds, divide-by-zero and runtime-descriptor/allocation errors currently return
`0x8000000400000000`, `0x8000000500000000`, `0x8000000600000000` respectively from
the affected function. They are not a language-wide exception channel and can
collide with ordinary u64 results or be narrowed by a caller returning u8.
Programs requiring reliable error propagation must currently use explicit u64
status-returning functions and separate result buffers, as the decimal component
does. A separate propagated error ABI remains required before general compiler
porting can be called robust.
