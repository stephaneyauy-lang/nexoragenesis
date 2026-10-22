# A8(4) — the self-hosting contract, and the trust root it names

**Status: the contract is written; the first step was NOT taken, and this
document says why in the terms the brief allows.** Nothing in this file weakens
`REPLAY.md`, and the limit paragraph in that file is still there, verbatim,
byte for byte — measured in §7.

The criterion A8(4) demands is *« construction du compilateur v0 depuis ces
sources par la chaîne maison ; aucune substitution cachée par le producteur C »*.
A contract that does not say **which file is trusted** is not a contract, so
§1 names it, in a sentence meant to be quoted.

---

## 1. The trust root, in one quotable sentence

> **The trust root of the v0 self-hosting claim is
> `compiler/c/nova/frontend/nova.c` — the C host that compiles the 59 `.nova`
> modules that constitute the v0 producer — together with the 44 C entry points
> its generated code reaches; no artefact in this repository can execute a
> `.nova` module without them, so they are trusted and never verified, and every
> claim of self-hosting that rests on them is a claim about a C program.**

That sentence is falsifiable, and §6 falsifies part of it on purpose.

**There is a second, older trust root, and confusing the two is the error this
document exists to prevent.** `legacy/ntasm-s0/fixed-point/REPLAY.md:16-20`
names its own: the S0 launcher `compiler-host.NTASM1.EFI`, *"the result, not an
independent input"*. That one is **A8(3)**, which is CLOS. This document is
about **A8(4)**, whose trust root is a different file in a different language.
`REPLAY.md`'s limit paragraph is about A8(3) and is **not** evidence about
A8(4); `ngbuild.sh:1436` says the same thing in its own `not_asserted=` line.
Neither paragraph says anything about the C host, and nothing in the tree says
anything about the C host. **That silence is the finding.**

---

## 2. What is an INPUT, what is a RESULT, and what is OUT OF BAND

Every path below was verified to exist on disk on 2026-09-30 with
`sha256sum` and `stat -c%s`. The column is the reason, not a label.

### 2.1 The S0 loop — A8(3), CLOS, and its own trust root

| role | path | bytes | sha256 (16) |
|---|---|---|---|
| **input** | `legacy/ntasm-s0/compiler-host.ntasm` | 43793 | `1d72d9756f8f6d08` |
| **input** | `legacy/ntasm-s0/modules/compiler-core.ntasm` | 54798 | `fc1c5d5a2d001e15` |
| **OUT OF BAND** | `legacy/ntasm-s0/fixed-point/compiler-host.NTASM1.EFI` | 17408 | `82826f458aff21d4` |
| **OUT OF BAND** | `legacy/ntasm-s0/fixed-point/compiler-core.NTASM1.EFI` | 20992 | `a02425be642b8395` |
| recipe | `legacy/ntasm-s0/fixed-point/REPLAY.md` | 7600 | `65edc7d532f7fae6` |
| provenance | `legacy/ntasm-s0/fixed-point/README.md` | 4588 | `2628b10fb97beed8` |

The two PE are out of band because **nothing in the tree builds them.** They are
consumed, never produced: `legacy/tools/coldproof/ngbuild.sh:1348-1350` `mcopy`s them
into a throwaway ESP, and `out/c-bootstrap/nova/evidence/S0FixedPoint/replay.sh`
does the same. `fixed-point/README.md:5-9` records they were *copied in* on
29 September 2026 from `out/`, and `:44-48` records the load-bearing fact —
the producer is its own input, there is no third PE.

### 2.2 The v0 loop — A8(4), OPEN, and its trust root

| role | path | measured |
| **input** | `compiler/nova/*.nova` | 59 modules, 30 499 lines (counted 2026-09-30; a sibling lot landed a module during this one, so the line total is a dated measurement, not a fixed constant — the module count and every construct count in §3 were re-measured after it and are unchanged) |
| **input** | `tests/nova/tests/*-entry.nova` | 100 entry modules |
| **OUT OF BAND** | `compiler/c/nova/frontend/nova.c` | 2546 lines — compiles the tree above |
| **OUT OF BAND** | `compiler/c/nova/runtime/runtime_v2.c` | 396 lines — 13 callbacks |
| **OUT OF BAND** | `compiler/c/nova/runtime/run_host.c` | 67 lines — the only image mapper |
| **result** | `out/c-bootstrap/ntasm/ntasm` | sha256 `25d8e4b824d2551a…`, built by `scripts/ntbuild.sh` from C |

**The `.nova` tree is the v0 producer, written in v0, and the C host is what runs
it.** `ngbuild.sh:1014-1016` states the mechanism in the project's own words:
*"a module is not compiled into anything: it is opened, by path, by a process
that is already running."* That process is C.

**The complete C surface a `.nova` module can reach — 44 entry points:**

| surface | count | where |
|---|---|---|
| compile-time exports | 5 | `nova.h:11-18`, defined `nova.c:2523,2527,2530,2534,2543` |
| runtime v2 callbacks | 13 | `runtime_v2.h:9` (`calls[12]`) + `:12` (`copy_bytes`) |
| v2 control functions | 4 | `runtime_v2.h:66-69` |
| image loader | 2 | `run_host.h:10-11` |
| Nova-spelled intrinsics | 12 | recognised by name in `nova.c:1034-1169` |
| runtime v1 callbacks | 8 | `runtime.h:21-22` — **unreachable; no build links `runtime.c`** |

36 of the 44 are reachable in any build; the 8 v1 callbacks are dead code that
`ngbuild.sh:812-818` records as a falsified "not a gate" claim.

**The `.nova` tree is the v0 producer, written in v0, and the C host is what runs
it.** `ngbuild.sh:1015-1016` states the mechanism in the project's own words:
*"it is opened, by path, by a process that is already running."* That process is
C.

The intrinsics are not decoration. Measured over the `.nova` tree:
`runtime()` 1134, `len(` 813, `rt_free(` 759, `alloc(` 349, `slice(` 36,
`rt_close(` 9, `rt_open_new(` 7, `rt_write(` 7, `rt_open_read(` 1, `rt_read(` 1,
`rt_copy(` 1, **`rt_diag(` 0**. That last zero is the positive control on the
count: the instrument can report a zero for one member of a family it does
report non-zero for eleven others.

---

## 3. The measurement that decides this lot: the two dialects do not meet

This is the one new fact, and it was established by **running** the producer,
not by reading a comment about it.

```
$ ./out/c-bootstrap/ntasm/ntasm check legacy/ntasm-s0/compiler-host.ntasm
legacy/ntasm-s0/compiler-host.ntasm:1:1: E200: expected 'module'
EXIT=1
```

The v0 producer cannot read the S0 sources. And the reverse — can the v0
producer read **its own** source, the `.nova` tree?

```
$ for m in ast lexer pe nxo ntir machine_ir x64_lower_nxo macro_expand; do
    ./out/c-bootstrap/ntasm/ntasm check compiler/nova/$m.nova; done
ast              ast.nova:6:1:          E200: expected 'target'
lexer            lexer.nova:4:1:        E200: expected 'target'
pe               pe.nova:4:1:           E200: expected 'target'
nxo              nxo.nova:2:1:          E200: expected 'target'
ntir             ntir.nova:85:1:        E200: expected 'target'
machine_ir       machine_ir.nova:3:1:   E200: expected 'target'
x64_lower_nxo    x64_lower_nxo.nova:1:22: E200: expected 'target'
macro_expand     macro_expand.nova:3:1: E200: expected 'target'
```

**Eight of eight, on the first construct, all the same error.** The v0 producer
cannot compile the `.nova` tree, so *the v0 producer cannot build itself* — not
"not yet", but structurally, as measured.

**And the gap is NOT the missing `target` line.** I tested that, because it is
the difference between a one-line fix and a wall. Prepending
`target x86_64-nexora-none` to a **copy** in `/tmp` — never to the tree — moves
the error without removing it:

```
lexer.ntasm:5:1: E200: unsupported top-level declaration
ast.ntasm:7:1:   E200: unsupported top-level declaration
```

v0 recognises exactly **eight** top-level declarations — `default_abi`,
`features`, `import`, `const`, `comptime`, `macro`, `section`, `stub_table`
(`frontend.c:5107-5162`). The `.nova` tree uses top-level forms v0 does not
have:

- `export fn` — **361** occurrences; v0 has no top-level `fn` at all, only
  `section { fn … }`
- `export struct` — **17** occurrences, in the nine widest modules
  (`lexer`, `ast`, `pe`, `nxo`, `nxo_pe`, `ir_image`, `macro_splice`,
  `constant_eval`, `diagnostics`)
- `buf<u8>` / `buf<u64>` — **2484** occurrences; v0's type table has neither.
  Its only two `buf`/`struct` string hits are prose
  (`frontend.c:4468` *"structured stub requires stack_align 16"*,
  `:4501` *"structured executable stub must use .text"*), not types.

So the dialect gap is **structural**: two record/buffer systems and a different
top-level grammar. Hand-translating a single `fn` into v0 form *is* accepted
(`NTASM_C_CHECK_OK`), which is why this is a wall and not a syntax error — the
per-function body language is shared, and everything around it is not.

---

## 4. The decision, and its cost of reversal

The brief permits a first step only if it is mechanical, and requires stopping
otherwise:

> *« If it is not mechanical — if it requires choosing a language, a bootstrap
> order, or a trust anchor that is a judgement rather than a derivation — stop
> and write the contract plus that choice, with its cost of reversal, and do not
> start building. »*

**Decision, one line: no first step is taken; the bootstrap order is a
judgement and is deferred to lot 40, which is where the plan puts
successive generations anyway.**

The reason is measured, not cautious. Making the v0 producer self-hosting needs
a decision *before* any code: which of three routes is the anchor —

1. **extend the S0 launcher** to a v0 consumer (it is 17 408 bytes of S0, loads
   one PE, and `REPLAY.md`'s own limit already says it is unverified);
2. **write a Nova launcher in `.nova`**, executed by the C host — which uses the
   trust root as an input and so proves nothing about it;
3. **write a launcher in NTASM v0**, compiled by the C producer — same defect.

Routes 2 and 3 both *consume* the trust root rather than replacing it, so a
green result from either would be a claim about a C program wearing a
self-hosting label. Only route 1 removes it, and route 1 is the largest. **That
choice is worth more than a first file, and it is not mine to make silently.**

**Cost of reversal: low, and that is the point of stopping.** Nothing was built,
so nothing depends on the wrong choice. Reversing means re-reading §3, which is
four commands. Had a launcher been started under route 2 or 3, reversing would
have meant deleting a PE that a gate had already been made to attest — the exact
shape `AGENTS.md` warns about when it says a committed harness that reported
success had in fact hidden a failing state.

---

## 5. Which A8 obligation each step moves — and which it does not

| obligation | state before this lot | moved by this lot | state after |
|---|---|---|---|
| (1) C reproducibility | TENU | **no** — untouched, and nothing here could weaken it | TENU |
| (2) C/Nova convergence | TENU | **no** — the byte-parity gates are unaffected | TENU |
| (3) S0 fixed point | CLOS | **no** — and deliberately so; see §7 | CLOS |
| (4) v0 self-hosting | OPEN, not started | **no progress, and that is the deliverable** — the blocker is now *named and measured* instead of *stated* | OPEN, characterised |

**(4) is not advanced, and this document does not pretend otherwise.** What
changed is that A8(4) had two candidate blockers — *a C host that must be
replaced* and *a launcher that is out of band* — and the plan did not say which.
§3 measures that they are **one** blocker wearing two coats, because the C host
is the only thing that can execute the `.nova` tree, and it cannot execute its
own source. A lot that had started writing a launcher under route 2 would have
produced a green gate and moved nothing; that is the failure this file exists to
prevent.

---

## 6. Negative proof — what would falsify this contract, and one thing that does

A contract that cannot be wrong is an assertion. Three falsifiers, each stated
so a later lot can run it:

1. **A non-C host that executes `.nova`.** If any artefact loads and runs a
   generated Nova image without `run_host.c`, §1 is wrong. *Measured: not
   found.* Seven independent searches, all negative — no `.nova` launcher or
   runtime anywhere; zero occurrences of "nova" under `legacy/ntasm-s0/`;
   the only UEFI Nova consumer, `nova/uefi_probe.c:1`, is stamped
   `BOOTSTRAP_C_TEST` and written in C.
2. **The v0 producer accepts the `.nova` tree.** If `ntasm check` ever returns 0
   on `compiler/nova/`, §3 collapses and the wall is a front-matter
   problem. *Measured: it does not, 8 of 8.*
3. **The gate goes red when the claim is broken.** A contract verified only by
   green runs is verified by nothing.

**Falsifier 3, demonstrated.** The §3 probe was run against a positive control
in the same shell, in the same second, so the instrument is shown able to say
*yes*:

```
positive control   NTASM_C_CHECK_OK phase=frontend     <- the probe CAN say yes
negative  lexer.nova   lexer.nova:4:1: E200: expected 'target'
```

And the corpus census is published in §2.2, so a later reader can check that
`rt_diag`'s zero is a zero and not a broken instrument.

---

## 7. `REPLAY.md` is untouched — verified, not asserted

The limit paragraph, read from disk, byte for byte:

> **Two components only.** `module-host`, `native-lexer`, `native-source` and the
> rest of the S0 tree are **not** replayed and **not** claimed. Two green is not
> six. The trust root is still out of band: these files are the *result*, not an
> independent input, so this proves determinism and self-reproduction, not that
> the launcher is correct — by the definition of a trust root.

`REPLAY.md` is 7600 bytes, sha256 `65edc7d532f7fae6…`, and this lot did not
write to it. Two independent statements of the same limit are also in the tree
and were read, not paraphrased:

- `legacy/tools/coldproof/ngbuild.sh:1436` — `not_asserted=…REPLAY.md_is_the_result_and_not_an_independent_input_so_this_is_determinism_not_the_correctness_of_the_launcher…`
- `scripts/ntselfhost.sh:608` — `echo "NTSELFHOST_BOUNDARY fixed_point_proven=no"`,
  a literal in the project's own script, re-read from disk for this document.

**This lot did not weaken the recipe to make the contract satisfiable.** The
contract is satisfied by *naming* the trust root, not by removing it.

---

## 8. What a later lot should do first

Not a plan — the next single measurement, which is cheap and decides the
bootstrap order:

> **Count, per `.nova` module, the v0-legal rewrite distance to its own source:**
> how many of the 361 `export fn` fit inside a `section`, and how many of the
> 17 `export struct` and 2484 `buf<T>` have **any** v0 representation today.

If `buf<T>` has none, the `.nova` tree is not portable to v0 at all, and the
honest route is route 1 — extend the S0 launcher — with its cost stated up
front. If a representation exists, routes 2 and 3 become worth pricing. **That
answer is a derivation. The bootstrap order is a judgement, and it is not this
lot's to make.**
