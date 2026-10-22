# c-bootstrap-controlflow

The class the seven pinned members of `../c-bootstrap/` do not reach:
**control flow.** This directory is named for the property its members break,
not for its position in a sequence, and the property is stated here so the name
can be checked instead of taken on trust.

## The enumeration the property was read off

Counted by reading the seven files, not by taking any report's word for it.
`one return` counts returns in the entry's body **as the producer sees it**, so
`comptime-macro` is counted after its macro is expanded.

| member           | sections | fns | non-entry fn | branches | returns in the entry |
| ---------------- | -------- | --- | ------------ | -------- | -------------------- |
| `return42`       | 1        | 1   | 0            | 0        | 1                    |
| `return43`       | 1        | 1   | 0            | 0        | 1                    |
| `returnmax`      | 1        | 1   | 0            | 0        | 1                    |
| `helper-first`   | 1        | 2   | 1            | 0        | 1                    |
| `static-data`    | 2        | 1   | 0            | 0        | 1                    |
| `mutable-data`   | 2        | 1   | 0            | 0        | 1                    |
| `comptime-macro` | 1        | 1   | 0            | 0        | 1                    |

**The property is the last two columns together: every one of the seven is
straight line with one exit** — no `if`, no label, no `jmp`, no loop, and exactly
one `return`, which is also the last statement of the body.

The description the seven used to carry was *« one function, and it is the
entry »*. `helper-first` destroyed that. What replaced it is **not** *« two
functions »*: counting functions is the question the seventh member answered,
so the property that survived it is one it happens to satisfy. Control flow is a
different axis from declarations, and it is the axis on which the seven are
uniform and the second corpus is empty — no row of `BOUNDARY` in
`nova_corpus_convergence.c` contains a branch either.

Two further columns would also have come out uniform, and are recorded so this
member is not mistaken for the first probe of them: **the entry takes no
parameters in all seven**, and five of the seven have no data section. Both
members here preserve both, deliberately, so the branch is the *only*
difference between them and `return42` — a single-variable experiment against a
member the gate already measures.

## `branching-entry.ntasm` — the member that breaks it

An entry whose body is `if true { return 42 } else { return 43 }`.

The condition is a **boolean literal**, on purpose. The first version of this
member used `if 1 < 2` and is preserved next door under its own name, because it
turned out to be a different and larger finding. A literal keeps the experiment
single-variable: a parameter, a `let` or a data section would each have changed a
second thing, and two changed things prove nothing about either.

### What it actually did, against what was expected

**Expected, written into the gate before it was ever run: a refusal, 800.**
Measured on a green tree: **it converges, byte identical.** The expectation is
left in the gate file, marked wrong, and not edited into agreement.

Both object streams are 1520 bytes and both are
`sha256 866408105946f00ede0bf3c90d0d129c5ff56ff505a00646ceafc048d8d9e963`.
Both PE streams are 3584 bytes and both are
`sha256 1af76e82545b4f39885043184b17bc65ca703c6bf7ebe33b818151b4f8226026`.
All three directions ran — `C_TO_NOVA`, `NOVA_TO_C`, `PARITY`. The producer
does **not** silently drop an arm, which was the worse of the two outcomes the
expectation named.

**Why the prediction failed.** Not because the producer is more capable than the
reasoning assumed. The condition is a **literal**, and the reference folds it in
its own front end before anything is lowered. The body that reaches the
producer therefore has **one** return, not two, and the frameless word-record
path was never asked the question the prediction asked it.

### What this row covers, and what it does not

Covered from this date: a parameterless, data-free, single-function entry whose
body is an `if`/`else` **whose condition the front end can fold**.

Not covered, and not addressed by this row in any way: an `if`/`else` whose
condition is **computed at run time** — the shape that actually reaches the
word-record path with two live returns. Reaching it needs either a parameter on
the section, which the gate's own header names as the condition for delegating
to the framed producer, or a `bool` local, and a `let` makes the entry a framed
body. So the residue sits on the framed path. That member is the next one to
write, on a green tree. This row is deliberately not it.

### A number that moved between two runs of the same binary

The first run of this row answered **800** — the prediction. It was taken at
05:00 on a tree where four rows had moved off their pinned convergence
(`framed_let_const`, `framed_let_name`, `framed_let_call`,
`call_private_arity0`), so the tree was demonstrably not in the state the table
describes. Those four are all framed-class members; this one carries no `let`
and no call, so the repair was argued not to be on its path.

**That argument reached the wrong conclusion**, which is the useful part. The
tree closed at 05:05 and the same binary, on the same source, answers 0. Pinning
800 on the contaminated run would have written a green gate that meant nothing.

## `comparison-condition-refused.ntasm` — a divergence, not a member

**This file is not a corpus member and the gate does not measure it.** It is
kept on disk so the claim below is re-derivable rather than asserted.

The C reference **refuses** it: `nt_object_compile` answers `401`, *« constant
expression outside result range »*.

**The Nova frontend accepts the same shape.** `tests/nova/tests`,
gate `condition_types`, case *« two bounded numeric literals »*
(`tests_ntasm_condition_types.c:67`), expects `0`.

Every divergence measured in this project until now has been one direction —
**the product refuses what the reference builds**. This one is the other
direction, and it is the direction that matters more: a product that accepts
what the reference refuses will **emit an object the reference would not**, and
every byte-parity gate in this tree is blind to that by construction, because
they all start by asking the reference to build the same source.

### Why the reference refuses it, located

`compiler/c/ntasm/frontend/frontend.c:1782-1790`, in `infer`, case `NTF_X_BINARY`:

* a comparison gets `x->type = bool` (line 1776-1777);
* `constant_value` then succeeds, because `1 < 2` folds (line 1782);
* the range check at line 1786 asks `literal_fits(bool, 1, 0)`;
* `literal_fits` (line 1324) begins `if (!integer_kind(t->kind)) return 0;`, and
  `integer_kind` (line 1321) is `k >= NTF_T_U8 && k <= NTF_T_I64`. `NTF_T_BOOL`
  is **9** and `NTF_T_I64` is **8** (`frontend.h:63-77`), so `bool` is not an
  integer kind and `literal_fits` returns 0.

So the refusal is not about the operands. **It is that the reference has no
`bool` case in its constant range check and applies the check to a
`bool`-typed constant anyway.** The consequence is wider than this file: any
`if` whose condition is a comparison that constant-folds is refused, and any
comparison that does *not* fold — `if x == 0` with a parameter, which the
reference does accept — takes the `else` at line 1791 and is never range-checked
at all.

### Is the product's acceptance correct?

`spec/ntasm/ntasm.md:226-231` says the condition of an `if` must be *proved* `bool`,
and that the initial profile proves *« les comparaisons »* — comparisons,
unqualified. Nothing in that paragraph exempts the constant ones. So the
reference's `401` contradicts the spec text, and the `condition_types` case
quoted above is a **Nova test asserting a divergence**: it expects `0` for a
source the reference declines.

### ⚠ THIS IS A SPECIFICATION-VERSUS-REFERENCE DISAGREEMENT, NOT A PRODUCT DEFECT

Write that down separately from the rest, because it is the shape of thing
that gets silently resolved in the wrong direction. **The specification is on
the product's side here, not the reference's.** A reader who finds the
reference refusing a `bool` condition and no note will conclude the reference
is right, because in every other divergence in this project it was — the
product was the one refusing. **That inference is wrong here, and it is wrong
in the one direction that matters.**

The three facts, so the disagreement can be checked rather than believed:

| | |
| --- | --- |
| the reference | declines a `bool` constant in a range check it has no `bool` case for (`frontend.c:1324`, `:1321`, `frontend.h:63-77`) |
| the specification | says comparisons prove `bool`, unqualified (`spec/ntasm/ntasm.md:226-231`) |
| the product | accepts it, and a **Nova test asserts that it must** (`condition_types`, `tests_ntasm_condition_types.c:67`, expects `0`) |

Every other divergence measured in this project has been
**product-refuses-reference-builds**. This is the first
**specification-versus-reference** one, and the first in the direction where
the reference is the one out of step. Two consequences worth carrying:

* **The byte-parity gates cannot see this class at all.** Every one of them
  begins by asking the reference to build the same source, so a source the
  reference declines simply leaves the comparison unrun — a void that reads
  as a pass.
* **Resolving it by making the reference match the product is the cheap fix
  and the dangerous one**, because it would close the first
  specification-versus-reference disagreement in the project by editing the
  oracle instead of recording it.

**What resolving it correctly would take** (not attempted here, and not this
lot's business): either a `bool` case in `literal_fits` so a folded comparison
  is not range-checked against a type the check cannot express, or a
  specification amendment saying constant-folded comparisons are out of the
  initial profile. Both are decisions about the language, not about a
  producer, and neither is visible to a gate.

### What does the product emit for that shape?

**Not established, and it is not a claim this README is entitled to make.** It
needs a run of the Nova producer on this file, and the producer was mid-repair
under another lot when this was written. The honest statement is that the C-side
refusal was measured and the Nova-side emission is unknown.

## How the verdict above was taken, and what it is therefore not

**The verdict was taken WITHOUT AddressSanitizer and WITHOUT
UndefinedBehaviorSanitizer**, and outside `ngbuild.sh`'s own build path. The
installed `gcc` has no `libasan`/`libubsan`, and a gate run without them is a
gate that **cannot see a use-after-free or an out-of-bounds in the object it
just built**. So `failures=0` on this row means the two producers agreed on
these bytes, and it does **not** mean the run was memory-clean. Do not read it
as more than that.

(`nova_corpus_convergence` is a declared `NOVA_GATES` entry, and
`ngbuild.sh` runs those only when `custom=0` — that is, only in full-suite mode.
So `ngbuild.sh <gate>` cannot reach this gate at all, and the run was made with
the same compiler and flags by other means. That is a deviation from the
project's one build path and is stated here rather than left for a reader to
discover.)

One more thing a reader six weeks out would otherwise get wrong: the reference
PE of a **refusal** row is **measured and printed** on every run and is **not
asserted**. An assertion on it was written and then removed, because it turned
`imported_callee_macro` and `imported_module_no_call` red — the C reader
declines the reference's own object for a source carrying an unresolved import
(`nt_object_materialize 800 unresolved object import`). The measurement stayed;
the coupling did not. So those two rows are known to be refusals of the
**product**, and the reason they are not refusals of the harness is that nothing
in the row is compared against a Nova artefact.

## The next member: named, specified, and deliberately not written

**An `if`/`else` whose condition is computed at run time** — the shape with two
live returns, which is the one `branching-entry.ntasm` does not reach because
its literal condition is folded away before lowering.

It needs either a parameter on the section — which this gate's own header names
as the condition for delegating to the framed producer — or a `bool` local, and
a `let` makes the entry a framed body. **Either way it routes to the framed
path.**

It was not written because that path was under repair by another lot while this
row was measured, and a number taken there would have been a number about their
repair. **The reason is the repair, not the difficulty.** Write it on a green
tree, as its own `BOUNDARY` row, with its expectation registered before the run
the way `branching_entry`'s was.

## Reading the row

`tests/c/nova/nova_corpus_convergence.c`, the `BOUNDARY` table,
row `branching_entry`. The comment above it carries the enumeration, the
pre-registered expectation, and the statement of which side a failure would be
on.
