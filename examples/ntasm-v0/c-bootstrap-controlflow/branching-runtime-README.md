# branching-runtime — the member that reaches the framed path with two live returns

This is the README for **one member**, `branching-runtime.ntasm`, and for one
row of the `BOUNDARY` table in
`tests/c/nova/nova_corpus_convergence.c`. It is a separate file
from `README.md` beside it because that file is the record of a different
member and of a different, and now partly refuted, explanation. Nothing in
`README.md` was edited to agree with this one; the disagreement is recorded
below instead, and §4 says which of the two sentences in it is wrong.

## 1. The member

```
module bootstrap.branching_runtime
target x86_64-nexora-uefi
section .text {
    export fn main(in x:u64 @rcx) -> u64
    effects {}
    clobbers {rax} {
        if x == 0 {
            return 42;
        } else {
            return 43;
        }
    }
}
```

An `if`/`else` whose condition is **computed at run time**, which is the shape
`README.md` names at its `:220-235` as *the next member: named, specified, and
deliberately not written*. It is written here, and the reason it was not
written — that the framed path was under repair by another lot — is stale, as
that section itself says it would be.

**Why a parameter, and not a `bool` local.** `README.md:78-84` offers both. The
parameter is used because it is the one the delegation is stated in terms of,
so the route is checkable from the source: `declares_parameter` at
`x64_lower_nxo.nova:2506` returns 1 for a declaration with a kind-19 child, the
first term of the three-term predicate at `x64_lower_nxo.nova:2614` fires, and
the source goes to `build_framed_functions`. Measured on the tree rather than
read off the predicate: this member's tree carries exactly one kind-19 node, on
the entry, and no data section, so the second term (`data_seen`) is 0 and the
first is the one that fires.

**The single variable.** Against `return42` this changes the condition and
nothing else about the shape — no second function, no data section. Against
`branching-entry.ntasm` it changes two things: it adds the parameter and it
changes the condition. The parameter is not a free second variable, it is the
**only** way to obtain a value the front end cannot fold in a data-free source,
and so it is forced by the shape rather than chosen for it. §3 removes it as a
variable by holding it constant across a pair.

## 2. The pre-registered expectation, and an honesty clause about it

The expectation is in the gate file, in the comment above the row, in four
numbered parts: what the C reference will do, what the Nova producer will do,
**which side a failure would be on for each**, the pins, and what the gate's
own banner will print. It was written into the file before the row was run
through the gate, and it is left there whatever it turned out to be.

**It was not a blind prediction, and the file says so.** A throwaway probe
outside the repository — not a file in the tree, not a gate, deleted after the
measurement — had already put the same source through the same C libraries and
the same Nova host image the gate builds, and had already seen the C object
size and the producer's refusal, *before* the expectation was written. So items
(1) and (2) of the pre-registration are a **record**, and calling them a
prediction would be a comment asserting something about the past that is not
true of it. Items (3) and (4) — the pins this file asserts on every run, and
the verdict the run compares in both directions — were genuinely unrun, and
they are what the gate run tested.

All four held. See §5.

## 3. The member is a probe and not a fixture, and here is the number

The whole point of the member is that the body reaching the producer has **two
live returns**. Measured on the producer's own parse tree, not on the source
and not on a report:

```
IF children=3  condition="x == 0"
  ARM 0 kind=35  returns=0     <- the condition, not an arm
  ARM 1 kind=25  returns=1
  ARM 2 kind=25  returns=1
AT_PRODUCER live_arms=2 returns=2
```

**Two live children, two returns, three children under the branch node.** The
member is a probe.

**The pair that removes the other variables.** Hold the parameter constant and
change only the condition:

| condition on `x:u64` | live children at producer | Nova, mode 0 | Nova, mode 4 | C reference |
| --- | --- | --- | --- | --- |
| `if true` (literal) | 2 arms, 2 returns | builds 1536 | builds 1536 | 1536 |
| `if x == 0` (run time) | 2 arms, 2 returns | **refuses 800** | **refuses 800** | 1600 |

The literal-condition twin converges **byte identical** on both routes — the
same object and the same PE as the reference on all four streams — and it
carries the same two live children at the producer. So the refusal on this row
is **not** the branch, **not** the two-child linkage, **not** the frame, and
**not** the parameter. The only thing that differs between a convergence and a
refusal is whether the front end can fold the condition.

That is the finding, and it is narrower and more useful than « the producer
cannot do control flow »: **the framed producer lowers a two-armed `if`/`else`
correctly, byte for byte, and refuses when the condition is computed at run
time.** Which side that is on was named before the run: the product, specifically
the framed producer reached through the delegation.

## 4. `README.md`'s explanation of `branching-entry` is refuted, and this is the measurement

`README.md:67-71` says why `branching-entry.ntasm` did not reach the two-return
shape, and it is the reason this member was specified:

> The condition is a **literal**, and the reference folds it in its own front
> end before anything is lowered. The body that reaches the producer therefore
> has **one** return, not two, and the frameless word-record path was never
> asked the question the prediction asked it.

**Measured, that is false, and it is false in the part that matters.** Two
independent measurements:

1. **The Nova front end does not fold it.** The parse tree the producer entry
   receives for `branching-entry.ntasm` holds an `if` (kind 30) with **three**
   children — the condition, and two blocks — and **each block carries a
   `return`** (kind 29). `live_arms=2, returns=2`, exactly as on this member.
2. **The C reference does not fold it either.** The reference's own `.text` for
   `branching-entry.ntasm` contains a `Jcc rel32` at offset 334 and a `jmp
   rel32` at 679, and **both** immediates, 42 and 43, are present in the
   emitted bytes. A body with one return and a dead arm cannot contain a
   conditional branch or both arm immediates.

So `branching-entry.ntasm` **does** carry two live children into the producer,
**and** both arms are emitted, **and** the two producers agree byte for byte.

**Exactly what this refutes, and exactly what it does not.** Overstating a
refutation is the same defect as making one, so the boundary is stated:

* **REFUTED — the fold.** « the reference folds it in its own front end before
  anything is lowered … the body that reaches the producer therefore has one
  return, not two » is false on both sides, and so is the premise this member
  was specified against, « no corpus member currently carries two live children
  into the producer ». `branching-entry.ntasm` is one.
* **REFUTED — « never asked ».** The frameless word-record path *was* asked the
  question, on a body with two live returns, and it answered correctly and byte
  identically.
* **NOT REFUTED — « the residue sits on the framed path »**
  (`README.md:78-84`). That is **confirmed** by this member, which reaches the
  framed path by measurement of the delegation's first term. The
  specification was right about *where* the residue is and wrong only about
  *why* `branching-entry` did not reach it. A reader who took this section as
  « the specification was wrong » would be overreading it, and would discard a
  correct routing claim along with the incorrect mechanism.

**The residue is real; it is just not where the fold was.** It is not in the
two-child linkage, which works on both routes and on both condition kinds. It
is at the **foldability of the condition on the framed route**, and this
member is the first row of the table that sits on it.

`README.md` was not edited. It is not this lot's file, and a retraction that
lives only in the file making it is a retraction a reader will not meet.

## 5. What the gate measured, on a tree that was green before and after

**The tree was green before anything was written**, which is the whole reason
the numbers below are about this member and not about a repair in flight. Two
runs of `ngbuild.sh nova_corpus_convergence` with a disjoint `NG_BUILD`:

| | before the row | after the row |
| --- | --- | --- |
| `RAIL_SELFTEST` | 14 cases, 0 failed | 14 cases, 0 failed |
| banner | `checks=264 failures=0 cases=23 converged=7 of 7 known_gaps=0` | `checks=273 failures=0 cases=24 converged=7 of 7 known_gaps=0` |
| `BOUNDARY_SUMMARY` | `rows=13 converged=7 pinned_refusals=6` | `rows=14 converged=7 pinned_refusals=7` |
| `GATES_DONE` | `fail=0` | `fail=0` |
| `^FAIL` lines | 0 | 0 |

**The pre-registered pins, all four of them, held:**

```
BOUNDARY branching_runtime C object=1600
BOUNDARY branching_runtime NOVA refused=800 expected=800 C_object=1600 verdict=AS_PINNED
BOUNDARY branching_runtime REFUSAL_ROW C_PE=4096 table_c_pe=4096 DIGEST C_PE
                 sha256=c38665540141cf62526f52b930b68dd152ff2221af366fa69a3ebe866e078fbd
BOUNDARY_ROW branching_runtime expect=REFUSAL observed=AS_PINNED
BOUNDARY_SUMMARY rows=14 converged=7 pinned_refusals=7
```

The `converged == 7` literal in the gate is **not** changed by this row, and
that is the point of it being a literal rather than a sum: a row added as a
refusal must not move the convergence count.

**One caveat on the 4096.** For a refusal row the gate **measures and prints**
the reference's PE and does **not** assert it, which is this file's existing
convention and the reason is at `README.md:210-218`. So of the three pins on
this row, `1600` and `800` are asserted every run and `4096` is a printed
record. It is not an enforced number and should not be read as one.

**Both gate runs were under AddressSanitizer and UndefinedBehaviorSanitizer**,
because `ngbuild.sh`'s `run_harness` builds and runs every harness with
`-fsanitize=address,undefined` and `ASAN_OPTIONS=detect_leaks=1`. That is a
difference from the run `README.md:193-208` records for `branching-entry`, which
was taken without them. **The throwaway probe was not**, and it is not a
deliverable and is not in the tree.

## 6. The negative control, and what it had to refuse

The false positive available here is a sentence a reader can write down and
believe:

> « the row is in the table and the gate is green, therefore child ordering is
> covered »

The instrument below is built to refuse that, and it refuses it by **running**,
not by assertion. It reads its numbers from the gate's own run log and from the
producer's own parse tree:

```
ROW branching_entry    in_table=1 gate_green=1 live_children_at_producer=2
    returns_at_producer=2 nova_emitted_bytes=1
    FALSE_POSITIVE says: COVERED
    INSTRUMENT     says: CERTIFIED
ROW branching_runtime  in_table=1 gate_green=1 live_children_at_producer=2
    returns_at_producer=2 nova_emitted_bytes=0
    FALSE_POSITIVE says: COVERED
    INSTRUMENT     says: REFUSED -- a green row over a refusal is a green over
                               an absence, and no ordering was compared
CONTROL denominator: rows_of_this_experiment=2 in_the_table=2
    false_positive_would_say_covered=2
CONTROL instrument: certified=1 refused=1
CONTROL VERDICT: REFUSED -- the false positive fires and the instrument rejects
    it; the row it fires on is a refusal that emitted no bytes
CONTROL VACUITY: the instrument CAN certify, so its refusal is a judgement and
    not a constant
```

Two things make that a control rather than a demonstration of the obvious.

**It has a denominator.** `false_positive_would_say_covered=2` of 2. The false
positive does not merely *fail* to fire — it fires on **both** rows, and is
wrong on one of them. A control that reported « the false positive never fired »
would have been reporting that the claim was never in danger, which is a
different and much weaker result.

**It is not vacuous.** The same instrument returns `CERTIFIED` on
`branching_entry`. An instrument whose only answer is `REFUSED` proves nothing,
and the guard is asserted so that a future edit which hardens the test into a
constant turns this control red rather than green.

**The real test, stated so it can be argued with:** ordering is evidenced only
when *both* producers were made to order the same two children **and** their
bytes were compared. A refusal emits nothing, so a refusal row is a green row
over an absence.

## 7. What this row does NOT cover

This is the part that matters, and it is stated as scope because the number is
otherwise about an unbounded set.

**Covered from this date:** a section declaring a parameter, routed to the
framed producer by the delegation's first term, whose entry body is an
`if`/`else` whose condition is computed at run time. Covered as a **refusal**:
the C reference builds 1600 object bytes and a 4096 byte PE; the producer
answers 800 on both routes.

**Not covered, and not addressed by this row in any way:**

* **Child ordering on this shape.** The producer refuses, so it emits no bytes
  and no ordering is compared. The two children reach the producer — that is
  measured, §3 — and then the run stops. **This row does not close the ordering
  question and must not be cited as closing it.** The ordering question is
  narrowed, not answered: §4 shows the linkage is correct on the literal
  condition and on both routes, and this row shows the producer never gets far
  enough on the run-time condition to order anything.
* **The condition as an isolated variable.** The pair in §3 holds the parameter
  constant, which removes the parameter. It does **not** remove the *shape*:
  both members of the pair are `if`/`else` over two constant returns. Nothing
  here says what happens with a computed condition over computed operands, over
  a call, or over a local, and nothing here says what happens with an `if`
  **without** an `else`, or with a nested `if`.
* **Anything about the `let`-routed variant.** The parameter is one of the two
  routes `README.md:78-84` names. The `bool` local reached by a `let` is the
  other, it was measured once on a scratch copy (two live arms, two returns at
  the producer, producer 800, reference 1936 bytes) and it is **not** a row, so
  it is not asserted by anything and will not turn this gate red when it moves.
* **The failure's location inside the producer.** The row records **that** the
  framed producer answers 800 on this shape. It does not record the site, and a
  reader must not read `800` as « the branch lowering refused »: the literal twin
  in §3 lowers a two-armed branch successfully through the same route, so the
  refusal is downstream of branch lowering and this row does not say where.
* **The other two delegation terms.** `data_seen` and `any_body_is_framed` are
  untouched by this row; only `declares_parameter` is exercised.
* **Anything outside the two routes the gate drives.** The gate asks mode 0 and
  this lot measured mode 4 through a throwaway; neither is a statement about any
  other entry.

**What would actually close the ordering question,** and is not this row: a
member on this shape that the producer **builds**, so that two sides emit and
are compared. On today's tree there is none, and the honest report is that this
member establishes where the edge is rather than what lies past it.

## 8. Reading the row

`tests/c/nova/nova_corpus_convergence.c`, the `BOUNDARY` table,
row `branching_runtime`. The comment above it carries the route argument, the
four-part pre-registered expectation, the honesty clause about what was and was
not blind, and the statement of which side a failure would be on. The row
itself is read from disk, not copied inline, for the reason the row above it
states: a corpus member that exists only inside a C array is a member no reader
can open.

This row is the fourteenth, so the header's `BOUNDARY[] ... 13 rows` was
corrected to `14` in the same change. A count left stale by a row added beside
it is a comment asserting something about the tree that is no longer true, and
the `converged == 7` literal was deliberately **not** touched.
