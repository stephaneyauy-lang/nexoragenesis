# A5 — the seven compilation bounds, and the diagnostic text nobody has looked at

Criterion **A5** (`docs/status/ntasm-completion.md`, *Acceptation obligatoire de B2.1*).
Lot `W21A5Bounds`, wave 21. This is the primary artefact; the run log is a
separate file and the two are never merged, because a report that summarises a
log and the log it summarised have different failure modes and only one of them
is recoverable.

## What this lot was asked, and the two questions hiding inside it

The A5 row names seven bounds that no campaign had measured, and names them as
unmeasured so that the line would not read as though the ceilings were done:

```
hard_node_cap 262144   hard_name_cap 4194304  loop_cap 512
walk_depth_cap 64      parameter_cap 8         binding stack 65536
argument stack 4096
```

and it adds an eighth item that is a different kind of gap:

> *aucune campagne n'affirme quoi que ce soit sur le texte des diagnostics*

A bound that refuses does not say anything about **what it says**. So the eighth
item is not a seventh bound: it is a question about the *instrument*, asked of
every one of the other seven.

## The instrument

```
legacy/tools/coldproof/a5_bounds_campaign.c     the probe
legacy/tools/coldproof/a5_bounds_campaign.sh     the driver, its own cold build dir
```

A script and not a gate harness, deliberately: `ngbuild.sh:210`'s `GATES=(` is a
shared line range, and the inventory-closure rail turns any unregistered
`tests_ntasm_*.c` into a full-suite red *for everybody*. This adds no inventory
and edits no shared line.

Every ceiling in the campaign is **found by bisection**, never assumed, so a
change in a cost moves the number and the number is re-measured instead of
quietly becoming a constant. Every refusal is printed as the four `u64` words
the caller actually receives, with no decoding.

**Scope, stated because "the seven bounds" would be a number about an unbounded
set:** the expander `compiler/nova/macros/macro_expand.nova` as loaded from one
directory of six Nova sources, under the host runtime, with a `comptime` block
that may only **lower** the six declared budgets. Everything below is about
*this* module at *this* revision; the last section says what that does not
cover.

## The revision this answered for

Printed by the driver before the run, because a campaign that does not name the
revision it measured is a number about an unbounded set:

| file | sha256 |
|---|---|
| `tests/macro-expand-entry.nova` | `44152681171b4b66a8875d852311d3ce87fc3da9e24023154c5bf564edad6cdf` |
| `macro_expand.nova` | `a36464d1422c5a4d6b3d3efe2d3da739eacc4c02ddfc49ffd6750d59013fffc9` |
| `constant_eval.nova` | `1be1fd0c23241d9f3d2710b0969ad4de3cab77de262b2a0df2f3fb0f99a366bf` |
| `parser.nova` | `8009e56e229315e0dbee284367af2278e2043590f7885adfad3539432b92c46b` |
| `ast.nova` | `b09ef5a7b00e286a5c5200613adb6b6af3e6b3dcaf1f0c46b7daba412bb1103d` |
| `lexer.nova` | `d369a19bb548441e411c1bdffc1a036977b6848d37e025eabc02011ddc890e8c` |

`macro_expand.nova` was read twice for digests 4316 s apart and both reads were
`a36464d1…`. **The two reads are a *check* on a fact established by ownership,
not the fact itself** — a sibling lot held the same file this wave, and two
digest reads are what turned "nobody is editing it" from an assumption into a
measurement.

Baseline: **`checks=287 failures=0 observations=45`**, cold, `COLD_PROOF ok`.

## The result, one line per bound

`at−1` and `at` both produce a whole published region with **no diagnostic at
all**; only `at+1` refuses. That third arm is what makes the middle one a
frontier rather than a coincidence — a body that is simply invalid would produce
the same `at+1` and nothing here would notice.

| bound | declared | reachable? | what answers at the boundary | `at−1` | `at` | `at+1` |
|---|---|---|---|---|---|---|
| `parameter_cap` | 8 | **reachable**, clean | `372` reason 2 | 7 params → code 0 | 8 → code 0 | 9 → `372/2` |
| `walk_depth_cap` | 64 | **reachable**, but its unit is unpublished | `375` reason 9 | 29 levels → code 0 | 30 levels → code 0 | 31 levels → `375/9` |
| `loop_cap` | 512 | **reachable**, clean at fuel max | `380` reason 2 | 511 items → code 0 | 512 items → code 0 | 513 items → `380/2` |
| `hard_name_cap` | 4194304 **bytes** | **reachable**, only on long names | `900` reason 1 | 99-byte names → code 0 | 107-byte → code 0 | 115-byte → `900/1` |
| binding stack | 65536 words | **UNREACHABLE by arithmetic** | its shadow, `380/2` | 510 lets → code 0 | 511 lets → code 0 | 512 lets → `380/2` |
| argument stack | 4096 words | **UNREACHABLE by arithmetic** | its shadow, `201/5` | 126 levels → code 0 | 127 levels → code 0 | 128 levels → `201/5` |
| `hard_node_cap` | 262144 nodes | **UNREACHABLE, shadowed** | the arena, `201/3` | 33792 items → code 0 | 34304 → code 0 | 34816 → `201/3` |

## The headline: which of the seven turned out to be unreachable

**Three: the binding stack, the argument stack, and `hard_node_cap`.** These are
the same three the tree's own banner names, but two of the three reasons it
gives needed work, and one of them was found by this campaign measuring the
wrong thing first.

A declared maximum nothing can reach **cannot fail, so it protects nothing**.
That is a different promise from one that can be reached, and the difference is
the whole finding. It is the same shape as a verdict nothing can reach: a
dormant verdict reported as coverage is a claim about a set the instrument
cannot see.

### Binding stack 65536 — unreachable, and the arithmetic checks out

`bind_stride` is 7, and `push_binding` (`macro_expand.nova:908-912`) doubles
`want` from 256 and refuses when `want > 65536`. So the largest entry count that
fits is **9362** (65534 words); the 9363rd would need 65541 — **five words too
many**. A body that pushes 9363 of them holds 9363 statements, and the template
item cap refuses that at 512, **eighteen times earlier**. Measured: 510 lets and
511 lets expand whole, 512 are refused `380/2`.

*Promises:* nothing at 9363 entries.
*Does not promise:* that 65536 words is enforced by being reached. It never is.

### Argument stack 4096 — unreachable, and the arithmetic checks out

`arg_stride` is 4 (`macro_expand.nova:1000`), so 4096 words hold 1024 chain
levels, and the expansion depth budget answers at 128 — **eight times below**.
Measured: 126 and 127 levels expand, 128 is refused `201/5`, and the measured
expansion depth at the 127-level ceiling is exactly the declared 128.

*Promises:* nothing at 1024 chain levels.

### `hard_node_cap 262144` — unreachable, and the first version of this campaign
### measured the wrong shadow

The banner's arithmetic still holds: `node_bytes` is 96 and `max_arena` is
frozen at 16777216, so the arena answers at `16777216/96 = 174762` charges,
below the 262144 at which `reserve_nodes` would refuse. Verified this run.

**But the campaign's first version of this arm read a ceiling that was not the
arena's, and printed the wrong bound's name over it.** It bisected the *outer*
meta-for count; that count is itself a meta-for count, so the outer stops at 512
whatever the arena allows, and the ceiling that came back answered `380` reason
2 — **`loop_cap`**. A `hard_node_cap` measurement that was a `loop_cap`
measurement wearing its name. The arm now pins the outer at 512 and walks the
inner, which is the only direction in which the arena is reachable at all.

Corrected, on a shape with 1-byte introduced names so the name table is nowhere
near its own ceiling:

| inner count | items | answer |
|---|---|---|
| 66 | 33792 | code 0, 169474 published nodes |
| 67 | 34304 | code 0, 172034 published nodes |
| 68 | 34816 | `201` reason 3, nothing published |

`reserve_nodes` is, as the module says of itself, dead code. It is not a
guarantee and nothing should rely on it.

**A boundary that moves when the caller's buffer moves is a boundary of the
caller.** An earlier run reached `runtime=4` (`NV2_BOUNDS`) with `code=0` and
nothing published at 32704 items with a 1 GiB output buffer; the corrected arm
reaches 172034 published nodes with a fitted 32 MiB buffer. A second boundary
appeared and then disappeared with a change of buffer, and it is recorded here
rather than quietly dropped, because it is the shape of the defect this project
keeps meeting.

## Two things the A5 row states that did not survive this run

Left visible rather than tidied: a correction that carries its own mistake into
the artefact teaches the next reader the trap.

### 1. The arena is not `96×(nodes+1)`, and it is not `96×nodes` either

The row's finding is that `take_node` bills `nodes_made` (which counts the
temporaries of a folded condition) while `node_count` counts only what the
caller receives, so the arena is `96×(nodes+1)`.

Measured on four bodies, by **two independent instruments** — the measure
request, and a bisection of the *arena budget* with the body held constant:

| body | published nodes | `nodes_made` = arena/96 | made − published |
|---|---|---|---|
| 1 let | 11 | 11 | **0** |
| 4 lets | 26 | 26 | **0** |
| 16 lets | 86 | 86 | **0** |
| 64 lets | 326 | 326 | **0** |

The cross-check agrees: 4 lets, minimum arena 2496 bytes = 26×96, difference
**0**.

**On bodies that fold no condition the `+1` is not there at all.** And on a body
that does fold, the overhead is not `+1` either: the deepest nested meta-for
that expanded published **172034** nodes against an arithmetic ceiling of
**174762** charges — a difference of **2728**.

**So neither `96×nodes` nor `96×(nodes+1)` is a rule. The overhead is a property
of the body: 0 on four bodies, 2728 on a fifth.** What survives is weaker and
still true — the arena and the node budget are billed on the same counter with
different published counts, so a ceiling derived from one and written down as a
constant is a claim about a shape and not about the module.

**A body's name length is the smallest evidence of that in the whole campaign:**
the same 32768 items that a 115-byte introduced name refuses `900/1` are
*expanded without complaint* at one byte.

### 2. `hard_name_cap 4194304` bounds **BYTES**, and the shared header says words

Read, not recalled. `reserve_names` (`macro_expand.nova:642-648`):

```
let mut want:u64=env.name_cap;
while want*8<(env.name_bytes+extra_bytes) { want=want*2; }
if want*8>hard_name_cap() { return 1; }
let words:buf<u64>=alloc(runtime(),want);
```

`want` is a **word** count — `alloc` hands back `want` u64 — so `want*8` is a
**byte** count, and `4194304` bounds **4 MiB of introduced name text**.
`ntasm_fuel_model.h` called the unit "name table words" and converted it to
`524288` entries of 8 words, which is 33554432 bytes — **eight times the ceiling
that is actually enforced**. Corrected in place; see *Corrections landed*.

## `hard_name_cap` is reachable, and only on a body that writes long names

Measured on 32768 items — a count held well under the arena's ceiling, so the
two counters are separated:

| introduced name length | answer |
|---|---|
| 1 byte (and at 8, 99, 107) | code 0, whole published region |
| 115 bytes | `900` reason 1, nothing published |

The measured slope is **28.844 name bytes per item** at 8-byte names (945152
bytes for 32768 items). This is the reachable bound of the seven, and it is
reachable **only** because name length does not move the node count — the two
budgets are independent counters, and a ceiling is a property of the body.

## The eighth item: the diagnostic text

**The expander has no diagnostic text, and this is measured with a positive
control and a negative control.**

*Positive control* — a **successful** expansion, whose produced name table
provably holds spellings. The same scanner read
`__ntm$1$e1$t0000u64__ntm$1$e1$t0001u64__ntm$1$e1$t0002u64__ntm$1$e1$t0003u64`.
**A scanner that found nothing there would be broken, and every negative it
produced would be void.**

*Measured* — the **whole output region** the caller receives, for seven refusals
at seven boundaries, scanned for printable byte runs of four or more and not
only the four diagnostic words, because a message could in principle be
published alongside the code. **Zero runs at every one.** What the caller
receives, verbatim:

```
parameter_cap   372/2   [372   6  1 2]
walk_depth_cap  375/9   [375  75  9 9]
loop_cap        380/2   [380   7  5 2]
binding_stack   380/2   [380 520  9 2]
argument_stack  201/5   [201 388 26 5]
hard_node_cap   201/3   [201  17  9 3]
arena_bytes     900/1   [900  17  9 1]
```

Four unsigned words. No sentence, no limit named, no value.

**And the asymmetry is the sharp part, because the other producer of the same
bounds *does* carry text.** The product has a text channel — `NtError.message`,
printed as `E<code> <message>` (`cli.c:138`, `:203`, `:243`) — and the C
reference populates it for these very bounds:

```
frontend.c:3784  "quoted block statement limit exceeded"
frontend.c:2244  "meta-for iteration output exceeds 512 statements"
frontend.c:4791  "declaration meta-for output exceeds 512"
```

The Nova tree contains **three** occurrences of those strings and every one is
a **comment quoting the reference** (`macro_expand.nova:56`, `:411`, `:1873`) —
none of them emits. That is a search that returns three and not zero, so the
negative is a *classification* rather than an absence, and it was made with a
pattern known to match: the same pattern finds the three strings in
`frontend.c`, in the same shell, in the same run.

**So the same bound has a sentence in one producer and a number in the other,
and a caller reading only the code cannot tell `372` from `380` from `900`.**

### What each diagnostic promises, and what it does not

| bound | promises | does **not** promise |
|---|---|---|
| `parameter_cap` | a family, a position, a reason — enough to route a diagnostic and point a user at a line | which limit was crossed. `372` reason 2 covers arity, kind **and** shape |
| `walk_depth_cap` | the same | **the depth at which it was crossed.** The walk depth is a *parameter* of `walk()` and `run_block()`, not a field of `Env`; the measure request publishes `env.depth_peak`, which is *expansion* nesting and answers 1 on this shape. A caller cannot tell from the instrument whether the cap was crossed at 65 or at 200, and cannot convert the body parameter into the declared unit at all |
| `loop_cap` | the same | which of the two things behind `380/2` fired — a count past this cap, or a body repeating more template items than the reference's table holds |
| `hard_name_cap` | the same | `900` reason 1 is the **same three words** for the name table, the node table, the binding stack and the argument stack |
| binding stack | *nothing*: unreachable | that 65536 words is enforced by being reached |
| argument stack | *nothing*: unreachable | that 4096 words is enforced by being reached |
| `hard_node_cap` | *nothing*: unreachable | that 262144 nodes is enforced by being reached |

**A bound whose text said "budget exceeded" would still be worse than nothing**,
because it attributes a cause it did not establish. These are better than that:
they name a code and a position and nothing else. **The criterion asks about the
instrument that names the specific limit and the actual value, and in the Nova
expander that instrument does not exist.**

## The mutation: a green probe is evidence about the campaign

`--mutate` runs the same probe twice more, on **copies** in the build
directory, with two controls answering two separate questions:

```
Q1  was the PERTURBATION the one I meant?   controls that must PASS
Q2  was the RUN doing what I asked?         a control that must FAIL
```

### The control that must fail, and what it caught

A copy of the same six files with one Nova syntax error must make the run
refuse to build an image and exit non-zero. **A control that must fail and
returns green means the run compiled the shipped tree, and every number in it is
void** — and that is declared void *by the script*, not diagnosed by the reader,
because the reader is the part that is primed.

**It came back non-zero for TWO independent reasons**, and chasing that was
worth it: the intended `E400 168:15 unknown Nova type / status=NO_IMAGE`, and a
LeakSanitizer report about **this probe's own early return**, which freed the
six loaded sources on the success path and not on the no-image path. A control
that fails for two reasons is a control whose reason you do not know, so the
leak is fixed; the control now fails for the intended reason alone, with **zero
LeakSanitizer lines** in its log.

### M1 — relaxing only the arena term, and it **survived**

The mutation the A5 row already records one level down. `max_arena` 16777216 →
167772160, one term, and the driver asserts the copy differs by **exactly two
lines** before it runs anything.

**It came back green, and the arena accounting was byte-identical to the
baseline.** That is a finding about the campaign, not about the product, and
here is why:

> every body this campaign composes pins `arena_bytes=16777216` through a
> `comptime` block, and a `comptime` block may only **lower** a budget — so the
> declared maximum is never consulted at all. Raising `max_arena` cannot move a
> number the probe does not read.

**The campaign is blind to a budget the caller pins, and sensitive to one the
caller does not.** That is the same defect class as a gate that re-derives its
own thresholds at run time, one layer down, and it was found by a mutation
rather than by review.

### M2 — the mutation the probe *can* see

`node_bytes` 96 → 48. One term, the same shape, and it is the constant every
arena figure in this campaign derives from. **It bites, in the strongest way
available**: the arena accounting halves exactly — 1056→528, 2496→1248,
8256→4128, 31296→15648 — the node-cap ceiling moves from 34304 items to 52224
because halving the charge lets twice as many through, and the campaign's own
assertion about the overhead fires:

> `FAIL_OBS the arena overhead per body is not the SAME across four bodies
> (4294967290, 4294967283, 4294967253, 4294967133 lets)`

**And that failure is the campaign learning something about itself.** The probe
derives `nodes_made` as `arena / 96`, and that derivation is valid only when
`node_bytes` is 96. The mutation turned a hard-coded arithmetic premise into a
failing check, and the check's own message is what named it. **An assertion that
a mutation can turn red is an assertion with teeth; the proof is that this one
went red.**

Scope of M2, stated because the run was cut by its own 1500 s cap: **all seven
bound arms completed** under the mutation, the arena section completed, and the
run was stopped while crossing-check bisecting. The cross-check and the text arm
did not run under M2.

**Both mutation results are reported.** A probe that is green on M1 and red on
M2 is not a probe that works; it is a probe with a stated boundary, and the
boundary is written down above rather than left for the next reader to
rediscover.

### The two controls, and their verdicts

| question | control | expected | measured |
|---|---|---|---|
| was the **run** doing what was asked? | a Nova syntax error in a copy | must **fail** | `status=1`, `E400 168:15 unknown Nova type`, `status=NO_IMAGE`, **0 LeakSanitizer lines** |
| was the **perturbation** the one meant? M1 | copy differs by exactly one term | must **pass** | `changed_lines=2` |
| was the **perturbation** the one meant? M2 | copy differs by exactly one term | must **pass** | `changed_lines=2` |
| did M1 **bite**? | arena lines vs the baseline in the same build | must be **identical** | identical → **M1 survived** |
| did M2 **bite**? | arena lines vs the same baseline | must **differ** | differ → **M2 bit** |

The M1 and M2 baselines are the **same file in the same cold build directory**.
A baseline taken elsewhere would be a comparison across machines, and every one
of these verdicts would be a comparison against something nobody named.

## Corrections landed

### `tests/c/nova/ntasm_fuel_model.h` (this lot owns it)

* `ng_fuel_bounds` extended from **four rows to all eight** compiler bounds, with
  `loop_cap`, `walk_depth_cap`, `parameter_cap` and `template_item_cap` added.
  They were reachable, and readable out of another source — but a table whose
  whole purpose is to be looked up does not hold the four that were easy and
  omit the rest.
* `hard_name_cap`'s **unit corrected from words to bytes**, with the reason
  (`reserve_names` tests `want*8`, and `want` is a word count) written into the
  row. The `524288`-entry conversion survives, because 4194304 bytes *is* 524288
  entries of 8 bytes; **the arithmetic was right and the label was not.**
* Every row gains a **diagnostic-text column**, so a reader looking up a bound's
  status is not left to assume the code is a message.
* The header's own scope sentence — *"of the expander's eight compiler bounds,
  four are reachable and four are unreachable, and the four in this table are
  the unreachable four"* — **retracted in place**. It is wrong on the
  reachable/unreachable side: `hard_name_cap` is measured **reachable**, so the
  unreachable set is three. Leaving that sentence would have been a claim
  contradicted by the table forty lines below it.

## What I could not establish, stated as plainly as what I could

* **The walk depth at which `walk_depth_cap` fires.** It is a parameter of
  `walk()` and `run_block()`, not a field of `Env`, and the measure request does
  not publish it. The triple is reported in **body nesting levels** (29/30/31)
  and the declared unit is reported as **not measured**. The first version of
  this campaign asserted a mapping of two units per level, copied from the
  module's own comment; the measurement beside it contradicted the arithmetic, so
  the assertion is gone and the discrepancy is reported instead.
* **Which `runtime_v2` site raised the `NV2_BOUNDS` seen at 32704 items** — a
  checked out-of-range access, or the total-allocation ceiling
  (`BYTES_MAX` 64 MiB times four). Not isolated, and not guessed. It also did
  not reproduce once the output buffer was fitted, so it may be nothing at all.
* **Whether the name table and the arena are separable at every item count.**
  Separated at 32768 items, measured. Not swept.
* **`template_item_cap`'s status** is carried in the shared header from other
  arms of the macro_expand gate and is **explicitly marked as not re-measured
  here** — this lot's list named seven bounds and that is the eighth.
* **The campaign's reach for `arena_bytes` itself.** Every body pins it through
  `comptime`, so the declared maximum is never exercised. That is the M1
  finding, and it is a limit of this campaign rather than a property of the
  product.

## Citations, with their provenance

A line number I did not read is not a citation; it is a rumour with a number on
it. Every row below was read against the bytes of the revision named above.

| claim | site | status |
|---|---|---|
| `max_arena` 16777216, `max_ast_nodes` 1048576 | `macro_expand.nova:30-31` | **read** |
| `node_bytes` 96 | `macro_expand.nova:204` | **read** |
| `take_node` bills `nodes_made`, publishes `node_count` | `macro_expand.nova:715-732` | **read** |
| `push_binding` refuses `want > 65536` | `macro_expand.nova:908-912` | **read** |
| `push_arg` refuses `want > 4096` | `macro_expand.nova:1014-1018` | **read** |
| `reserve_names` tests `want*8 > hard_name_cap()` | `macro_expand.nova:642-648` | **read** |
| `bind_stride` 7, `arg_stride` 4 | `macro_expand.nova:900, 1000` | **read** |
| walk depth guarded at four sites | `macro_expand.nova:1410, 1652, 2141, 2312` | **read** |
| `Env.depth_peak` is expansion nesting, not walk depth | `macro_expand.nova:2388-2391` | **read** |
| the three reference-text strings are COMMENTS in the Nova tree | `macro_expand.nova:56, 411, 1873` | **read** |
| reference text `"quoted block statement limit exceeded"` | `frontend.c:3784` | **read** |
| `NtError.message` printed as `E<code> <message>` | `cli.c:138, 203, 243` | **read** |
| `NV2_BOUNDS = 4` | `runtime_v2.h:29` | **read** |
| `BYTES_MAX = 64 MiB`, and the two sites that raise `NV2_BOUNDS` | `runtime_v2.c:9, 58, 112-115` | **read** |
| **`take_node` at `macro_expand.nova:483-504`** | the A5 row and this lot's brief both cite this | **STALE — the function is at 715-732.** Inherited from prose and never re-derived; found by reading the file rather than by arithmetic |

**One source moved under this lot, and it is recorded rather than smoothed
over.** `tests_ntasm_macro_expand.c` was read at `eefa8d5c…` and is now
`7808127e…`: `W21A5Provenance` owns that file and edited it during this lot's
run. **No claim in this report is a line-number citation into it** — every
citation above is into `macro_expand.nova`, `frontend.c`, `cli.c` or
`runtime_v2`, and the harness was read only for the API it exposes. The consumer
gate was re-run against the **current** harness and passes
(`NTASM_NOVA_MACRO_EXPAND checks=1095 failures=0 cases=291`, `GATES_DONE
fail=0`), which is the check that matters for a shared header and is worth more
than a digest comparison.

## Where the logs are, so a reader can check this

A claim and the artefact that would let a reader check it are the same thing and
they must have the same lifetime. **An artefact in a directory nothing indexes is
as good as a deleted one**, and the build directory this campaign ran in
(`/mnt/d/Projets/Racine-C/ng21a5bounds-230216-9332/run12`) was one nothing knew
to look in. The four logs are therefore copied to the indexed evidence tree:

```
out/c-bootstrap/nova/evidence/W21A5Bounds/
  baseline.log     167c001433ba4fee1f3fbc32d65541a26b35b3895d66ca1a4944b40f981d52dc
  mutated.log      d4b22b0b57472f5561f64fe387f8d2f3f214eef6ecc996195f81ed4d5188fce6
  mutated-2.log    551507a443c9919c5f166a47acd1528af08a932fa8fc76c568b722299aa9bfb4
  must-fail.log    1401f04075a0ce64710cc2cc68a4cec83fa93aacc124f82587f50248ed1add00
  README.md        what each log's SILENCE means
```

**Every number in this report is a quotation from `baseline.log` unless it is
labelled as coming from a mutation**, and no number in it is a recollection.

**One log is truncated and that is a scope statement, not a success.**
`mutated-2.log` stops mid-run: M2 was cut by its own 1500 s cap after all seven
bound arms and the arena section completed, and its cross-check and text arm
never ran. It has no `A5_CAMPAIGN_BOUNDS checks=…` summary line, and that absence
is what a reader should read as its limit.

## How to reproduce

```sh
cd /mnt/d/Projets/Racine-C/NexoraGenesis
B=/mnt/d/Projets/Racine-C/ng21a5bounds-$(date +%H%M%S)-$$
bash legacy/tools/coldproof/a5_bounds_campaign.sh $B            # baseline
bash legacy/tools/coldproof/a5_bounds_campaign.sh $B.m --mutate # + both mutations and both controls
```

The build directory must be absolute, must resolve to itself, and must hold
**zero files** before the run — asserted with `find -type f | wc -l`, not with
`test -d`, because a directory can exist and be empty and `test -d` passes
either way. Existence is not sufficiency, and the two properties are
independent.
