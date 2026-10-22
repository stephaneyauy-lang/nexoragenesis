# A5, the provenance half: what is measured, on what, and what is not

Lot `W21A5Provenance`, 29 September 2026. Criterion A5 of
`docs/status/ntasm-completion.md:46`:

> « Macros AST et comptime | **Hygiène, provenance, absence d'I/O et bornes imposées, avec tests adverses** »

**The one-sentence answer, asked for by the lot brief:** *A5's provenance half is
now measured, and it is measured on the produced name table of every expansion —
twelve constructed adversarial inputs whose outcomes are each pinned to a named
rule, a case count declared as 12 and compared with `==` against the 12 actually
judged, a positive control that fires on all three of the classifier's answers,
and two producer mutations that turn the campaign red — with one finding, that a
name re-bound by the caller at function scope is accepted.*

Everything below is either a quoted line from a run or a path I can name. Every
number says whether it came from a live path or from a durable artefact.

---

## 0. A discrepancy in the criterion row, stated before anything else

`docs/status/ntasm-completion.md:46` says, of this same criterion:

> « **Deux campagnes, une par prohibition, sont livrées avec preuve négative chacune ;
> la moitié « provenance » reste non couverte, et c'est la seconde campagne que cette
> ligne nomme.** »

**That sentence does not describe the tree I was given.** A provenance campaign was
already present in `tests/c/nova/tests_ntasm_macro_expand.c` — a
comment block headed « A5 wave 13: provenance, and the seven bounds » at line 684,
and six numbered items inside `main()` beginning at line 3494 — the surface, the
mark oracle, the ordinal, the sweep, the leak and the execution of the produced
text — followed by a seventh on the compiler bounds. I did not take that on a
reading. It runs, cold, and prints:

```
PROV_SURFACE mark_forge_refused=800 control_expanded=1 channel=closed_by_the_lexer
PROV_SWEEP entries=13 expanded=11 marked=21 spelled=15 caller=0 unclassified=0
PROV_LEAK unclassified_published=1 name=w
```

(from `final.out`, the live run of §6). So the campaign exists and executes.

**I am not editing `docs/status/ntasm-completion.md`** — it is not my file, and it is the
row several other lots are working around this wave. This is a handover, not a
repair: **the A5 row's
« la moitié « provenance » reste non couverte » is stale with respect to the current
harness, and whoever owns that row should re-read it before the wave closes.** The
row also understates the campaign in a second way, which §5 makes precise.

---

## 1. What the campaign already did, and what it could not do

The pre-existing wave-13 block is, in its own words, « THE SWEEP: every produced
name, classified » — and it is genuinely the strong kind of measurement: the
produced name table is the expander's only egress, so classifying every name in it
covers the whole surface rather than a list somebody thought to enumerate.

**But it is not adversarial, and criterion A5 asks for adversarial tests
separately from the four things it enumerates.** Every entry in the thirteen-entry
corpus that reaches a `k_let`/`k_fn`/decl node succeeds. A corpus built out of
refusals would say nothing about *which* names a refusal is refusing, so a corpus
that expands is the right design for a sweep — and it is exactly the wrong corpus
for « avec tests adverses ». Those are two different requirements and the tree had
one of them.

**So this lot builds the adversarial half.** The sweep is left exactly as it was.

---

## 2. The twelve cases, each judged, each with a control where a control is possible

Live output, `final.out`. One example first, then the table.

The provenance claim in its most concrete form — the shadowed case, the two
bindings both spelled `t`, the marks printed rather than counted:

```
ADV_NAME shape=shadowed node=4  |__ntm$2$e1$t|     <- the OUTER template's t
ADV_NAME shape=shadowed node=11 |__ntm$1$e2$t|     <- the INNER template's t
```

Same spelling, two different marks, two different macro ordinals. That is what
"the expansion resolves each name to its own binding" looks like in bytes, and the
assertion compares the **ordinals** — two copies of one mark would satisfy a count
of "distinct strings" and would not satisfy this.

| n | shape | outcome | rule that answered |
|---|---|---|---|
| 0 | `control` — not adversarial, must expand | **0**, publishes `__ntm$1$e1$t` | none; this is the canary |
| 1 | `sibling_scope` | **374/1** | a name bound only in a sibling scope is a capture |
| 2 | `shadowed` | **0**, two distinct marks | hygiene: accepted, and correctly |
| 3 | `recursion` | **201/2** | `call_depth` answers a self-expanding macro |
| 4 | `rebind_fnlocal` | **0 — ACCEPTED** | **the finding, §4** |
| 5 | `rebind_fnlocal_ctl` | **0** | control for row 4 |
| 6 | `rebind_module` | **381/1** | the same rebind at module scope |
| 7 | `rebind_module_ctl` | **0** | control for row 6 |
| 8 | `param_shadow` | **376/2** | refused at `macro_expand.nova:1527` |
| 9 | `reserved` | **376/3** | refused at `macro_expand.nova:1529` |
| 10 | `unbound` | **374/1** | a name the caller never bound |
| 11 | `recurse_metafor` | **377/4** | a form rule, **not** a budget — see §5 |

**7 refused, 5 accepted.** Of the 5: three are controls (0, 5, 7), one is correct
by design (2, the shadowed case must expand — that is what hygiene means), and one
is the finding (4).

**A control exists for every acceptance that could have one**, and each control
differs from its case **only in the caller's text**, so the pair can come apart:

- rows 4 / 5 — same template, same call, caller binds `t` vs binds `other`. Both
  expand. The acceptance is not an accident of the template.
- rows 6 / 7 — same template, module `const t` vs `const other`. One is refused
  381, the other expands. This pair is what makes 381 a *rule* rather than a
  blanket refusal, and it is the pair that locates the finding.
- row 0 stands alone for rows 1, 3, 8, 9, 10, 11: a parser that refused everything
  would produce eleven refusals and look like a thorough campaign. The canary is
  the reason the other eleven mean anything. This is the I/O campaign's argument,
  restated, and it is why that campaign was worth having.

---

## 3. The case count, printed and checked by equality

The brief's trap, and the `x64_lower_lea` shape: a closure that judged 189 rows and
*declared* 189 because a manifest cell could not be allocated, under the same
banner as a full pass.

```
ADV_SUMMARY declared=12 judged=12 accepted=5 refused=7 count_checked_by=equality
            control_expanded=1 classifier_control_fires=1
```

`declared` is a literal, `ADV_CASES`, and `judged` is incremented inside the loop.
They are compared with `!=`, in **both** directions:

```c
if (judged != (unsigned)ADV_CASES) { failures++; ... }
```

Not a floor. A floor is a campaign that is content to judge less than it claims,
which is the defect itself. **§4.1 shows this check firing.**

Note what the *pre-existing* sweep does and does not do: its vacuity floor is
`expanded < 11 || tally[CLS_MARKED] < 18` — a floor, on a corpus whose size is
derived from two array lengths. I did not change it; I measured what it is
(§4.2, M1) and recorded the result.

---

## 4. The mutation record — which mutations bit, and which survived

> « Une sonde qui revint verte est consignée plutôt qu'enterrée. »

Every mutation was applied to a **copy**. The gate loads its Nova sources by
*relative* path from the cwd, so all runs happened inside a scratch tree carrying
its own `compiler/nova`; the repository was only ever read. The scratch
copy's digest equalled the repository's at the start
(`a36464d1422c5a4d6b3d3efe2d3da739eacc4c02ddfc49ffd6750d59013fffc9`) and again
after the producer mutations were reverted, which is the check that the scratch
tree — not the tree — is what moved.

Baseline: `checks=1095 failures=0 cases=291`, reproduced independently in the
scratch tree as well as through `ngbuild.sh`.

| # | mutation | verdict | what it says |
|---|---|---|---|
| M1 | sweep vacuity floor `11/18` → `1/1` | **SURVIVED** | the floor is a backstop, not a discriminator (§4.2) |
| M2 | delete the sweep's per-name *unclassified* verdict | **SURVIVED** | the 13-entry corpus never produces an unclassified name (§4.2) |
| M3 | producer: packed `__ntm$` word → `^_ntm$` | **BITES** (18 FAIL) | the campaign is pointed at the expander, not at itself |
| M3b | producer: packed `__ntd$` word → `^_ntd$` | **BITES** (15 FAIL) | and not at one mark constructor |
| M4 | one adversarial case silently absent | **BITES** | **the count check is live** |
| M5 | the control case made a must-refuse case | **BITES** | the canary is load-bearing |

### 4.1 The two that must bite, and do

**M4 is the trap, closed.** One case made silently absent, and:

```
FAIL the adversarial set judged 11 cases and claims 12, so a green from this block
     would be a green from a smaller experiment than the one named
```

`checks=1092 failures=1 cases=290`. Note `cases=290`, not 291 — the run *knows* it
judged one fewer, and says so in a number a reader can compare.

**M5 is the canary, closed.** The control turned into a must-refuse and:

```
FAIL adversarial case 0 (control) returned 0/0 and the campaign says 900/1
     -- CONTROL_the_shape_must_expand
```

**M3 is the one that says the campaign measures the expander.** My *first* attempt
at M3 replaced the ASCII spelling `__ntm$` and came back **green** — and that green
is a fact about my mutation, not about the campaign: both occurrences of `__ntm$`
in `macro_expand.nova` are in **comments** (lines 17 and 1512). The literal the
expander emits is a packed little-endian word, `0x0000246d746e5f5f`, written by
`put_mark` at `macro_expand.nova:1254-1264`. Perturbing *that* byte gives 18 red
lines, and the campaign shows the thing rather than a count:

```
FAIL hygiene mark=0 rewrite=0 named=1
ADV_NAME shape=shadowed node=4 |^_ntm$2$e1$t|
```

**M3b** does the same for `__ntd$` and reaches the sweep's own per-name verdict:

```
FAIL corpus 2 produced the unclassified name |^_ntd$1$e1$r0$t0$c| at node 4
```

### 4.2 The two that survived, and what a surviving mutation is evidence about

**M1 — the sweep's vacuity floor, weakened to nothing, changes no verdict.** The
floor exists to catch a corpus that silently stops expanding; on a corpus that
does expand it is inert. It is not a defect, and it is not a strength either. The
floor is a floor, and this is what a floor is worth: it bounds a regression, it
does not evidence one. The adversarial block's count check is not a floor, and M4
is the difference between the two.

**M2 — deleting the sweep's per-name *unclassified* verdict changes nothing.**
This is the more interesting survival, and it is a real hole in the pre-existing
campaign rather than a quirk of my mutation. The reason is a property of the
corpus, and it is worth stating plainly:

> **The thirteen-entry corpus never produces an unclassified name.** The only
> thing in the whole campaign that reaches `CLS_UNCLASSIFIED` is `PROV_LEAK`'s
> `bare_name` shape, which yields exactly one name, `w`.

So the sweep's strongest per-name verdict — « this name came from nowhere, and the
run is red » — has nothing to fire on in the state the corpus is currently in. M3b
proves it is *reachable* and not dead code: perturb the producer and the very same
verdict fires. The verdict is correct and dormant. **A dormant verdict is not
evidence, and I am not going to report it as one.** The honest sentence is the one
above: the corpus contains no leak, so the check for leaks rests, in this tree, on
one constructed name in one shape.

---

## 5. What this campaign does NOT cover, in the criterion's own vocabulary

Written into the campaign's own banner (`A5_CAMPAIGN_LIMITS`, keys
`limits_adversarial_not` and `limits_adversarial_classifier`) so that a reader
meets it in the log rather than only in a document. A campaign that does not say
what it did not cover is a campaign whose silence reads as coverage.

**Provenance.**
- Mutual recursion between **two** macros. Row 3 is self-recursion; the two-macro
  cycle is a different walk and is not measured.
- A name whose **text depends on a comptime condition** — the same template
  yielding `c` on one branch and `d` on another. The corpus does contain a
  `meta-if` (`META_IF`, `PROV_SWEEP_ENTRY entry=3 … names=15`), and it does
  publish names; but both of its branches introduce the same text `c`, differing
  only in the initialiser, so a produced name that *changes with the branch* is
  not in the corpus. I checked rather than assumed: the first draft of this
  bullet said the meta-if « publishes no name », and the sweep line above says
  `names=15`.
- **Cross-invocation and cross-module provenance**: whether two expansions in two
  different modules can collide, and whether the serial is global or per-module.
- Whether a name is **both** a mark format **and** declared by the caller. The
  classifier checks marks first, so such a name classifies as `CLS_MARKED` and
  this campaign would not notice. The lexer makes the shape unreachable from a
  caller's source, and `PROV_SURFACE` measures that the lexer refuses it — but the
  classifier's precedence is untested, and an unreachable shape is not a tested one.
- The classifier reads a name out of a node when `n[0] == 90 && n[7] > n[6]`. A
  produced name carried by a **different node kind** is never offered to it.
- The `caller_writes` test is textual. The pre-existing banner already names the
  limit — a brace in a string or a comment would fool it — and the corpus spells
  neither. That limit is inherited, not introduced here.

**Hygiène.** Rows 8 and 9 measure 376/2 and 376/3 on two hand-built names. They do
not measure 376/1 (a template name that already exists as a binding at expansion
time), parameter count at the cap, arity mismatch 371, or expansion in a type
position 386.

**Bornes imposées.** Rows 3 and 11 are the only places this block touches a bound,
and they are not bound measurements. Row 3 is a *consequence* of `call_depth`;
row 11 is refused 377/4 — a **form** rule, `macro_expand.nova:1983` — and not a
budget at all. It is in the set because it is a different walk, and it is named as
a form refusal so nobody reads it as a second depth measurement. The six maxima and
the eight compiler bounds remain the ceilings campaign's business, and this block
makes no claim on them.

**Absence d'I/O.** Untouched by this block. That is the io_purity campaign's, and
its own silences stand as it wrote them.

**Tests adverses, generally.** The twelve inputs are twelve *hand-written sources*.
Nothing here generates them, so there is no claim about a space of shapes — only
about twelve of them, named, with the rules that answer them recorded one by one.

**Diagnostic text.** No campaign in this file asserts anything about the text of a
diagnostic, and this block does not either. It compares codes and reasons.

---

## 6. Reproducing this

```
NG_BUILD=/mnt/d/Projets/Racine-C/<your-build-dir> NG=/mnt/d/Projets/Racine-C \
  bash legacy/tools/coldproof/ngbuild.sh macro_expand
```

Cold, from a build directory never used before. Observed, from that run:

```
NTASM_NOVA_MACRO_EXPAND checks=1095 failures=0 cases=291
GATES_DONE fail=0
```

`cases` rose from 276 to 291 and `checks` from 1056 to 1095: fifteen new judged
cases and thirty-nine new checks, with no new harness file and therefore no change
to the gate inventory. The gate run reads `ADV_CASE`, `ADV_NAME`, `ADV_CONTROL`
and `ADV_SUMMARY`; the twelve case verdicts are in the log, not only in this
document, which is the separation the two artefacts exist to keep.

**And nothing that was already measured moved.** Every measurement line the
pre-edit run printed — 57 of them, `PROV_`, `DIGEST`, `TEMPLATE_ITEMS`, `BOUND`,
`BOUND_STATUS`, `CEILING`, `DISTINCTION`, `IO_SURFACE`, `REF_` — was diffed
against the same line from the post-edit run:

```
pre_lines=57  post_lines=57
IDENTICAL: every pre-existing measurement is byte-for-byte unchanged by this lot
```

That is the evidence for the sentence in §1 that the sweep is untouched. It is a
diff of two durable artefacts, not a recollection.

### 6.1 One green that was about the instrument, not the campaign

Recorded here because it is the shape the four absences in this wave share, and
because this lot produced one.

My first M3 replaced the ASCII spelling `__ntm$` in a **copy** of
`macro_expand.nova` and the campaign came back **green**. The available reading was
not *« the provenance campaign does not depend on the producer »*. It was *« this
mutation did not touch the code »*, and checking cost one grep: both occurrences
of `__ntm$` in the file are in comments, at lines 17 and 1512, while the byte the
expander actually emits is a packed little-endian word written by `put_mark` at
`macro_expand.nova:1254-1264`.

**A negative control that fires is not a positive control — it is the instrument
saying it is in the wrong state, and its silence on the question means nothing.**
The green was void, and the correct claim from the same measurement was about the
mutation. Perturbing the packed word instead gave 18 red lines. Had I reported the
first green, the writeup would have contained a false statement about the campaign
in the exact place where a reader would most want to believe it.

The mutation record is a scratch script in the lot's own build directory, not in
the tree: it perturbs copies, reverts them, and prints a verdict word per
mutation. It is not shipped, because a mutation script that ships is a script
somebody will eventually run against the tree by accident.

---

## 7. A retraction, left visible

The campaign's own banner first read

```
adversarial_caught=9_of_12 ...
adversarial_accepted=2_of_12 ...
```

I wrote those two numbers from the shape list rather than from a run. The run said
`refused=7 accepted=5`. The two numbers a reader would have compared against each
other disagreed, so the measurement is believed and the guess is withdrawn. The
banner now carries the measured split **and names the three controls inside the
acceptances**, because a tally that hid the controls would read as a worse campaign
than it is, and one that hid the finding inside them would read as a better one.
The correction is in the banner as a comment, not as a quiet overwrite.

Three of the block's `file:line` citations were also off by one when first written
(`macro_expand.nova:1526` and `:1528` pointed at the test and at a closing brace
rather than at the refusals). They were re-derived against the bytes and re-checked
with W21A4Footprints' `audit_citations.sh`, pointed at this file; all four now
resolve to the intended line. One of the four is reported `MISSING-FILE` by that
tool, because the tool's regex cannot see a citation that sits inside a
`key=value` banner string — the bytes are right and the tool's limitation is the
thing being reported.

---

## 8. Files, ownership, and the one thing I did not do

**Edited** (declared to Main before any edit):
- `tests/c/nova/tests_ntasm_macro_expand.c` — one new block inside
  the existing provenance campaign, plus banner keys. Baseline digest
  `eefa8d5c065412002c8b28cdcb6e323dc376fc7514e4f6c150fa97b6e07df80d`; the harness
  under test for the mutation record was
  `7808127eecf5f591a76f91e237581e5fbc342e2c944ea40b00c8cf7305a314d2`.

**Not edited, deliberately:** `compiler/nova/macros/macro_expand.nova`. The
campaign needed nothing from it. Its digest is
`a36464d1422c5a4d6b3d3efe2d3da739eacc4c02ddfc49ffd6750d59013fffc9` before and
after this lot, and the mutation record's scratch copy is the only thing that ever
held a perturbed byte.

**Not run:** the 94-gate suite. Integration is Main's, once, after the wave.

**Not established, and I am not claiming it:** that the criterion A5 is now
*liver*. The provenance half is measured, and measured adversarially, but the
hygiene half is two hand-built names deep and the criterion row is one line that
also covers the other three. A line closed on two of its halves would be the same
false sentence in a new place.

---

## 9. Admissibility: the two questions, answered separately

« Perturb a copy, not the tree » is necessary and it is not sufficient. There are
two independent questions, and a void run and a sound mutation both produce a
number and look identical from the outside.

```
1. did the RUN do what I asked?          -> a control that MUST FAIL
2. was the PERTURBATION the one I meant? -> a control that MUST PASS
```

**Question 1 — answered.** An unbalanceable brace was injected into the **scratch**
copy of `put_mark` and the *unperturbed* harness run against it. It must go red,
and it did: `FAIL modules compile`, `E400 228:35 unknown Nova type`, `FAIL image
maps`. Restoring the scratch copy returned the run to green. The pair differs only
in the scratch file, so the red was produced by the perturbation and by nothing
else. **The scratch copy is the file the binary reads, and no M3 number is a
fallback to the repository.**

**Question 2 — answered.** For M3 the mutation is one byte inside a packed
little-endian word; the *named observable* is the produced name table. Checked in
both directions: the unperturbed run carries `^_ntm$` in **0** lines and does carry
the real `__ntm$2$e1$t`; the perturbed run carries it in **18** lines and is red;
restoring returns it to **0**. Eight controls passed, none failed. The mutation's
precondition was asserted (`assert s.count(old) == 1`) rather than assumed, because
a mutation applied to the wrong artefact of the same string is the failure this
question exists to catch.

**The build directory, by file count rather than by existence.** A directory can
exist and be genuinely empty, so `test -d` would have passed and proved nothing.
`find … -type f | wc -l` gave **197** files before any absence was read out of it,
and a positive control (`mkdir -p` then `ls -d`, rc=0) and a negative control (an
impossible path, rc=2) were both run in the same shell. The repository's
`macro_expand.nova` digest was `a36464d1…` before, during and after every
perturbation.

**A precondition for question 2, and the gap in my own record.** Question 2 is
not only « a control that must pass ». It is `s.count(old) == 1` **first** — a
mutation applied to one of several identical sites is a mutation whose site
nobody chose. I had asserted that for M3, M3b and M5 and **not** for M1, M2 or
M4, which found their anchor with `next(...)` or `sed` and therefore took the
first of whatever they found. Measured afterwards, all three anchors do occur
exactly once — so the verdicts were right **by luck, not by assertion**, and a
verdict that is right by luck is a verdict that will not stay right when a
sibling edits the harness. Preconditions added, whole record re-run, every
verdict reproduced identically:

| mutation | anchor | count | verdict after the precondition |
|---|---|---|---|
| M1 | `expanded < 11 \|\| tally[CLS_MARKED] < 18` | 1 | SURVIVED |
| M2 | `if (cls == CLS_UNCLASSIFIED) {` | 1 | SURVIVED |
| M3 | packed `0x0000246d746e5f5f` | 1 | BITES (18) |
| M3b | packed `0x00002464746e5f5f` | 1 | BITES (15) |
| M4 | `if (src == NULL) continue;` | 1 | BITES |
| M5 | `want[0] = 0; want_reason[0] = 0;` | 1 | BITES |

The script now stops with `PRECONDITION_FAILED` rather than mutating. The
re-run's exit status was read without a pipe: `MUTATE_REAL_EXIT=0`.

### 9.1 A control of mine caught an instrument of mine, and the report would have been false

Worth recording because the control did its job by failing.

The first version of the question-2 control searched for the mutated byte with
`grep -c "^_ntm\$"`. In a basic regex `^` is the **start-of-line anchor**, not a
literal caret, so that pattern matches a line *beginning* with `_ntm$` — which
nothing ever does. The control reported:

```
run: exit=1 fail_lines=18 lines_carrying_the_mutated_byte=0
PASS  the perturbed run is red
FAIL  the mutation did not reach the produced names; it hit something that does not emit
the named observable, printed:
     ADV_NAME shape=shadowed node=4 |^_ntm$2$e1$t|
```

**The FAIL and the line beneath it contradict each other, and the line is right:**
the mutation had landed, the instrument could not see it. Had I not built the
question-2 control at all, I would have reported M3 on the strength of having
*read* that line once — which is the thing §4.1 says not to do, and which is how
this project's other false corrections happened.

Two errors in the same thirty lines, both mine, both now fixed, and both fixed in
the artefact rather than only in this sentence:

- the search, now `grep -acF` — fixed string, the whole regex-metacharacter class
  removed, with the reason written into the script next to the pattern;
- the exit code. `bash … | head -50; echo $?` reports **`head`'s** status, not the
  control's, and it printed `posctl_exit=0` on a run that contained a failing
  check. Re-run without the pipe: `REAL_EXIT=0` on 8-of-8 — and the same wrapper
  would have printed `0` on a run that failed. **A number taken from a pipeline is
  a number about the pipeline.**

### 9.2 Per-citation provenance, in the standard format

Every `file:line` this report asserts, and how it was obtained. The column exists
because the author cannot be relied on to remember which numbers in a paragraph
were checked, and neither can the reader.

| citation | verified | inherited |
|---|---|---|
| `docs/status/ntasm-completion.md:46` — the A5 row and its quoted sentence | read, twice | — |
| `tests_ntasm_macro_expand.c:684` — the wave-13 banner | read | — |
| `tests_ntasm_macro_expand.c:3494` — the first numbered item | read, by grep over the block headers | — |
| `tests_ntasm_macro_expand.c:3714-3719` — the per-name verdict M2 removes | read; the range also came back from the mutator's own output | — |
| `macro_expand.nova:1409`, `:1416-1417`, `:1428` — `declares_below` | read, byte by byte | — |
| `macro_expand.nova:1527`, `:1529` — the 376/2 and 376/3 refusals | read, after the audit found them off by one | — |
| `macro_expand.nova:1983` — 377/4, the form rule | read | — |
| `macro_expand.nova:1254-1264` — `put_mark` | read | — |
| `macro_expand.nova:17`, `:1512` — the two `__ntm$` comments | read, by grep | — |
| `frontend.c:2384,4818,4880,4938` — the mark formats | — | **inherited** from the pre-existing banner; I did not open `frontend.c` and make no claim of my own about those four lines |

The last row is the one that would have been invisible in a paragraph of prose.
It is inherited, it was correct, and it is not mine to have verified.
