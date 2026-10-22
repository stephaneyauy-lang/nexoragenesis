#include "nova.h"
#include "../../ntasm/backend/codegen.h"
#include "../runtime/runtime_v2.h"
#include "../analysis/seed_reachability.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A small independent typed frontend. These limits are explicit diagnostics,
 * not silent truncation. Arrays are fixed during compilation so graph IDs and
 * token-owned names remain stable until the shared backend finishes.
 * Every cap below is per PROGRAM, not per module: one nova_compile_many_v2
 * call shares a single Compiler, so a gate that hands it forty-one modules
 * pays for all forty-one at once. The budget is sensitive to the SHAPE of the
 * source and not only to its size. One flat local costs one variable, one
 * expression and one statement; one field of a record literal costs eleven
 * variables, ninety-five expressions and sixty-seven statements, because
 * lower_record emits one fully guarded call_v2(NV2_RESOLVE) per field
 * written, so a struct of n fields costs about 58n flat locals. collect_records
 * walls a single struct at 64 fields independently of the whole-program
 * field count, and MAX_TOKENS walls a flat local at roughly eight tokens, which
 * is why MAX_LOCALS is a backstop no source can reach on its own: a field
 * write is the only shape cheap in tokens and dense in variables, and it buys
 * 8.6 expressions per variable, so MAX_NODES always binds first. Size a source
 * change against the numbers above, not against its byte count. */
enum {
  /* Token budget history, the same 32 Ki steps over the same 25% headroom.
   * This is the second of the five bounds to state a derivation rather than
   * transcribe a number, and the first whose guard carries TWO thresholds in
   * one expression. Read the last paragraph before touching either of them.
   *
   * WHAT WAS MEASURED. The 61 pipeline modules of the compiler/nova
   * corpus, lexed in ONE nova_compile_many_v2 call, measure 307653 tokens.
   * That set is what fires this guard: at 262144 it refuses with code 201
   * "Nova token limit" in x64_lower_novo.nova:1165, token_count 262143.
   * 1.25*307653 = 384566, and 393216 = 12 * 32768 is the smallest 32 Ki step
   * at or above it, a headroom of 1.278x. The step below it, 360448, is
   * 1.172x and does not qualify. 262144 was 0.852x of the need: a number
   * with no derivation behind it, and not even 1.25x. Re-measured 20261002.
   *
   * READ THE TWO PARAGRAPHS BELOW BEFORE TRUSTING THE NUMBER, because the
   * need above is NOT the largest program on this tree and the two are not
   * the same question.
   *
   * (1) The largest PROGRAM is far smaller. A closure that can produce an
   * image is a gate entry plus its whole transitive import set, and there are
   * 107 of those on this tree. 105 complete; the largest is validate-entry
   * at 43 modules and 173327 tokens, 0.661x of this bound. NOT ONE of the
   * 107 reaches the token guard. So this value is not sized after the
   * heaviest gate, and was not derived from one: it is sized after the
   * whole-corpus lex, the only workload on this tree that has ever reached
   * this bound. Deriving it from 173327 instead would give a smaller number
   * that explains no refusal anyone has actually observed.
   *
   * (2) 64 inputs is the widest program this compiler admits: lex() refuses
   * count > 64, so nothing wider exists here. A ladder of dependency-first
   * closures measured up to that 64 peaks at 248003 tokens, which 262144
   * covered by only 1.057x -- less than the 25% every other bound here is
   * sized to, on the largest real workload below the corpus lex. NOT ONE of
   * the 64 rungs reached this guard. Rungs 43 to 56 refuse with the
   * EXPRESSION limit and rungs 57 to 64 with code 300 "duplicate record
   * type", which is the ladder accumulating a second and third gate entry
   * whose record declarations collide: a name clash, not a memory bound. The
   * ladder is reported for what it shows -- nothing else on this tree comes
   * near this bound -- and not as a family of programs, because a prefix of
   * it is a program only up to the first extra entry.
   *
   * WHAT A RAISE COSTS. This constant is not only a guard: compile_profile()
   * allocates the token array AND the skip_declaration array with it.
   * sizeof(Token) = 144, measured, so both arrays together are 152 bytes per
   * token: 38912 kB at 262144, 58368 kB here, a rise of 19456 kB. Nothing
   * that reaches an artifact is sized by this constant, so the rise is a
   * resident cost and not a change to any emitted image -- which is why no
   * gate banner below moves.
   *
   * THE TWO THRESHOLDS, WHICH ARE NOT THE SAME NUMBER. The guard reads
   *     if (c->token_count >= (c->safe_v2 ? MAX_TOKENS : 65536) - 1)
   * and both arms sit on that one line, so a reader will conflate them. Only
   * the first arm is this constant. The second is a literal typed at the
   * guard; it belongs to the LEGACY profile (nova_compile_many, safe_v2==0)
   * and NOTHING in this lot changes it. It is 65536 before and 65536 after.
   * The two arms were 4x apart and are now 6x apart. A legacy compile is
   * still refused at 65535 tokens, and no figure in this comment says
   * otherwise.
   *
   * THE ANSWER THIS BOUND DOES NOT GIVE, AND WHERE IT WENT. Lifted to 393216
   * on a COPY, the 61-module corpus lexes to its full 307653 and then refuses
   * again, at MAX_NODES: code 201 "Nova expression limit", 1081344 expressions,
   * diagnostics.nova:392. That is the next bound, not this one, and it is
   * reported here rather than fixed -- a token ceiling raised on a guess would
   * have hidden it for another lot. It is no longer the next bound: MAX_NODES
   * was measured and raised in lot 83, and the comment under it carries the
   * derivation, so the refusal above is the one that happened while
   * MAX_NODES stood at 1081344 and does not happen now. The corpus still
   * carries no gate entry, so as one call it cannot produce an image at any
   * bound: it refuses 701 "Nova ABI2 requires main" once the others are lifted,
   * and it now gets past this guard and stops at MAX_LOCALS instead. What this
   * paragraph does NOT give is still true and still open: a corpus-wide entry.
   * Read the two together -- this one for the token need, the one below for the
   * node need -- rather than the first alone, which is a day out of date in its
   * last sentence.
   * Re-measured 20261002. Every figure here is produced by
   * out/c-bootstrap/nova/lot78/, which writes nothing under
   * compiler/c/ and prints the diff of its instrumented copy
   * against this file. */
  MAX_TOKENS = 393216,
  /* Node budget. 32 Ki steps, 25% headroom over the measured need, and now
   * written out in full because this is the bound whose stated need stopped
   * being true while the number stayed where it was (MEM.md R151, R183).
   *
   * HISTORY. 262144 held 294912; 327680 held to the features pass; the 39
   * inputs of the validate gate plus macro_expand.nova measured 672982
   * expressions, and 851968 was the smallest 32 Ki step at or above
   * 1.25*672982 = 841228. 851968 stopped holding when the diagnostics gate grew
   * to 41 inputs, which measured 863016 expressions, and 1081344 was the
   * smallest 32 Ki step at or above 1.25*863016 = 1078770, a headroom of 1.25x.
   * Re-measured 20260927. That was correct on the tree of that day.
   *
   * WHAT IS MEASURED NOW, and this is the whole derivation. The 61 pipeline
   * modules of the compiler/nova corpus, lexed in ONE
   * nova_compile_many_v2 call, measure 2064667 expressions. That set is what
   * fires this guard: at 1081344 it refuses with code 201 "Nova expression
   * limit" at 392:13, and the instrumented copy reports expression_count =
   * 1081344, statement_count = 741403 at the refusal. The span's source index
   * is 35, and span.source is one-based, so the module is the 35th of the 61 in
   * sorted order: compiler/nova/ntir_inspect.nova. The MAX_TOKENS
   * comment above reports the same refusal site as diagnostics.nova:392. The
   * two disagree about which module that is and neither is corrected here to
   * match the other: publish both and let a reader with the tree settle it
   * (R161). What is not in dispute is the COUNT, which is the thing this bound
   * is sized on, and it is the same number in both lots.
   *
   *   need            = 2064667 expressions   (the 61-module corpus lex)
   *   1.25 * need     = 2580833.75
   *   step            = 2588672 = 79 * 32768  <- smallest 32 Ki step >= it
   *   step below      = 2555904 = 1.238x      <- does NOT qualify
   *   headroom        = 2588672 / 2064667 = 1.254x
   *   old bound       = 1081344 = 0.524x of the need
   *
   * THE OLD BOUND WAS NOT A MARGIN. It was 0.524x of this need, and R183 says
   * a bound under the need is not a margin. It was under the need of the
   * widest real program on this tree as well: tests/diagnostics-entry.nova, 44
   * modules, measures 1118916 expressions when the bound is lifted, which is
   * 1.035x of 1081344. That closure has been refusing on this guard, and only
   * this guard, at the size it has today. Deriving from 1118916 instead would
   * give 1.25*1118916 = 1398645 and the step 1409024 = 43 * 32768; it is NOT
   * what is written above, for the same reason MAX_TOKENS is sized after the
   * whole-corpus lex and not after the heaviest gate: the corpus lex is the only
   * workload that has ever reached this bound and the one that explains the
   * refusal anyone has observed. Both numbers are here so the choice can be
   * checked rather than inherited.
   *
   * TWO COUNTERS, ONE BOUND, AND WHICH ONE IS AT THE WALL. expression_new() and
   * statement_new() both read this constant, and a reader will take them for one
   * measurement. They are two. At the corpus refusal above, expression_count was
   * 1081344 of 1081344 and statement_count was 741403, which is 0.686x of the
   * SAME bound, so the guard that fired is the EXPRESSION one. At completion the
   * corpus carries 1451402 statements against 2064667 expressions, a ratio of
   * 0.703 that ran between 0.703 and 0.711 over the 56 rungs of a 64 rung
   * ladder that compile at all, so the statement count is never the larger of
   * the two on this tree. The shared bound is therefore the right shape: one
   * number, sized by the counter that is larger, with the smaller one riding on
   * a ceiling 1.78x its own need. A separate statement bound would be a second
   * number to derive and to keep true, and it would buy nothing, because no
   * measurement on this tree has the statement counter anywhere near the
   * expression one. The 64 rung ladder is the cleanest single check of the
   * change: at 1081344 fourteen of its rungs fire THIS guard and none fire the
   * statement one; at 2588672 no rung fires this guard at all and eight fire
   * MAX_LOCALS instead, which is the next bound and the paragraph after this.
   *
   * THE NEED IS NOT THE LARGEST PROGRAM HERE, for the reason MAX_TOKENS records
   * at length and not repeated. Of the 107 gate closures -- the only closures
   * that can produce an image -- 105 complete at the old bound and 106 at this
   * one. The one this guard stopped is diagnostics-entry.nova, 44 modules,
   * refused on the expression guard before this change and compiles after it,
   * measured at 1118916 expressions and 786897 statements. tests/fixtures/
   * pe-dependency.nova refuses code 701
   * "Nova ABI2 requires main" and is a fixture, not a bound. The 61-module
   * corpus carries no gate entry, so as one call it still cannot produce an
   * image at ANY bound: with this one lifted it refuses 701 as well. A larger
   * ceiling is not a smaller workload.
   *
   * WHAT A RAISE COSTS. This constant is not only a guard: compile_profile()
   * sizes c->p.expressions AND c->p.statements with it, and lower_expr() takes
   * its budget as MAX_NODES * 4. sizeof(NtFExpr) = 232 and sizeof(NtFStmt) = 168,
   * measured from inside the translation unit, so the two arrays are 400 bytes
   * per node: 432537600 bytes at 1081344 and 1035468800 here, a rise of
   * 602931200 bytes, 575 MiB. That is a large number and it is stated rather
   * than left for a reader to compute. Three things bound it. The arrays are
   * plain calloc, so a run pays for the entries it writes and not for the
   * ceiling: the corpus touches 825866800 bytes of them, and the largest gate
   * closure 447566400. Nothing that reaches an artifact is sized by this
   * constant, so the rise is a resident cost and not a change to any emitted
   * image -- which is why no gate banner moves, a claim that was then measured
   * rather than argued (out/c-bootstrap/nova/lot83/, section 6 of FINDINGS.md:
   * four runs on one frozen tree, three values, identical banners and identical
   * full logs).
   * And the lowering budget moves with it, 4325376 to 10354688, against a
   * measured corpus peak of 113770, so it is not the binding one either.
   *
   * THE NEXT BOUND WAS MAX_LOCALS, AND IT IS NOW SIZED. When this comment was
   * written MAX_LOCALS was 196608 against a corpus need of 326067, 0.604x of it,
   * and the whole arithmetic was left to the next lot on purpose: raising it on
   * a guess would have hidden it, exactly as a token ceiling raised on a guess
   * hid this one for a day. Lot 106 measured it instead (327248 variables on the
   * 20261002 corpus, 0.601x for the old bound) and MAX_LOCALS is now 425984, so
   * the two paragraphs that describe it are below. Nothing in THIS constant
   * moved, and nothing in this comment's own figures moved with it: every
   * COMPLETION count here was taken with both bounds lifted on a copy, because
   * a count printed where a run died is a death mark and not a measurement. On
   * the 20261002 corpus the three ceilings stand at 0.801x, 0.785x and 0.768x of
   * their needs, so MAX_NODES is now the nearest wall of the three and a
   * corpus-wide program stops there before it stops at the variable guard.
   *
   * THE OTHER THRESHOLD, WHICH IS NOT THIS NUMBER. Both guards read
   *     c->p.expression_count >= (c->safe_v2 ? MAX_NODES : 32768)
   * so a reader will conflate the arms. Only the first is this constant; the
   * second is a literal typed at the guard and belongs to the LEGACY profile
   * (nova_compile_many, safe_v2 == 0). It is 32768 before and 32768 after. The
   * two arms were 33x apart and are now 79x apart, further and not closer.
   *
   * Every figure above is produced by out/c-bootstrap/nova/lot83/, which writes
   * nothing under compiler/c/ except this comment and this value,
   * runs against a FROZEN copy of the tree so no sibling edit could enter a
   * measurement, and prints the diff of its instrumented copy against that
   * tree. Re-measured 20261002. */
  MAX_NODES = 2588672,
  /* THE NAME IS NOT WHAT THIS CONSTANT BOUNDS. Read the census before the
   * number. MAX_VARS is named at ELEVEN places in this translation unit: SIX
   * of them are GUARD reads that can refuse, and FIVE are SIZINGS that only
   * array() memory and cannot refuse at all.
   *
   * The SIX guards do not compare one counter. They compare THREE DIFFERENT
   * ONES:
   *     - c->p.type_count at FOUR of them, whose messages are "Nova type
   *       limit", "Nova record type limit", "Nova literal type limit" and
   *       "Nova memory type limit";
   *     - c->field_count at ONE, the record field guard, whose message is
   *       "record field limit";
   *     - c->p.variable_count at ONE, and that one is the LEGACY arm of the
   *       variable guard: `variable_count >= (safe_v2 ? MAX_LOCALS : MAX_VARS)`.
   *       It is the ONLY read of this constant that is about variables.
   * The FIVE sizings are c->tm and c->p.types (type_count), c->fields
   * (field_count), and -- on the same ternary as the one variable guard --
   * c->vm and c->p.variables.
   *
   * SO ON THE PROFILE THIS TREE COMPILES, MAX_VARS BOUNDS TYPES AND RECORD
   * FIELDS AND NOT VARIABLES AT ALL. The variable budget on that profile is
   * MAX_LOCALS, the constant the other arm of that ternary names. Its name is a
   * historical accident and this paragraph is the only place in the file that
   * says so.
   *
   * 326067 -- the "326067 VARIABLES" lot 83 reported in the same sentence set
   * as "2064667 expressions" -- IS NOT COMPARABLE TO THIS NUMBER, AND THE NEXT
   * READER WILL SUBTRACT THEM ANYWAY. 326067 is c->p.variable_count. On the
   * profile the corpus compiles under, c->p.variable_count is compared against
   * MAX_LOCALS and never against this constant. It IS comparable to MAX_LOCALS
   * = 425984, which is where lot 106 measured it (327248; re-measured here at
   * 327964, a sibling measurement of the same quantity on a slightly later
   * tree). 326067 against 4096 is not a factor of eighty below a bound; it is a
   * factor of eighty between a VARIABLE count and a TYPE-AND-FIELD budget, which
   * measure different things, so the factor carries no meaning either way. If
   * the question is whether the variable ceiling is high enough, MAX_LOCALS is
   * the number to read and this one is not evidence about it.
   *
   * THE MEASUREMENT, on the same population lot 106 used: the 61 top-level
   * .nova modules of compiler/nova, 1805164 bytes, as ONE call to
   * nova_compile_many_v2, on a frozen copy of the tree, with this constant and
   * MAX_FUNCS raised on a COPY so the run COMPLETED and its counts are a
   * completion and not a death mark. It reaches type_count 1080 and field_count
   * 232, with variable_count 327964, function_count 1790, expression_count
   * 2077786, statement_count 1460660 and token_count 309169 alongside. The 107
   * gate closures -- the only closures that can produce an image -- reach at
   * most type_count 631 and field_count 187, and 106 of the 107 complete at
   * this bound. NOT ONE of the 107, and NOT ONE of 64 ladder rungs, reached ANY
   * read of this constant or of MAX_FUNCS.
   *
   * SO WHAT THE 32 Ki / 1.25x RULE SAYS, STATED AND NOT ACTED ON. 1.25*1080 =
   * 1350, and the smallest 32 Ki step at or above 1350 is 32768. The step below
   * it does not exist on this grid: 32768 is the FIRST step, so there is no
   * smaller one, and 4096 is an eighth of it. So the rule would say 32768, and
   * 32768 is 30.34x the need.
   *
   * This lot does NOT raise it, and the reason is that the headroom rule is
   * ALREADY SATISFIED BY A WIDE MARGIN AND THE STEP IS A CONVENTION THE OTHER
   * FOUR FOLLOW AND THIS ONE NEVER DID. 4096 is 3.7926x the measured need of
   * 1080 and 17.6552x the measured need of 232 on the other counter it bounds.
   * Contrast MAX_LOCALS, which stood at 0.601x of its need and had to be
   * raised: that was a bound BELOW its workload, and every corpus-wide compile
   * died before it finished. This one is not below anything. 4096 is also a
   * power of two, not a multiple of 32768, so it was never on the step grid and
   * nothing here is being restored to it.
   *
   * AND RAISING IT WOULD CHANGE A SECOND PROFILE BY EIGHT, WHICH IS THE REAL
   * ARGUMENT AGAINST. This constant is the ONLY bound on variables on the
   * LEGACY profile (safe_v2 == 0, nova_compile / nova_compile_many). Raising it
   * to 32768 raises that profile's variable ceiling from 4096 to 32768 as a
   * side effect of a derivation aimed at TYPES. That profile's other ceilings
   * are the literal 256 at the function guard, 32768 at the node guard and
   * 65536 at the token guard; making its variable ceiling equal its node
   * ceiling is a change to that profile's shape, and no measurement in this
   * lot justifies it. One constant serving three counters with needs of 1080,
   * 232 and an unmeasured legacy variable need is not a shared MEASUREMENT; see
   * the paragraph below.
   *
   * THE BOUND IS STILL A BOUND, which is checked and not assumed. Three
   * generated programs, each built to cross one of the counters, each refused
   * code 201 with a position, and each COMPLETED when the bound was lifted --
   * which is the pair that says the refusal was the bound and not something
   * else:
   *     4096 one-field structs   -> type_count 4096, "Nova record type limit"
   *                                 at 4087:8
   *     66 structs of 64 fields  -> field_count 4096, "record field limit"
   *                                 at 66:14, AT type_count 77 -- that is 53x
   *                                 short of the type wall and exactly AT the
   *                                 field wall. That is the measurement that
   *                                 makes these two counters independent, and
   *                                 so the one constant that reads both is not
   *                                 reading one measurement twice.
   *     32768 functions          -> function_count 32768, "Nova function
   *                                 limit" at 32770:15 (MAX_FUNCS, not this)
   *
   * THE LEGACY ARM, AND WHY THE CORPUS CANNOT EXERCISE IT. The corpus is
   * safe_v2 source -- it opens with `module <name>;` -- and the legacy profile
   * refuses all 61 modules with code 100 "Nova invalid source byte" on their
   * first line. So the legacy ladder measures a refusal at byte 0 and its
   * counts are the counts of a program that never started; reporting them as a
   * legacy need would be the exact defect this paragraph exists to prevent.
   * Measured on legacy source instead, the arm is live and refuses cleanly: a
   * generated program of 4160 locals is refused at variable_count 4096 against
   * 4096, at the guard named "Nova variable limit". What the legacy profile
   * cannot do is grow type_count with records: collect_records() is called only
   * `if (c->safe_v2)`, so 4096 structs in legacy source mint ZERO types, and
   * the field guard is unreachable there entirely.
   *
   * WHAT WOULD JUSTIFY RAISING IT, since this lot did not. Any ONE of these,
   * measured, and not reasoned:
   *     - a program of this tree that refuses with "Nova record type limit",
   *       "Nova type limit", "Nova literal type limit", "Nova memory type
   *       limit" or "record field limit", at any count. That would be a
   *       completion with the constant lifted, and its count would be the need.
   *       Nothing on this tree produces one: not the corpus, not the 107 gate
   *       closures, not the 64 rungs.
   *     - a workload whose type_count passes 4096. From today's 1080 that is
   *       3016 more, very nearly a quadrupling, and the widest completing gate
   *       closure on this tree reaches 631, so the gap is not close.
   *     - a LEGACY workload whose variable_count exceeds 4096. This is the one
   *       that would genuinely justify a raise, because on that profile this
   *       constant IS the variable bound; and it cannot be produced from the
   *       corpus, which does not parse there. It would have to come from a
   *       caller of nova_compile / nova_compile_many, and the only callers on
   *       this tree are unit tests over inline string literals.
   *
   * WHAT A RAISE WOULD COST. This constant is the only thing that sizes three
   * arrays, and all three are measured from inside this translation unit
   * because TypeMeta and Field are private to it and cannot be measured from
   * outside at all: sizeof(TypeMeta) = 48, sizeof(NtFType) = 32, sizeof(Field) =
   * 56, so 136 B per unit. At 4096 the three together are 557056 B, 0.5 MiB;
   * at 32768 they would be 4456448 B, 4.2 MiB, a rise of 3899392 B, 3.7 MiB per
   * compiler instance. That is the price of a raise nothing needs, and it is
   * stated rather than left for a reader to compute.
   *
   * Every figure above is produced by out/c-bootstrap/nova/lot119/, which
   * writes nothing under compiler/c/ except this comment, runs
   * against a FROZEN copy of the tree so no sibling edit could enter a
   * measurement, and prints the diff of its instrumented copy against that
   * tree. Line numbers are quoted only where a control's refusal position is
   * part of the claim. Re-measured 20261002. */
  MAX_VARS = 4096,
  /* Variable budget: the same 32 Ki step as its neighbours, but sized by a
   * measurement and not by a comment somebody read.
   *
   * THE POPULATION FIRST, because a variable count without a set is a number
   * without a meaning. Every figure below is over ONE population: the 61
   * top-level .nova modules of compiler/nova, 1791958 bytes, compiled as a
   * SINGLE call to nova_compile_many_v2. The 107 gate closures --
   * the only closures that can produce an image -- are measured over the same
   * tree, and the widest of them (diagnostics-entry.nova, 44 modules) needs 180415
   * variables, 0.551x of the corpus-wide figure, so the one call is the larger
   * population and the one this constant is sized against. 106 of the 107
   * complete at the old bound; the one that does not is
   * tests/fixtures/pe-dependency.nova, which refuses 701 "Nova ABI2 requires
   * main" at the lift as well and is a fixture, not a bound.
   *
   * THE NEED IS A COMPLETION AND NOT A DEATH MARK. 327248 variables, taken with
   * this one constant lifted to 16000000 on a COPY, MAX_NODES untouched at
   * 2588672 so nothing else became the wall. The same corpus at the old value
   * refuses 201 "Nova variable limit" at variable_count 196608, and the counts on
   * that run are how far it got and not what it needs. The lifted run reaches the
   * end of the corpus and its only remaining refusal is the corpus-wide 701,
   * which is not a bound. On the same corpus the counters read expr=2073172,
   * stmt=1457383, toks=308445, funcs=1788, and the tree carries no larger need in
   * any of them.
   *
   * THE ARITHMETIC, all five parts. 1.25*327248 = 409060. The smallest 32 Ki step
   * at or above it is 425984 = 13*32768. The step BELOW it is 393216 = 12*32768,
   * which is 1.2016x the need and 15844 variables short of 1.25x, so it does not
   * qualify and the chosen step is the smallest that does. Headroom is
   * 425984/327248 = 1.3017x. THE OLD BOUND WAS 0.601x OF THE NEED: it was not a
   * margin, it was BELOW the workload, so every corpus-wide compile on this tree
   * died before it finished and no amount of correctness at 196608 could have
   * produced an image. 196608 was itself the smallest 32 Ki step above a need of
   * 134265 measured on a much smaller input set; that need has since moved 2.44x
   * and the number was carried forward rather than re-derived, which is exactly
   * how a bound ends up below its workload while every comment above it is
   * individually true.
   *
   * ONE MEASUREMENT OR TWO. THREE reads of this constant exist in the translation
   * unit and exactly ONE of them can refuse anything: variable_new() at nova.c:735,
   * on c->p.variable_count. The other two, compile_profile() at :2657 and :2665,
   * size c->vm and c->p.variables; they cannot refuse, they calloc. So this is NOT
   * the MAX_NODES shape, where expression_new and statement_new are two
   * comparisons against one constant and only one of them ever fires: there is no
   * second variable counter in this compiler, and over 64 ladder rungs the eight
   * that reach this bound -- rungs 49 to 56 -- all name the same variable guard.
   * The two sizings are the GUARD'S CONSEQUENCE and not a second measurement: both
   * arrays are indexed only by NtFId values variable_new() minted under the guard,
   * or by loops bounded by variable_count, so a sizing set independently of the
   * guard would turn this constant from a bound into a heap overflow. They read
   * the same name, so they cannot disagree.
   *
   * THE BOUND IS STILL A BOUND, which is checked rather than assumed. A generated
   * 685752 byte program of 24000 statements of 'let v:buf<u8>=w(s,s,s);' -- 21
   * variables per 16 tokens, a shape chosen BY MEASUREMENT because at this bound
   * MAX_TOKENS allows 0.923 tokens per variable and MAX_NODES 6.08, so the
   * variable guard is the FIRST wall it meets -- reaches the new value and is
   * refused code=201 "Nova variable limit" at 19911:20, on expression_count
   * 2436259 of 2588672, i.e. before either node guard. The same program is refused
   * at 7834:1 on the old value. A raised bound that can no longer refuse is a bound
   * that was wrong to raise.
   *
   * WHAT A RAISE COSTS. This constant is not only a guard: it is the ONLY thing
   * that sizes c->vm (VariableMeta, 16 B) and c->p.variables (NtFVariable, 128 B).
   * Both were measured, not assumed -- the first from INSIDE this translation unit
   * because VariableMeta is private to it and cannot be measured from outside at
   * all, the second from outside as well so the two can be compared rather than one
   * assumed. That is 144 B per variable, so one 32 Ki step of this constant is
   * exactly 4718592 B, 4.5 MiB, and the headroom above is worth 7 of them. At
   * 196608 the two arrays are 28311552 B, 27.0 MiB; at 425984 they are 61341696 B,
   * 58.5 MiB; the rise is 33030144 B, 31.5 MiB. That is a large number and it is
   * stated rather than left for a reader to compute. Peak resident cost is not it:
   * both arrays are plain calloc and only written entries are faulted in, and the
   * corpus touches 47123712 B of them, 44.9 MiB. Nothing that reaches an artefact
   * is sized by this constant.
   *
   * THE OTHER THRESHOLD, WHICH IS NOT THIS NUMBER. The guard reads
   *     c->p.variable_count >= (c->safe_v2 ? MAX_LOCALS : MAX_VARS)
   * so a reader will conflate the arms. Only the first is this constant; the
   * second is MAX_VARS = 4096 and belongs to the LEGACY profile (nova_compile_many,
   * safe_v2 == 0). It is 4096 before and 4096 after.
   *
   * Every figure above is produced by out/c-bootstrap/nova/lot106/, which writes
   * nothing under compiler/c/ except this comment and this value,
   * runs against a FROZEN copy of the tree so no sibling edit could enter a
   * measurement, prints the diff of its instrumented copy against that tree, and
   * rebuilds a FRESH variant object for every bound it quotes so no run can report
   * a bound using the last run's binary. Re-measured 20261002. */
  MAX_LOCALS = 425984,
  /* Function budget, the same 32 Ki steps over the same 25% headroom. This
   * is the first of the five bounds whose value is derived from a measured
   * need rather than transcribed from a comment (MEM.md R151), so the
   * derivation is written out here in full. The 42 module validate image
   * declares 861 functions; adding compiler/nova/ir/machine_ir.nova to
   * that SAME compile declares 258 more, because the budget is per PROGRAM
   * and not per module, for 1119.
   * 1.25*1119 = 1398.75, and the smallest 32 Ki step at or above it is
   * 32768.
   * READ THE NEXT PARAGRAPH BEFORE TRUSTING THE NUMBER. The STEP is what
   * carries this value, not the headroom rule: 32768 is 29.28x the measured
   * need, where MAX_NODES sits at 1.25x and MAX_LOCALS at 1.46x. It was not
   * traded away for that, because the bound is free -- fm and p.functions
   * are plain calloc and only declared entries are ever written, so the 43
   * module compile peaks at 427648 kB with this bound and 428032 kB with
   * the cap lifted to 1000000, measured, which is why raising it costs
   * nothing that the other four bounds are not already spending.
   * THE NEED IS A PROPERTY OF THIS IMAGE and not of the compiler: it moves
   * whenever a module in ng_parity_paths moves. ast.nova is 8 of the change
   * since lot 51 (7252f0fe...); validate.nova is 0 of it (29f046c9...,
   * byte-identical to the digest MEM.md records, so its 20261001 01:49:53
   * write was a restore and not an addition); and lot 51's 851 is NOT
   * reproducible from this tree and has no artefact to bisect against, so
   * two functions of that change are unaccounted for. They are reported
   * here rather than resolved, because a number nobody can reproduce is a
   * fact about the measurement and not about the bound.
   *
   * RE-MEASURED 20261002 ON A LARGER POPULATION, AND THE VALUE IS CONFIRMED
   * RATHER THAN CHANGED. Lot 53 sized this against ONE image. The 61 top-level
   * modules of compiler/nova, compiled as a SINGLE call to
   * nova_compile_many_v2 on a frozen copy of the tree, declare 1790 functions
   * -- a need 1.60x the 1119 above, and the largest this compiler has been
   * asked to hold. 1.25*1790 = 2237.50, and the smallest 32 Ki step at or above
   * it is 32768 again, so the two populations derive the SAME constant and the
   * value in the file did not move. The headroom on the larger figure is
   * 18.31x rather than 29.28x, and the argument of the paragraph above is
   * unchanged and still the reason it is not smaller: the STEP carries this
   * value and the bound is free, because fm and p.functions are plain calloc
   * and only declared entries are ever written.
   *
   * THE READ CENSUS, WHICH IS ONE COUNTER AND NOT TWO. MAX_FUNCS is named at
   * FOUR places: TWO guards and TWO sizings. Both guards compare
   * c->p.function_count and nothing else -- `function_count >= (safe_v2 ?
   * MAX_FUNCS : 256)` where a function is declared, and a second, unconditional
   * `function_count >= MAX_FUNCS` in the ABI2 wrapper, which mints one more
   * entry for the synthesised `main` and must leave room for it. Two reads, one
   * counter: this IS a shared MEASUREMENT, unlike the constant above it, and
   * the difference is the whole of the two derivations' shapes. The two
   * sizings are c->fm and c->p.functions, which cannot refuse.
   *
   * Note the OTHER THRESHOLD, which is not this constant: the first guard's
   * legacy arm is the literal 256, not MAX_FUNCS. It is 256 before and 256
   * after, and a generated legacy program of 300 functions is refused at
   * function_count 256 against 256, so that arm is a bound in its own right and
   * is not evidence about this one.
   *
   * THE BOUND IS STILL A BOUND, checked and not assumed. A generated program of
   * 32768 functions is refused code 201 "Nova function limit" at function_count
   * 32768 against 32768, at 32770:15, and the SAME program completes with 32770
   * functions when this constant alone is lifted. That pair is what says the
   * refusal was this bound and not something else, and it is why a value that
   * sits 18.31x above the need is still a bound rather than a constant.
   *
   * Nothing on this tree comes near it: not the corpus at 1790, not the 107
   * gate closures (the widest completes at 1169), and not one of 64 ladder
   * rungs. If a raise were ever wanted, the evidence would be a program of this
   * tree refused with "Nova function limit" or "Nova ABI2 wrapper exceeds
   * function limit", at any count; the completion with the constant lifted
   * would then be the need. Nothing here produces one.
   * Re-measured 20261001, and again 20261002. The 20261001 figures are at
   * out/c-bootstrap/nova/lot53/probe_funcs.sh and the 20261002 ones at
   * out/c-bootstrap/nova/lot119/, both of which write nothing under
   * compiler/c/ and print the diff of their instrumented copy
   * against this file. */
  MAX_FUNCS = 32768,
  T_ID = 256,
  T_NUM,
  T_STRING,
  T_ARROW,
  T_EQ,
  T_NE,
  T_LE,
  T_GE,
  T_SHL,
  T_SHR,
  T_AND,
  T_OR,
  X_INDEX = 100,
  X_LEN = 101,
  X_RUNTIME = 102,
  X_ALLOC = 103,
  X_SLICE = 104,
  X_BYTES = 105,
  X_RECORD = 106,
  X_FIELD = 107,
  X_FIELD_INIT = 108,
  OP_AND = 100,
  OP_OR = 101
};
enum {
  TY_U8 = 1,
  TY_U64 = 2,
  TY_BOOL = 3,
  TY_BUF = 4,
  TY_RUNTIME = 5,
  TY_U16 = 6,
  TY_U32 = 7,
  TY_I8 = 8,
  TY_I16 = 9,
  TY_I32 = 10,
  TY_I64 = 11
};
typedef struct {
  int kind;
  char text[80];
  uint64_t value;
  NtFSpan span;
  char *bytes;
  size_t byte_count;
} Token;
typedef struct Owned {
  void *pointer;
  struct Owned *next;
} Owned;
typedef struct {
  int kind, exported;
  NtFId element, module;
  const char *name;
  unsigned first_field, field_count;
  size_t body_start, body_end;
} TypeMeta;
typedef struct {
  const char *name;
  NtFId type;
  NtFSpan span;
  unsigned offset;
} Field;
typedef struct {
  unsigned scope, active, mutable_value;
  NtFId length;
} VariableMeta;
typedef struct {
  size_t start, end;
  unsigned count;
  NtFId params[64];
} FunctionMeta;
typedef struct {
  NtFProgram p;
  Token *tokens;
  size_t token_count, at;
  VariableMeta *vm;
  FunctionMeta *fm;
  NtArtifact *out;
  jmp_buf failure;
  NtFId function;
  unsigned scope, depth;
  size_t lowering_budget;
  int safe_v2;
  Owned *owned;
  size_t literal_bytes;
  NtFId current_module, source_module[65];
  size_t header_end[65];
  unsigned char imports[65][65];
  Token *import_tokens[65][64];
  unsigned import_count[65];
  TypeMeta *tm;
  Field *fields;
  unsigned field_count;
  size_t *skip_declaration;
  NtFId loop_start[128], loop_end[128];
  unsigned loop_depth;
} Compiler;
#define EX(c, i) ((c)->p.expressions[(i) - 1])
#define ST(c, i) ((c)->p.statements[(i) - 1])
#define VA(c, i) ((c)->p.variables[(i) - 1])
#define FN(c, i) ((c)->p.functions[(i) - 1])
static Token *tok(Compiler *c) { return &c->tokens[c->at]; }
static void fail_at(Compiler *c, unsigned code, NtFSpan s,
                    const char *message) {
  c->out->error.code = code;
  c->out->error.source_index = s.source;
  c->out->error.offset = s.start;
  c->out->error.line = s.line;
  c->out->error.column = s.column;
  snprintf(c->out->error.message, sizeof c->out->error.message, "%s", message);
  longjmp(c->failure, 1);
}
static void fail(Compiler *c, unsigned code, const char *m) {
  fail_at(c, code, tok(c)->span, m);
}
static void *array(Compiler *c, size_t count, size_t size) {
  void *p = calloc(count, size);
  if (!p)
    fail_at(c, 900, (NtFSpan){0}, "Nova allocation failed");
  return p;
}
static void *owned(Compiler *c, size_t size) {
  void *p = array(c, size ? size : 1, 1);
  Owned *n = malloc(sizeof *n);
  if (!n) {
    free(p);
    fail_at(c, 900, (NtFSpan){0}, "Nova allocation failed");
  }
  *n = (Owned){p, c->owned};
  c->owned = n;
  return p;
}
static unsigned hex_digit(unsigned b) {
  return b >= '0' && b <= '9'   ? b - '0'
         : b >= 'a' && b <= 'f' ? b - 'a' + 10
         : b >= 'A' && b <= 'F' ? b - 'A' + 10
                                : 99;
}
static void enter(Compiler *c) {
  if (++c->depth > 128)
    fail(c, 201, "Nova nesting exceeds 128");
}
static void leave(Compiler *c) { --c->depth; }
static int accept(Compiler *c, int kind) {
  if (tok(c)->kind == kind) {
    c->at++;
    return 1;
  }
  return 0;
}
static int word(Compiler *c, const char *w) {
  return tok(c)->kind == T_ID && !strcmp(tok(c)->text, w);
}
static int keyword(Compiler *c, const char *w) {
  if (word(c, w)) {
    c->at++;
    return 1;
  }
  return 0;
}
static Token *need(Compiler *c, int kind, const char *message) {
  Token *t = tok(c);
  if (!accept(c, kind))
    fail(c, 200, message);
  return t;
}
static void token_push(Compiler *c, Token t) {
  if (c->token_count >= (c->safe_v2 ? MAX_TOKENS : 65536) - 1)
    fail_at(c, 201, t.span, "Nova token limit");
  c->tokens[c->token_count++] = t;
}
static int alpha(unsigned ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_';
}
static int digit(unsigned ch) { return ch >= '0' && ch <= '9'; }
static void lex(Compiler *c, const NtFInput *inputs, size_t count) {
  if (!inputs || !count || count > 64)
    fail_at(c, 201, (NtFSpan){0}, "Nova expects 1..64 inputs");
  for (size_t file = 0; file < count; file++) {
    const char *s = inputs[file].text;
    size_t n = inputs[file].length, i = 0;
    uint32_t line = 1, col = 1;
    if (!s || n > 4 * 1024 * 1024)
      fail_at(c, 201, (NtFSpan){.source = (uint32_t)file + 1},
              "Nova source absent or exceeds 4 MiB");
    while (i < n) {
      unsigned ch = (unsigned char)s[i];
      if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
        i++;
        if (ch == '\n') {
          line++;
          col = 1;
        } else
          col++;
        continue;
      }
      if (ch == '/' && i + 1 < n && s[i + 1] == '/') {
        while (i < n && s[i] != '\n') {
          i++;
          col++;
        }
        continue;
      }
      Token t = {0};
      t.span = (NtFSpan){(uint32_t)file + 1, line, col, i, i + 1};
      size_t begin = i;
      if (alpha(ch)) {
        t.kind = T_ID;
        while (i < n &&
               (alpha((unsigned char)s[i]) || digit((unsigned char)s[i])))
          i++;
        if (i - begin >= sizeof t.text)
          fail_at(c, 201, t.span, "Nova identifier exceeds 79 bytes");
        memcpy(t.text, s + begin, i - begin);
      } else if (ch == '"' && c->safe_v2) {
        size_t end = i + 1;
        while (end < n && s[end] != '"' && s[end] != '\n' && s[end] != '\r') {
          if (s[end] == '\\' && end + 1 < n)
            end++;
          end++;
        }
        if (end >= n || s[end] != '"')
          fail_at(c, 100, t.span, "unterminated Nova string");
        t.kind = T_STRING;
        t.bytes = owned(c, end - i);
        i++;
        while (i < end) {
          unsigned b = (unsigned char)s[i++];
          if (b == '\\') {
            if (i == end)
              fail_at(c, 100, t.span, "unterminated string escape");
            b = (unsigned char)s[i++];
            if (b == 'n')
              b = '\n';
            else if (b == 'r')
              b = '\r';
            else if (b == 't')
              b = '\t';
            else if (b == '0')
              b = 0;
            else if (b == 'x') {
              if (end - i < 2 || hex_digit((unsigned char)s[i]) > 15 ||
                  hex_digit((unsigned char)s[i + 1]) > 15)
                fail_at(c, 100, t.span, "invalid hex string escape");
              b = hex_digit((unsigned char)s[i]) * 16 +
                  hex_digit((unsigned char)s[i + 1]);
              i += 2;
            } else if (b != '\\' && b != '"')
              fail_at(c, 100, t.span, "unknown Nova string escape");
          }
          t.bytes[t.byte_count++] = (char)b;
        }
        i++;
      } else if (digit(ch)) {
        t.kind = T_NUM;
        unsigned base = 10;
        if (ch == '0' && i + 1 < n && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
          base = 16;
          i += 2;
        }
        size_t digits = i;
        while (i < n) {
          unsigned b = (unsigned char)s[i],
                   d = b >= '0' && b <= '9'   ? b - '0'
                       : b >= 'a' && b <= 'f' ? b - 'a' + 10
                       : b >= 'A' && b <= 'F' ? b - 'A' + 10
                                              : 99;
          if (d >= base)
            break;
          if (t.value > (UINT64_MAX - d) / base)
            fail_at(c, 401, t.span, "Nova integer exceeds u64");
          t.value = t.value * base + d;
          i++;
        }
        if (i == digits)
          fail_at(c, 100, t.span, "Nova number has no digits");
        if (i < n && alpha((unsigned char)s[i]))
          fail_at(c, 100, t.span, "Nova malformed integer suffix");
      } else {
        t.kind = (int)ch;
        i++;
        if (i < n) {
          int pair = 0;
          unsigned next = (unsigned char)s[i];
          if (ch == '-' && next == '>')
            pair = T_ARROW;
          else if (ch == '=' && next == '=')
            pair = T_EQ;
          else if (ch == '!' && next == '=')
            pair = T_NE;
          else if (ch == '<' && next == '=')
            pair = T_LE;
          else if (ch == '>' && next == '=')
            pair = T_GE;
          else if (ch == '<' && next == '<')
            pair = T_SHL;
          else if (ch == '>' && next == '>')
            pair = T_SHR;
          else if (ch == '&' && next == '&')
            pair = T_AND;
          else if (ch == '|' && next == '|')
            pair = T_OR;
          if (pair) {
            t.kind = pair;
            i++;
          }
        }
        if (ch < 33 || ch > 126 || !strchr("(){}[],:;.+-*/%&|^~!<>=", (int)ch))
          fail_at(c, 100, t.span, "Nova invalid source byte");
      }
      t.span.end = i;
      col += (uint32_t)(i - begin);
      token_push(c, t);
    }
  }
  Token end = {0};
  if (c->token_count) {
    end.span = c->tokens[c->token_count - 1].span;
    end.span.start = end.span.end;
    end.span.column++;
  }
  token_push(c, end);
}
static NtFId expression_new(Compiler *c, NtFExpr x) {
  if (c->p.expression_count >= (c->safe_v2 ? MAX_NODES : 32768))
    fail_at(c, 201, x.span, "Nova expression limit");
  c->p.expressions[c->p.expression_count++] = x;
  return (NtFId)c->p.expression_count;
}
static NtFId statement_new(Compiler *c, NtFStmt s) {
  if (c->p.statement_count >= (c->safe_v2 ? MAX_NODES : 32768))
    fail_at(c, 201, s.span, "Nova statement limit");
  c->p.statements[c->p.statement_count++] = s;
  return (NtFId)c->p.statement_count;
}
static NtFId literal(Compiler *c, uint64_t n, NtFId type, NtFSpan span) {
  return expression_new(
      c, (NtFExpr){.kind = type == TY_BOOL ? NTF_X_BOOL : NTF_X_LITERAL,
                   .type = type,
                   .value = n,
                   .constant = 1,
                   .span = span});
}
static NtFId name_expr(Compiler *c, NtFId var, NtFSpan span) {
  return expression_new(c, (NtFExpr){.kind = NTF_X_NAME,
                                     .type = VA(c, var).type,
                                     .resolved = var,
                                     .name = VA(c, var).name,
                                     .span = span});
}
static NtFId binary(Compiler *c, NtFOp op, NtFId a, NtFId b, NtFId type,
                    NtFSpan span) {
  return expression_new(c, (NtFExpr){.kind = NTF_X_BINARY,
                                     .type = type,
                                     .op = op,
                                     .left = a,
                                     .right = b,
                                     .span = span});
}
static int is_buffer(Compiler *c, NtFId type) {
  return type && type <= c->p.type_count && c->tm[type - 1].kind == 1;
}
static int is_record(Compiler *c, NtFId type) {
  return type && type <= c->p.type_count && c->tm[type - 1].kind == 2;
}
static unsigned width_of(Compiler *c, NtFId type) {
  return type && type <= c->p.type_count && c->p.types[type - 1].bits
             ? c->p.types[type - 1].bits / 8
             : 8;
}
static int is_signed(NtFId type) { return type >= TY_I8 && type <= TY_I64; }
static NtFId builtin_integer(const char *name) {
  static const char *names[] = {"u8", "u64", "u16", "u32",
                                "i8", "i16", "i32", "i64"};
  static const NtFId ids[] = {TY_U8, TY_U64, TY_U16, TY_U32,
                              TY_I8, TY_I16, TY_I32, TY_I64};
  for (unsigned i = 0; i < 8; i++)
    if (!strcmp(name, names[i]))
      return ids[i];
  return 0;
}
static unsigned buffer_width(Compiler *c, NtFId type) {
  return width_of(c, c->tm[type - 1].element);
}
static NtFId type_lookup(Compiler *c, Token *qualifier, Token *name) {
  NtFId module = c->current_module;
  if (qualifier) {
    module = 0;
    for (size_t i = 0; i < c->p.module_count; i++)
      if (!strcmp(c->p.modules[i].name, qualifier->text))
        module = (NtFId)i + 1;
    if (!module || !c->imports[c->current_module - 1][module - 1])
      fail_at(c, 302, qualifier->span, "Nova type module is not imported");
  }
  for (size_t i = 0; i < c->p.type_count; i++)
    if (c->tm[i].kind == 2 && c->tm[i].module == module &&
        !strcmp(c->tm[i].name, name->text)) {
      if (qualifier && !c->tm[i].exported)
        fail_at(c, 302, name->span, "Nova record type is private");
      return (NtFId)i + 1;
    }
  fail_at(c, 400, name->span, "unknown Nova type");
  return 0;
}
static NtFId type_parse(Compiler *c);
static NtFId type_parse_inner(Compiler *c) {
  if (c->safe_v2 && tok(c)->kind == T_ID) {
    NtFId type = builtin_integer(tok(c)->text);
    if (type) {
      c->at++;
      return type;
    }
  }
  if (keyword(c, "runtime"))
    return TY_RUNTIME;
  if (keyword(c, "u64"))
    return TY_U64;
  if (keyword(c, "u8"))
    return TY_U8;
  if (keyword(c, "bool"))
    return TY_BOOL;
  if (keyword(c, "buf")) {
    need(c, '<', "expected < after buf");
    NtFId element;
    if (c->safe_v2) {
      element = type_parse(c);
      if (element == TY_RUNTIME)
        fail(c, 400, "runtime descriptors cannot be array elements");
    } else {
      if (!keyword(c, "u8"))
        fail(c, 400, "only buf<u8> is implemented");
      element = TY_U8;
    }
    if (tok(c)->kind == T_GE)
      tok(c)->kind = '=';
    else if (tok(c)->kind == T_SHR)
      tok(c)->kind = '>';
    else
      need(c, '>', "expected > after buffer element");
    for (size_t i = 0; i < c->p.type_count; i++)
      if (c->tm[i].kind == 1 && c->tm[i].element == element)
        return (NtFId)i + 1;
    if (c->p.type_count >= MAX_VARS)
      fail(c, 201, "Nova type limit");
    NtFId type = (NtFId)++c->p.type_count;
    c->p.types[type - 1] = (NtFType){.kind = NTF_T_PTR,
                                     .element = element,
                                     .bits = 64,
                                     .space = NTF_SPACE_USER};
    c->tm[type - 1] = (TypeMeta){.kind = 1, .element = element};
    return type;
  }
  if (c->safe_v2 && tok(c)->kind == T_ID) {
    Token *name = tok(c);
    c->at++;
    Token *qualifier = NULL;
    if (accept(c, '.')) {
      qualifier = name;
      name = need(c, T_ID, "expected qualified type name");
    }
    return type_lookup(c, qualifier, name);
  }
  fail(c, 400, "expected u8, u64, bool or buf<u8>");
  return 0;
}
static NtFId type_parse(Compiler *c) {
  enter(c);
  NtFId type = type_parse_inner(c);
  leave(c);
  return type;
}
static NtFId variable_new(Compiler *c, const char *name, NtFId type,
                          NtFSpan span, NtFDirection dir, unsigned mut) {
  if (c->p.variable_count >= (c->safe_v2 ? MAX_LOCALS : MAX_VARS))
    fail_at(c, 201, span, "Nova variable limit");
  NtFId id = (NtFId)++c->p.variable_count;
  VA(c, id) = (NtFVariable){.name = name,
                            .span = span,
                            .type = type,
                            .function = c->function,
                            .module = c->current_module,
                            .direction = dir,
                            .reg = {-1, 64, 0},
                            .scope = c->scope};
  c->vm[id - 1] =
      (VariableMeta){.scope = c->scope, .active = 1, .mutable_value = mut};
  return id;
}
static NtFId lookup_optional(Compiler *c, Token *t) {
  for (size_t i = c->p.variable_count; i > 0; i--)
    if (c->vm[i - 1].active && VA(c, i).function == c->function &&
        !strcmp(VA(c, i).name, t->text))
      return (NtFId)i;
  return 0;
}
static NtFId lookup(Compiler *c, Token *t) {
  NtFId id = lookup_optional(c, t);
  if (!id)
    fail_at(c, 301, t->span, "Nova unknown or out-of-scope variable");
  return id;
}
static void unique_local(Compiler *c, Token *t) {
  for (size_t i = 0; i < c->p.variable_count; i++)
    if (c->vm[i].active && VA(c, i + 1).function == c->function &&
        c->vm[i].scope == c->scope && !strcmp(VA(c, i + 1).name, t->text))
      fail_at(c, 300, t->span, "Nova duplicate local in same scope");
}
static NtFId function_find(Compiler *c, Token *t) {
  for (size_t i = 0; i < c->p.function_count; i++)
    if (!strcmp(c->p.functions[i].name, t->text) &&
        (!c->safe_v2 || c->p.functions[i].module == c->current_module))
      return (NtFId)i + 1;
  fail_at(c, 301, t->span, "Nova unknown function");
  return 0;
}
static NtFId qualified_function(Compiler *c, Token *module, Token *name) {
  NtFId target = 0;
  for (size_t i = 0; i < c->p.module_count; i++)
    if (!strcmp(c->p.modules[i].name, module->text))
      target = (NtFId)i + 1;
  if (!target || !c->imports[c->current_module - 1][target - 1])
    fail_at(c, 302, module->span, "Nova qualified module is not imported");
  for (size_t i = 0; i < c->p.function_count; i++)
    if (c->p.functions[i].module == target &&
        !strcmp(c->p.functions[i].name, name->text)) {
      if (!c->p.functions[i].exported)
        fail_at(c, 302, name->span, "Nova function is private to its module");
      return (NtFId)i + 1;
    }
  fail_at(c, 301, name->span, "Nova imported function does not exist");
  return 0;
}
static void module_headers(Compiler *c) {
  for (size_t start = 0; start + 1 < c->token_count;) {
    unsigned source = c->tokens[start].span.source;
    size_t end = start;
    while (end < c->token_count && c->tokens[end].span.source == source &&
           c->tokens[end].kind)
      end++;
    c->at = start;
    NtFId module = 1;
    if (keyword(c, "module")) {
      Token *name = need(c, T_ID, "expected module name");
      need(c, ';', "expected ; after module name");
      module = 0;
      for (size_t i = 0; i < c->p.module_count; i++)
        if (!strcmp(c->p.modules[i].name, name->text))
          module = (NtFId)i + 1;
      if (!module) {
        if (c->p.module_count >= 65)
          fail_at(c, 201, name->span, "Nova module limit");
        module = (NtFId)++c->p.module_count;
        c->p.modules[module - 1] = (NtFModule){.name = name->text,
                                               .target = "x86_64-uefi",
                                               .default_abi = "efi-x64-v0",
                                               .features = 1,
                                               .span = name->span};
      }
    }
    c->source_module[source] = module;
    while (keyword(c, "import")) {
      Token *name = need(c, T_ID, "expected imported module name");
      need(c, ';', "expected ; after import");
      if (c->import_count[source] >= 64)
        fail_at(c, 201, name->span, "Nova import limit");
      c->import_tokens[source][c->import_count[source]++] = name;
    }
    c->header_end[source] = c->at;
    if (c->at > end)
      fail_at(c, 200, c->tokens[start].span,
              "Nova header crosses a source boundary");
    start = end;
  }
  for (unsigned source = 1; source <= 64; source++)
    for (unsigned j = 0; j < c->import_count[source]; j++) {
      Token *t = c->import_tokens[source][j];
      NtFId target = 0;
      for (size_t i = 0; i < c->p.module_count; i++)
        if (!strcmp(c->p.modules[i].name, t->text))
          target = (NtFId)i + 1;
      if (!target)
        fail_at(c, 302, t->span,
                "Nova imported module is not among compiler inputs");
      c->imports[c->source_module[source] - 1][target - 1] = 1;
    }
  c->at = 0;
}
static void collect_records(Compiler *c) {
  unsigned depth = 0;
  for (size_t i = 0; i + 1 < c->token_count;) {
    if (i < c->header_end[c->tokens[i].span.source]) {
      i = c->header_end[c->tokens[i].span.source];
      continue;
    }
    size_t start = i;
    int exported = 0;
    if (!depth && c->tokens[i].kind == T_ID &&
        !strcmp(c->tokens[i].text, "export")) {
      exported = 1;
      i++;
    }
    if (!depth && c->tokens[i].kind == T_ID &&
        !strcmp(c->tokens[i].text, "struct")) {
      c->at = i + 1;
      c->current_module = c->source_module[c->tokens[i].span.source];
      Token *name = need(c, T_ID, "expected record name");
      for (size_t t = 0; t < c->p.type_count; t++)
        if (c->tm[t].kind == 2 && c->tm[t].module == c->current_module &&
            !strcmp(c->tm[t].name, name->text))
          fail_at(c, 300, name->span, "duplicate record type");
      need(c, '{', "expected record field block");
      size_t begin = c->at;
      unsigned braces = 1;
      while (braces) {
        if (!tok(c)->kind || tok(c)->span.source != name->span.source)
          fail_at(c, 200, name->span, "unterminated record definition");
        if (accept(c, '{'))
          braces++;
        else if (accept(c, '}'))
          braces--;
        else
          c->at++;
      }
      if (c->p.type_count >= MAX_VARS)
        fail_at(c, 201, name->span, "Nova record type limit");
      NtFId type = (NtFId)++c->p.type_count;
      c->p.types[type - 1] = (NtFType){.kind = NTF_T_PTR,
                                       .element = TY_U8,
                                       .bits = 64,
                                       .space = NTF_SPACE_USER};
      c->tm[type - 1] =
          (TypeMeta){.kind = 2,
                     .name = name->text,
                     .module = c->current_module,
                     .exported = exported || c->current_module == 1,
                     .body_start = begin,
                     .body_end = c->at - 1};
      c->skip_declaration[start] = c->at;
      i = c->at;
      continue;
    }
    if (c->tokens[i].kind == '{')
      depth++;
    else if (c->tokens[i].kind == '}' && depth)
      depth--;
    i++;
  }
  size_t declared = c->p.type_count;
  for (size_t type = 0; type < declared; type++)
    if (c->tm[type].kind == 2) {
      TypeMeta *meta = &c->tm[type];
      c->current_module = meta->module;
      c->at = meta->body_start;
      meta->first_field = c->field_count;
      while (c->at < meta->body_end) {
        Token *name = need(c, T_ID, "expected record field name");
        for (unsigned f = 0; f < meta->field_count; f++)
          if (!strcmp(c->fields[meta->first_field + f].name, name->text))
            fail_at(c, 300, name->span, "duplicate record field");
        need(c, ':', "expected record field type");
        NtFId ft = type_parse(c);
        if (ft == TY_RUNTIME)
          fail_at(c, 400, name->span,
                  "runtime descriptors cannot be record fields");
        if (meta->field_count >= 64 || c->field_count >= MAX_VARS)
          fail_at(c, 201, name->span, "record field limit");
        c->fields[c->field_count++] =
            (Field){name->text, ft, name->span, meta->field_count * 8};
        meta->field_count++;
        if (c->at < meta->body_end && !accept(c, ',') && !accept(c, ';'))
          fail(c, 200, "expected separator between record fields");
      }
    }
  c->at = 0;
}
static int integer(NtFId t) {
  return t == TY_U8 || t == TY_U64 || (t >= TY_U16 && t <= TY_I64);
}
static int literal_magnitude(Compiler *c, NtFId id, uint64_t *m,
                             int *negative) {
  NtFExpr *x = &EX(c, id);
  if (x->kind == NTF_X_LITERAL && integer(x->type)) {
    *m = x->value;
    *negative = x->negative;
    return 1;
  }
  if (x->kind == NTF_X_UNARY && (x->op == NTF_OP_NEG || x->op == NTF_OP_POS) &&
      literal_magnitude(c, x->left, m, negative)) {
    if (x->op == NTF_OP_NEG)
      *negative = !*negative;
    return 1;
  }
  return 0;
}
static void retag(Compiler *c, NtFId id, NtFId type) {
  NtFExpr *x = &EX(c, id);
  x->type = type;
  if (x->left)
    retag(c, x->left, type);
  if (x->right)
    retag(c, x->right, type);
}
static int constant_integer(Compiler *c, NtFId id) {
  NtFExpr *x = &EX(c, id);
  if (x->negative == 2)
    return 0;
  if (x->kind == NTF_X_LITERAL)
    return integer(x->type);
  if (x->kind == NTF_X_UNARY)
    return constant_integer(c, x->left);
  return x->kind == NTF_X_BINARY && x->op < NTF_OP_EQ &&
         constant_integer(c, x->left) && constant_integer(c, x->right);
}
static int coerce_integer(Compiler *c, NtFId id, NtFId type, NtFSpan span) {
  uint64_t magnitude;
  int negative;
  if (literal_magnitude(c, id, &magnitude, &negative)) {
    unsigned bits = width_of(c, type) * 8;
    uint64_t limit = is_signed(type)
                         ? (UINT64_C(1) << (bits - 1)) - (negative ? 0 : 1)
                     : bits == 64 ? UINT64_MAX
                                  : (UINT64_C(1) << bits) - 1;
    if ((negative && !is_signed(type)) || magnitude > limit)
      fail_at(c, 401, span, "integer literal is outside its target type");
    retag(c, id, type);
    return 1;
  }
  if (constant_integer(c, id)) {
    NtFExpr *x = &EX(c, id);
    if (x->left && !coerce_integer(c, x->left, type, span))
      return 0;
    if (x->right && !coerce_integer(c, x->right, type, span))
      return 0;
    x->type = type;
    return 1;
  }
  return 0;
}
static void compatible(Compiler *c, NtFId value, NtFId type, NtFSpan s) {
  NtFExpr *x = &EX(c, value);
  if (c->safe_v2 && is_buffer(c, type) && (int)x->kind == X_ALLOC) {
    x->type = type;
    return;
  }
  if (c->safe_v2 && is_record(c, type) && x->kind == NTF_X_LITERAL &&
      !x->type && !x->value) {
    x->type = type;
    return;
  }
  if (x->type == type)
    return;
  if (c->safe_v2 && integer(x->type) && integer(type)) {
    if (coerce_integer(c, value, type, s))
      return;
    if (is_signed(x->type) == is_signed(type) &&
        width_of(c, x->type) <= width_of(c, type))
      return;
  }
  if (x->type == TY_U8 && type == TY_U64)
    return;
  if (x->kind == NTF_X_LITERAL && type == TY_U8 && x->value <= 255) {
    x->type = TY_U8;
    return;
  }
  fail_at(
      c, 400, s,
      "Nova type mismatch (no implicit narrowing or bool/integer conversion)");
}
static void signatures(Compiler *c) {
  while (tok(c)->kind) {
    if (c->safe_v2 && c->skip_declaration[c->at]) {
      c->at = c->skip_declaration[c->at];
      continue;
    }
    if (c->safe_v2 && c->at < c->header_end[tok(c)->span.source]) {
      c->at = c->header_end[tok(c)->span.source];
      continue;
    }
    c->current_module = c->safe_v2 ? c->source_module[tok(c)->span.source] : 1;
    size_t declaration_start = c->at;
    int exported = c->safe_v2 ? keyword(c, "export") : 0;
    if (!keyword(c, "fn"))
      fail(c, 200, "expected fn declaration");
    Token *n = need(c, T_ID, "expected function name");
    for (size_t i = 0; i < c->p.function_count; i++)
      if (!strcmp(c->p.functions[i].name, n->text) &&
          c->p.functions[i].module == c->current_module)
        fail_at(c, 300, n->span, "Nova duplicate function");
    if (c->p.function_count >= (c->safe_v2 ? MAX_FUNCS : 256))
      fail(c, 201, "Nova function limit");
    c->function = (NtFId)++c->p.function_count;
    c->scope = 0;
    NtFFunction *f = &FN(c, c->function);
    *f = (NtFFunction){.name = n->text,
                       .high_level_expressions = c->safe_v2,
                       .module = c->current_module,
                       .abi = c->safe_v2 ? "efi-x64-v0" : "nx64-abi-v0",
                       .section = ".text",
                       .span = n->span,
                       .clobbers = (UINT64_C(1) << 17) | 1,
                       .exported = exported || c->current_module == 1 ||
                                   !strcmp(n->text, "main")};
    FunctionMeta *fm = &c->fm[c->function - 1];
    need(c, '(', "expected (");
    while (!accept(c, ')')) {
      Token *p = need(c, T_ID, "expected parameter name");
      unique_local(c, p);
      need(c, ':', "expected parameter type");
      NtFId type = type_parse(c);
      unsigned slots = is_buffer(c, type) ? 2 : 1;
      if (f->param_count + slots > (c->safe_v2 ? 64u : 4u))
        fail_at(
            c, 403, p->span,
            "Nova parameter list exceeds its ABI slot limit (buffer uses two)");
      NtFId v = variable_new(c, p->text, type, p->span, NTF_IN, 0);
      if (!f->first_param)
        f->first_param = v;
      fm->params[fm->count++] = v;
      f->param_count += slots;
      if (is_buffer(c, type))
        c->vm[v - 1].length =
            variable_new(c, "$length", TY_U64, p->span, NTF_IN, 0);
      if (accept(c, ')'))
        break;
      need(c, ',', "expected , or )");
    }
    need(c, T_ARROW, "expected -> return type");
    f->return_type = type_parse(c);
    if (f->return_type == TY_BUF && !c->safe_v2)
      fail(c, 400, "buffer returns require a later ABI");
    need(c, '{', "expected function body");
    fm->start = c->at - 1;
    unsigned braces = 1;
    while (braces) {
      if (!tok(c)->kind)
        fail(c, 200, "unterminated function body");
      if (accept(c, '{'))
        braces++;
      else if (accept(c, '}'))
        braces--;
      else
        c->at++;
      if (braces > 128)
        fail(c, 201, "Nova block nesting exceeds 128");
    }
    fm->end = c->at;
    for (size_t at = declaration_start; at < fm->end; at++)
      if (c->tokens[at].span.source != c->tokens[declaration_start].span.source)
        fail_at(c, 200, c->tokens[at].span,
                "Nova declaration crosses a source-file boundary");
  }
}
static NtFId parse_expression(Compiler *c, int minimum);
static void append_arg(Compiler *c, NtFId *first, NtFId *tail, NtFId value) {
  if (*tail)
    EX(c, *tail).next = value;
  else
    *first = value;
  *tail = value;
}
static NtFId atom(Compiler *c) {
  Token *t = tok(c);
  if (accept(c, T_STRING))
    return expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_BYTES,
                                       .type = TY_BUF,
                                       .name = t->bytes,
                                       .string_length = t->byte_count,
                                       .span = t->span});
  if (c->safe_v2 && accept(c, '[')) {
    size_t maximum = 0;
    for (size_t i = c->at; i < c->token_count && c->tokens[i].kind != ']';
         i++) {
      if (c->tokens[i].kind != T_NUM && c->tokens[i].kind != ',')
        fail_at(c, 400, c->tokens[i].span,
                "byte array literals require literal u8 elements");
      maximum++;
    }
    char *bytes = owned(c, maximum);
    size_t n = 0;
    while (!accept(c, ']')) {
      Token *v = need(c, T_NUM, "expected byte array literal element");
      if (v->value > 255)
        fail_at(c, 401, v->span, "byte array element exceeds u8");
      bytes[n++] = (char)v->value;
      if (accept(c, ']'))
        break;
      need(c, ',', "expected , between array elements");
    }
    return expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_BYTES,
                                       .type = TY_BUF,
                                       .name = bytes,
                                       .string_length = n,
                                       .negative = 1,
                                       .span = t->span});
  }
  if (accept(c, T_NUM))
    return literal(c, t->value, TY_U64, t->span);
  if (keyword(c, "true"))
    return literal(c, 1, TY_BOOL, t->span);
  if (keyword(c, "false"))
    return literal(c, 0, TY_BOOL, t->span);
  if (c->safe_v2 && keyword(c, "null"))
    return literal(c, 0, 0, t->span);
  if (accept(c, '(')) {
    NtFId x = parse_expression(c, 0);
    need(c, ')', "expected )");
    return x;
  }
  if (accept(c, '!')) {
    NtFId x = parse_expression(c, 11);
    if (EX(c, x).type != TY_BOOL)
      fail_at(c, 400, t->span, "! requires bool");
    return binary(c, NTF_OP_EQ, x, literal(c, 0, TY_BOOL, t->span), TY_BOOL,
                  t->span);
  }
  if (accept(c, '~')) {
    NtFId x = parse_expression(c, 11);
    if (!integer(EX(c, x).type))
      fail_at(c, 400, t->span, "~ requires integer");
    return expression_new(c, (NtFExpr){.kind = NTF_X_UNARY,
                                       .type = EX(c, x).type,
                                       .op = NTF_OP_NOT,
                                       .left = x,
                                       .span = t->span});
  }
  if (accept(c, '-')) {
    NtFId x = parse_expression(c, 11);
    if (!integer(EX(c, x).type))
      fail_at(c, 400, t->span, "- requires integer");
    return expression_new(c, (NtFExpr){.kind = NTF_X_UNARY,
                                       .type = EX(c, x).type,
                                       .op = NTF_OP_NEG,
                                       .left = x,
                                       .span = t->span});
  }
  if (!accept(c, T_ID))
    fail(c, 200, "expected Nova expression");
  Token *qualifier = NULL;
  if (c->safe_v2 && !lookup_optional(c, t) && tok(c)->kind == '.' &&
      c->tokens[c->at + 1].kind == T_ID &&
      (c->tokens[c->at + 2].kind == '(' || c->tokens[c->at + 2].kind == '{')) {
    qualifier = t;
    c->at++;
    t = need(c, T_ID, "expected qualified function name");
  }
  if (c->safe_v2 && !lookup_optional(c, t) && tok(c)->kind == '{') {
    NtFId type = type_lookup(c, qualifier, t);
    TypeMeta *meta = &c->tm[type - 1];
    need(c, '{', "expected record initializer");
    unsigned char seen[64] = {0};
    unsigned count = 0;
    NtFId first = 0, tail = 0;
    while (!accept(c, '}')) {
      Token *field = need(c, T_ID, "expected record field");
      unsigned at = meta->field_count;
      for (unsigned i = 0; i < meta->field_count; i++)
        if (!strcmp(c->fields[meta->first_field + i].name, field->text))
          at = i;
      if (at == meta->field_count)
        fail_at(c, 301, field->span, "record has no such field");
      if (seen[at])
        fail_at(c, 300, field->span, "duplicate record initializer field");
      seen[at] = 1;
      count++;
      need(c, ':', "expected : after record field");
      NtFId value = parse_expression(c, 0);
      Field *f = &c->fields[meta->first_field + at];
      compatible(c, value, f->type, field->span);
      NtFId init =
          expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_FIELD_INIT,
                                      .type = f->type,
                                      .left = value,
                                      .value = f->offset,
                                      .span = field->span});
      append_arg(c, &first, &tail, init);
      if (accept(c, '}'))
        break;
      need(c, ',', "expected , between record fields");
    }
    if (count != meta->field_count)
      fail_at(c, 400, t->span, "record initializer must supply every field");
    return expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_RECORD,
                                       .type = type,
                                       .first_arg = first,
                                       .span = t->span});
  }
  if (accept(c, '(')) {
    if (qualifier)
      goto named_call;
    if (c->safe_v2 && !strcmp(t->text, "runtime")) {
      need(c, ')', "runtime() takes no arguments");
      return expression_new(c, (NtFExpr){.kind = NTF_X_REGISTER,
                                         .type = TY_RUNTIME,
                                         .reg = {15, 64, 0},
                                         .span = t->span});
    }
    if (!strcmp(t->text, "alloc")) {
      NtFId rt = parse_expression(c, 0);
      compatible(c, rt, TY_RUNTIME, t->span);
      need(c, ',', "alloc requires runtime and size");
      NtFId size = parse_expression(c, 0);
      compatible(c, size, TY_U64, t->span);
      need(c, ')', "expected ) after alloc");
      return expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_ALLOC,
                                         .type = TY_BUF,
                                         .left = rt,
                                         .right = size,
                                         .span = t->span});
    }
    if (!strcmp(t->text, "slice")) {
      NtFId b = parse_expression(c, 0);
      if (!is_buffer(c, EX(c, b).type))
        fail_at(c, 400, t->span, "slice expects a buffer");
      if (EX(c, b).kind != NTF_X_NAME && (int)EX(c, b).kind != X_FIELD)
        fail_at(c, 400, t->span, "slice source must name a buffer");
      need(c, ',', "slice requires buffer,start,length");
      NtFId start = parse_expression(c, 0);
      compatible(c, start, TY_U64, t->span);
      need(c, ',', "slice requires length");
      NtFId size = parse_expression(c, 0);
      compatible(c, size, TY_U64, t->span);
      need(c, ')', "expected ) after slice");
      return expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_SLICE,
                                         .type = EX(c, b).type,
                                         .left = b,
                                         .right = start,
                                         .first_arg = size,
                                         .resolved = EX(c, b).resolved,
                                         .span = t->span});
    }
    if (!strcmp(t->text, "rt_copy")) {
      NtFId first = 0, tail = 0;
      for (unsigned arg = 0; arg < 4; arg++) {
        if (arg)
          need(c, ',',
               "rt_copy requires runtime,destination,source,byte count");
        NtFId value = parse_expression(c, 0);
        compatible(c, value,
                   arg == 0   ? TY_RUNTIME
                   : arg == 3 ? TY_U64
                              : TY_BUF,
                   t->span);
        append_arg(c, &first, &tail, value);
      }
      need(c, ')', "expected ) after rt_copy");
      return expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_RUNTIME,
                                         .type = TY_U64,
                                         .value = NV2_COPY,
                                         .first_arg = first,
                                         .span = t->span});
    }
    static const char *runtime_names[] = {
        "rt_free",  "rt_open_read", "rt_open_new", "rt_read",
        "rt_write", "rt_close",     "rt_diag"};
    static const char *runtime_types[] = {"RB",  "RB", "RB", "RUB",
                                          "RUB", "RU", "RB"};
    for (unsigned operation = 0; operation < 7; operation++)
      if (!strcmp(t->text, runtime_names[operation])) {
        NtFId first = 0, tail = 0;
        const char *types = runtime_types[operation];
        for (unsigned i = 0; types[i]; i++) {
          if (i)
            need(c, ',', "expected runtime argument separator");
          NtFId value = parse_expression(c, 0);
          if (types[i] == 'B') {
            if (!is_buffer(c, EX(c, value).type) &&
                !(operation == 0 && is_record(c, EX(c, value).type)))
              fail_at(
                  c, 400, t->span,
                  "runtime argument requires a buffer or releasable record");
          } else
            compatible(c, value, types[i] == 'R' ? TY_RUNTIME : TY_U64,
                       t->span);
          append_arg(c, &first, &tail, value);
          if (types[i] == 'B') {
            if (EX(c, value).kind != NTF_X_NAME)
              fail_at(c, 400, t->span,
                      "runtime buffer argument must name a buffer");
            NtFId n =
                is_record(c, EX(c, value).type)
                    ? literal(c, c->tm[EX(c, value).type - 1].field_count * 8,
                              TY_U64, t->span)
                    : name_expr(c, c->vm[EX(c, value).resolved - 1].length,
                                t->span);
            if (is_buffer(c, EX(c, value).type) &&
                buffer_width(c, EX(c, value).type) > 1)
              n = binary(c, NTF_OP_MUL, n,
                         literal(c, buffer_width(c, EX(c, value).type), TY_U64,
                                 t->span),
                         TY_U64, t->span);
            append_arg(c, &first, &tail, n);
          }
        }
        need(c, ')', "runtime argument count mismatch");
        return expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_RUNTIME,
                                           .type = TY_U64,
                                           .value = operation + 1,
                                           .first_arg = first,
                                           .span = t->span});
      }
    NtFId cast_type = builtin_integer(t->text);
    if (cast_type &&
        (c->safe_v2 || cast_type == TY_U8 || cast_type == TY_U64)) {
      NtFId x = parse_expression(c, 0);
      if (!integer(EX(c, x).type))
        fail_at(c, 400, t->span, "numeric casts require an unsigned integer");
      need(c, ')', "expected ) after numeric cast");
      unsigned bits = width_of(c, cast_type) * 8;
      NtFId cast =
          binary(c, NTF_OP_AND, x,
                 literal(c, bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1,
                         TY_U64, t->span),
                 cast_type, t->span);
      EX(c, cast).negative = 2;
      return cast;
    }
    if (!strcmp(t->text, "len")) {
      if (c->safe_v2) {
        NtFId buffer = parse_expression(c, 0);
        if (!is_buffer(c, EX(c, buffer).type))
          fail_at(c, 400, t->span, "len expects a buffer");
        need(c, ')', "expected ) after len");
        return expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_LEN,
                                           .left = buffer,
                                           .type = TY_U64,
                                           .span = t->span});
      }
      Token *n = need(c, T_ID, "len expects a buffer variable");
      NtFId v = lookup(c, n);
      if (VA(c, v).type != TY_BUF)
        fail_at(c, 400, n->span, "len expects buf<u8>");
      need(c, ')', "expected ) after len");
      if (c->safe_v2) {
        NtFId rt = expression_new(c, (NtFExpr){.kind = NTF_X_REGISTER,
                                               .type = TY_RUNTIME,
                                               .reg = {15, 64, 0},
                                               .span = t->span});
        NtFId buffer = name_expr(c, v, t->span);
        EX(c, rt).next = buffer;
        return expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_RUNTIME,
                                           .type = TY_U64,
                                           .value = NV2_LENGTH,
                                           .first_arg = rt,
                                           .span = t->span});
      }
      return name_expr(c, c->vm[v - 1].length, t->span);
    }
  named_call:;
    NtFId fn =
        qualifier ? qualified_function(c, qualifier, t) : function_find(c, t);
    FunctionMeta *fm = &c->fm[fn - 1];
    NtFId first = 0, tail = 0;
    unsigned pos = 0;
    while (!accept(c, ')')) {
      if (pos >= fm->count)
        fail(c, 403, "Nova call has too many arguments");
      NtFId parameter = fm->params[pos++];
      NtFId x = parse_expression(c, 0);
      compatible(c, x, VA(c, parameter).type, t->span);
      append_arg(c, &first, &tail, x);
      if (is_buffer(c, VA(c, parameter).type)) {
        NtFId length = 0;
        if (EX(c, x).kind == NTF_X_NAME)
          length = name_expr(c, c->vm[EX(c, x).resolved - 1].length, t->span);
        else if (c->safe_v2 && (int)EX(c, x).kind == X_FIELD)
          length = expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_LEN,
                                               .type = TY_U64,
                                               .left = x,
                                               .span = EX(c, x).span});
        else
          fail_at(c, 400, EX(c, x).span, "buffer argument must name a buffer");
        append_arg(c, &first, &tail, length);
      }
      if (accept(c, ')'))
        break;
      need(c, ',', "expected , between arguments");
    }
    if (pos != fm->count)
      fail_at(c, 403, t->span, "Nova call has too few arguments");
    return expression_new(c, (NtFExpr){.kind = NTF_X_CALL,
                                       .type = FN(c, fn).return_type,
                                       .resolved = fn,
                                       .first_arg = first,
                                       .name = t->text,
                                       .span = t->span});
  }
  NtFId var = lookup(c, t);
  return name_expr(c, var, t->span);
}
static NtFId primary(Compiler *c) {
  NtFId x = atom(c);
  while (tok(c)->kind == '[' || (c->safe_v2 && tok(c)->kind == '.')) {
    Token *t = tok(c);
    if (accept(c, '[')) {
      if (!is_buffer(c, EX(c, x).type))
        fail_at(c, 400, t->span, "only bounded buffers can be indexed");
      NtFId index = parse_expression(c, 0);
      if (!integer(EX(c, index).type))
        fail_at(c, 400, t->span, "buffer index must be unsigned integer");
      need(c, ']', "expected ]");
      x = expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_INDEX,
                                      .type = c->tm[EX(c, x).type - 1].element,
                                      .left = x,
                                      .right = index,
                                      .resolved = EX(c, x).resolved,
                                      .span = t->span});
    } else {
      c->at++;
      Token *name = need(c, T_ID, "expected record field name");
      if (!is_record(c, EX(c, x).type))
        fail_at(c, 400, t->span, "field access requires a record");
      TypeMeta *meta = &c->tm[EX(c, x).type - 1];
      unsigned i;
      for (i = 0; i < meta->field_count; i++)
        if (!strcmp(c->fields[meta->first_field + i].name, name->text))
          break;
      if (i == meta->field_count)
        fail_at(c, 301, name->span, "unknown record field");
      Field *f = &c->fields[meta->first_field + i];
      x = expression_new(c, (NtFExpr){.kind = (NtFExprKind)X_FIELD,
                                      .type = f->type,
                                      .left = x,
                                      .value = f->offset,
                                      .span = t->span});
    }
  }
  return x;
}
static int precedence(int t, NtFOp *op) {
  switch (t) {
  case T_OR:
    *op = (NtFOp)OP_OR;
    return 1;
  case T_AND:
    *op = (NtFOp)OP_AND;
    return 2;
  case '|':
    *op = NTF_OP_OR;
    return 3;
  case '^':
    *op = NTF_OP_XOR;
    return 4;
  case '&':
    *op = NTF_OP_AND;
    return 5;
  case T_EQ:
    *op = NTF_OP_EQ;
    return 6;
  case T_NE:
    *op = NTF_OP_NE;
    return 6;
  case '<':
    *op = NTF_OP_LT;
    return 7;
  case '>':
    *op = NTF_OP_GT;
    return 7;
  case T_LE:
    *op = NTF_OP_LE;
    return 7;
  case T_GE:
    *op = NTF_OP_GE;
    return 7;
  case T_SHL:
    *op = NTF_OP_SHL;
    return 8;
  case T_SHR:
    *op = NTF_OP_SHR;
    return 8;
  case '+':
    *op = NTF_OP_ADD;
    return 9;
  case '-':
    *op = NTF_OP_SUB;
    return 9;
  case '*':
    *op = NTF_OP_MUL;
    return 10;
  case '/':
    *op = NTF_OP_DIV;
    return 10;
  case '%':
    *op = NTF_OP_MOD;
    return 10;
  default:
    return 0;
  }
}
static NtFId parse_expression(Compiler *c, int minimum) {
  enter(c);
  NtFId a = primary(c);
  for (;;) {
    NtFOp op = NTF_OP_NONE;
    int prec = precedence(tok(c)->kind, &op);
    if (!prec || prec < minimum)
      break;
    Token *t = tok(c);
    c->at++;
    NtFId b = parse_expression(c, prec + 1);
    NtFId type;
    if (op == (NtFOp)OP_AND || op == (NtFOp)OP_OR) {
      if (EX(c, a).type != TY_BOOL || EX(c, b).type != TY_BOOL)
        fail_at(c, 400, t->span, "logical operators require bool operands");
      type = TY_BOOL;
    } else if ((op == NTF_OP_EQ || op == NTF_OP_NE) &&
               EX(c, a).type == TY_BOOL && EX(c, b).type == TY_BOOL)
      type = TY_BOOL;
    else if (c->safe_v2 && (op == NTF_OP_EQ || op == NTF_OP_NE) &&
             (is_record(c, EX(c, a).type) || is_record(c, EX(c, b).type))) {
      if (!EX(c, a).type)
        compatible(c, a, EX(c, b).type, t->span);
      if (!EX(c, b).type)
        compatible(c, b, EX(c, a).type, t->span);
      if (EX(c, a).type != EX(c, b).type)
        fail_at(c, 400, t->span,
                "reference equality requires matching record types");
      type = TY_BOOL;
    } else {
      if (!integer(EX(c, a).type) || !integer(EX(c, b).type))
        fail_at(c, 400, t->span, "operator requires integer operands");
      if (c->safe_v2) {
        if (op == NTF_OP_SHL || op == NTF_OP_SHR) {
          if (is_signed(EX(c, b).type))
            fail_at(c, 400, t->span, "shift amount must be unsigned");
          type = EX(c, a).type;
        } else {
          if (is_signed(EX(c, a).type) != is_signed(EX(c, b).type)) {
            if (is_signed(EX(c, a).type)) {
              if (!coerce_integer(c, b, EX(c, a).type, t->span))
                fail_at(c, 400, t->span,
                        "mixed signed and unsigned operands require an "
                        "explicit cast");
            } else if (!coerce_integer(c, a, EX(c, b).type, t->span))
              fail_at(c, 400, t->span,
                      "mixed signed and unsigned operands require an explicit "
                      "cast");
          }
          type = op >= NTF_OP_EQ && op <= NTF_OP_GE ? TY_BOOL
                 : width_of(c, EX(c, a).type) >= width_of(c, EX(c, b).type)
                     ? EX(c, a).type
                     : EX(c, b).type;
        }
      } else
        type =
            op >= NTF_OP_EQ && op <= NTF_OP_GE
                ? TY_BOOL
                : (EX(c, a).type == TY_U64 || EX(c, b).type == TY_U64 ? TY_U64
                                                                      : TY_U8);
    }
    a = binary(c, op, a, b, type, t->span);
  }
  leave(c);
  return a;
}
static void chain(Compiler *c, NtFId *first, NtFId *tail, NtFId s) {
  if (*tail)
    ST(c, *tail).next = s;
  else
    *first = s;
  *tail = s;
}
static NtFId parse_block(Compiler *c);
static int definitely_returns(Compiler *c, NtFId block) {
  for (NtFId s = ST(c, block).first; s; s = ST(c, s).next) {
    NtFStmt *t = &ST(c, s);
    if (t->kind == NTF_S_RETURN)
      return 1;
    if (t->kind == NTF_S_BLOCK && definitely_returns(c, s))
      return 1;
    if (t->kind == NTF_S_IF && t->else_branch &&
        definitely_returns(c, t->then_branch) &&
        definitely_returns(c, t->else_branch))
      return 1;
  }
  return 0;
}
static NtFId parse_statement(Compiler *c) {
  Token *t = tok(c);
  if (c->safe_v2 && (word(c, "break") || word(c, "continue"))) {
    int is_break = keyword(c, "break");
    if (!is_break)
      keyword(c, "continue");
    if (!c->loop_depth)
      fail_at(c, 500, t->span, "break/continue requires an enclosing loop");
    need(c, ';', "expected ; after loop control");
    return statement_new(
        c, (NtFStmt){.kind = NTF_S_INSTRUCTION,
                     .name = "jmp",
                     .variable = is_break ? c->loop_end[c->loop_depth - 1]
                                          : c->loop_start[c->loop_depth - 1],
                     .span = t->span});
  }
  if (tok(c)->kind == '{')
    return parse_block(c);
  if (keyword(c, "let")) {
    unsigned mut = (unsigned)keyword(c, "mut");
    Token *n = need(c, T_ID, "expected local name");
    unique_local(c, n);
    need(c, ':', "typed locals require :type");
    NtFId type = type_parse(c);
    need(c, '=', "local requires initializer");
    NtFId value = parse_expression(c, 0);
    compatible(c, value, type, n->span);
    need(c, ';', "expected ; after local");
    NtFId var = variable_new(c, n->text, type, n->span, NTF_LOCAL, mut);
    if (is_buffer(c, type))
      c->vm[var - 1].length =
          variable_new(c, "$length", TY_U64, n->span, NTF_LOCAL, mut);
    VA(c, var).initializer = value;
    return statement_new(c, (NtFStmt){.kind = NTF_S_LET,
                                      .span = t->span,
                                      .variable = var,
                                      .expression = value});
  }
  if (keyword(c, "return")) {
    NtFId x = parse_expression(c, 0);
    compatible(c, x, FN(c, c->function).return_type, t->span);
    need(c, ';', "expected ; after return");
    return statement_new(
        c, (NtFStmt){.kind = NTF_S_RETURN, .expression = x, .span = t->span});
  }
  if (keyword(c, "if")) {
    NtFId cond = parse_expression(c, 0);
    if (EX(c, cond).type != TY_BOOL)
      fail_at(c, 400, t->span, "if condition must be bool");
    NtFId yes = parse_block(c), no = 0;
    if (keyword(c, "else")) {
      if (word(c, "if")) {
        NtFId nested = parse_statement(c);
        no = statement_new(
            c,
            (NtFStmt){.kind = NTF_S_BLOCK, .first = nested, .span = t->span});
      } else
        no = parse_block(c);
    }
    return statement_new(c, (NtFStmt){.kind = NTF_S_IF,
                                      .condition = cond,
                                      .then_branch = yes,
                                      .else_branch = no,
                                      .span = t->span});
  }
  if (keyword(c, "while")) {
    NtFId label = statement_new(
        c, (NtFStmt){.kind = NTF_S_LABEL, .name = "$while", .span = t->span});
    NtFId cond = parse_expression(c, 0);
    if (EX(c, cond).type != TY_BOOL)
      fail_at(c, 400, t->span, "while condition must be bool");
    NtFId exit_label = statement_new(
        c,
        (NtFStmt){.kind = NTF_S_LABEL, .name = "$while_end", .span = t->span});
    if (c->loop_depth == 128)
      fail_at(c, 201, t->span, "loop nesting limit");
    c->loop_start[c->loop_depth] = label;
    c->loop_end[c->loop_depth++] = exit_label;
    NtFId body = parse_block(c);
    c->loop_depth--;
    NtFId jump = statement_new(c, (NtFStmt){.kind = NTF_S_INSTRUCTION,
                                            .name = "jmp",
                                            .variable = label,
                                            .span = t->span});
    NtFId last = ST(c, body).first;
    if (!last)
      ST(c, body).first = jump;
    else {
      while (ST(c, last).next)
        last = ST(c, last).next;
      ST(c, last).next = jump;
    }
    NtFId branch = statement_new(c, (NtFStmt){.kind = NTF_S_IF,
                                              .condition = cond,
                                              .then_branch = body,
                                              .span = t->span});
    ST(c, label).next = branch;
    ST(c, branch).next = exit_label;
    return statement_new(
        c, (NtFStmt){.kind = NTF_S_BLOCK, .first = label, .span = t->span});
  }
  if (tok(c)->kind == T_ID && c->tokens[c->at + 1].kind == '=') {
    c->at++;
    NtFId v = lookup(c, t);
    if (!c->vm[v - 1].mutable_value)
      fail_at(c, 400, t->span, "assignment requires let mut");
    need(c, '=', "expected =");
    NtFId x = parse_expression(c, 0);
    compatible(c, x, VA(c, v).type, t->span);
    need(c, ';', "expected ; after assignment");
    return statement_new(c, (NtFStmt){.kind = NTF_S_LET,
                                      .variable = v,
                                      .expression = x,
                                      .span = t->span});
  }
  NtFId x = parse_expression(c, 0);
  if (accept(c, '=')) {
    if ((int)EX(c, x).kind != X_INDEX && (int)EX(c, x).kind != X_FIELD)
      fail_at(c, 400, t->span,
              "assignment target is not a local or buffer element");
    NtFId value = parse_expression(c, 0);
    compatible(c, value, EX(c, x).type, t->span);
    need(c, ';', "expected ; after buffer write");
    return statement_new(c, (NtFStmt){.kind = (NtFStmtKind)X_INDEX,
                                      .condition = x,
                                      .expression = value,
                                      .span = t->span});
  }
  if (EX(c, x).kind != NTF_X_CALL && (int)EX(c, x).kind != X_RUNTIME)
    fail_at(c, 200, t->span,
            "only function calls can be expression statements");
  need(c, ';', "expected ; after call");
  return statement_new(
      c, (NtFStmt){.kind = NTF_S_CALL, .expression = x, .span = t->span});
}
static NtFId parse_block(Compiler *c) {
  enter(c);
  Token *t = need(c, '{', "expected {");
  c->scope++;
  NtFId first = 0, tail = 0;
  while (!accept(c, '}')) {
    if (!tok(c)->kind)
      fail(c, 200, "unterminated block");
    chain(c, &first, &tail, parse_statement(c));
  }
  for (size_t i = 0; i < c->p.variable_count; i++)
    if (VA(c, i + 1).function == c->function && c->vm[i].scope == c->scope)
      c->vm[i].active = 0;
  c->scope--;
  leave(c);
  return statement_new(
      c, (NtFStmt){.kind = NTF_S_BLOCK, .first = first, .span = t->span});
}
/* Lower checked Nova-only constructs into existing public typed IR. Hidden
 * locals preserve evaluation order and values across arbitrary nested calls.
 * No backend source is forked and no code is interpreted at run time. */
typedef struct {
  NtFId first, tail;
} Sequence;
static void emit(Compiler *c, Sequence *q, NtFStmt s) {
  chain(c, &q->first, &q->tail, statement_new(c, s));
}
static NtFId temporary(Compiler *c, NtFId value, Sequence *q) {
  NtFSpan span = EX(c, value).span;
  NtFId var =
      variable_new(c, "$temporary", EX(c, value).type, span, NTF_LOCAL, 1);
  emit(c, q,
       (NtFStmt){.kind = NTF_S_LET,
                 .variable = var,
                 .expression = value,
                 .span = span});
  return name_expr(c, var, span);
}
static NtFId reg_expr(Compiler *c, int family, unsigned bits, NtFId type,
                      NtFSpan span) {
  return expression_new(c, (NtFExpr){.kind = NTF_X_REGISTER,
                                     .reg = {family, bits, 0},
                                     .type = type,
                                     .span = span});
}
static void machine2(Compiler *c, Sequence *q, const char *name, NtFId a,
                     NtFId b, NtFSpan span) {
  EX(c, a).next = b;
  emit(c, q,
       (NtFStmt){.kind = NTF_S_INSTRUCTION,
                 .name = name,
                 .expression = a,
                 .span = span});
}
static NtFId sequence_block(Compiler *c, Sequence q, NtFSpan span) {
  return statement_new(
      c, (NtFStmt){.kind = NTF_S_BLOCK, .first = q.first, .span = span});
}
static NtFId context_memory(Compiler *c, unsigned offset, NtFSpan span) {
  return expression_new(c, (NtFExpr){.kind = NTF_X_MEMORY,
                                     .type = TY_RUNTIME,
                                     .memory = {.base = {15, 64, 0},
                                                .index = {-1, 64, 0},
                                                .scale = 1,
                                                .displacement = offset},
                                     .span = span});
}
static void store_context(Compiler *c, Sequence *q, unsigned offset,
                          uint64_t value, NtFSpan span) {
  machine2(c, q, "store", context_memory(c, offset, span),
           literal(c, value, TY_U64, span), span);
}
static void guard(Compiler *c, Sequence *q, NtFId condition, uint64_t code,
                  NtFSpan span) {
  if (c->safe_v2) {
    Sequence bad = {0};
    uint64_t error = code > UINT32_MAX ? ((code >> 32) & 255) : code;
    store_context(c, &bad, 16, error, span);
    store_context(c, &bad, 24, span.source, span);
    store_context(c, &bad, 32, span.start, span);
    emit(c, &bad,
         (NtFStmt){.kind = NTF_S_RETURN,
                   .expression =
                       literal(c, 0, FN(c, c->function).return_type, span),
                   .span = span});
    emit(c, q,
         (NtFStmt){.kind = NTF_S_IF,
                   .condition = condition,
                   .then_branch = sequence_block(c, bad, span),
                   .span = span});
    return;
  }
  NtFId r =
      statement_new(c, (NtFStmt){.kind = NTF_S_RETURN,
                                 .expression = literal(c, code, TY_U64, span),
                                 .span = span});
  NtFId b = statement_new(
      c, (NtFStmt){.kind = NTF_S_BLOCK, .first = r, .span = span});
  emit(c, q,
       (NtFStmt){.kind = NTF_S_IF,
                 .condition = condition,
                 .then_branch = b,
                 .span = span});
}
static NtFId lower_expr(Compiler *c, NtFId id, Sequence *q);
static NtFId member(Compiler *c, NtFId object, unsigned offset, Sequence *q,
                    NtFSpan span) {
  emit(c, q, (NtFStmt){.kind = NTF_S_CALL, .expression = object, .span = span});
  NtFId mem = expression_new(c, (NtFExpr){.kind = NTF_X_MEMORY,
                                          .type = TY_RUNTIME,
                                          .memory = {.base = {0, 64, 0},
                                                     .index = {-1, 64, 0},
                                                     .scale = 1,
                                                     .displacement = offset},
                                          .span = span});
  machine2(c, q, "load", reg_expr(c, 0, 64, TY_U64, span), mem, span);
  return temporary(c, reg_expr(c, 0, 64, TY_U64, span), q);
}
static void propagate_error(Compiler *c, Sequence *q, NtFSpan span) {
  NtFId status = member(c, reg_expr(c, 15, 64, TY_RUNTIME, span), 16, q, span);
  Sequence bad = {0};
  NtFId source =
      member(c, reg_expr(c, 15, 64, TY_RUNTIME, span), 24, &bad, span);
  Sequence position = {0};
  store_context(c, &position, 24, span.source, span);
  store_context(c, &position, 32, span.start, span);
  emit(
      c, &bad,
      (NtFStmt){.kind = NTF_S_IF,
                .condition = binary(c, NTF_OP_EQ, source,
                                    literal(c, 0, TY_U64, span), TY_BOOL, span),
                .then_branch = sequence_block(c, position, span),
                .span = span});
  emit(c, &bad,
       (NtFStmt){.kind = NTF_S_RETURN,
                 .expression =
                     literal(c, 0, FN(c, c->function).return_type, span),
                 .span = span});
  emit(
      c, q,
      (NtFStmt){.kind = NTF_S_IF,
                .condition = binary(c, NTF_OP_NE, status,
                                    literal(c, 0, TY_U64, span), TY_BOOL, span),
                .then_branch = sequence_block(c, bad, span),
                .span = span});
}
static NtFId call_v2(Compiler *c, unsigned operation, NtFId a, NtFId b, NtFId d,
                     Sequence *q, NtFSpan span) {
  NtFId arguments[3] = {a, b, d};
  for (unsigned i = 0; i < 3; i++)
    arguments[i] = temporary(
        c, arguments[i] ? arguments[i] : literal(c, 0, TY_U64, span), q);
  NtFId rt = member(c, reg_expr(c, 15, 64, TY_RUNTIME, span), 40, q, span);
  guard(c, q,
        binary(c, NTF_OP_EQ, rt, literal(c, 0, TY_U64, span), TY_BOOL, span),
        NV2_RUNTIME, span);
  NtFId version = member(c, rt, 0, q, span), size = member(c, rt, 8, q, span);
  guard(
      c, q,
      binary(c, NTF_OP_NE, version, literal(c, 2, TY_U64, span), TY_BOOL, span),
      NV2_RUNTIME, span);
  guard(c, q,
        binary(c, NTF_OP_LT, size,
               literal(c, operation < 12 ? 120 : 128, TY_U64, span), TY_BOOL,
               span),
        NV2_RUNTIME, span);
  NtFId target =
      member(c, rt, operation == NV2_COPY ? 120 : 16 + operation * 8, q, span);
  guard(
      c, q,
      binary(c, NTF_OP_EQ, target, literal(c, 0, TY_U64, span), TY_BOOL, span),
      NV2_RUNTIME, span);
  machine2(c, q, "mov", reg_expr(c, 1, 64, TY_U64, span),
           reg_expr(c, 15, 64, TY_U64, span), span);
  static const int registers[] = {2, 8, 9};
  for (unsigned i = 0; i < 3; i++) {
    emit(c, q,
         (NtFStmt){
             .kind = NTF_S_CALL, .expression = arguments[i], .span = span});
    machine2(c, q, "mov", reg_expr(c, registers[i], 64, TY_U64, span),
             reg_expr(c, 0, 64, TY_U64, span), span);
  }
  emit(c, q, (NtFStmt){.kind = NTF_S_CALL, .expression = target, .span = span});
  emit(c, q,
       (NtFStmt){.kind = NTF_S_INSTRUCTION,
                 .name = "call",
                 .expression = reg_expr(c, 0, 64, TY_U64, span),
                 .span = span});
  NtFId result = temporary(c, reg_expr(c, 0, 64, TY_U64, span), q);
  propagate_error(c, q, span);
  return result;
}
static NtFId runtime_call(Compiler *c, const NtFExpr *x, Sequence *q) {
  NtFId args[4] = {0};
  unsigned count = 0;
  for (NtFId a = x->first_arg; a;) {
    if (count == 4)
      fail_at(c, 403, x->span, "runtime ABI argument overflow");
    NtFId next = EX(c, a).next;
    args[count++] = temporary(c, lower_expr(c, a, q), q);
    a = next;
  }
  if (!count)
    fail_at(c, 700, x->span, "runtime call lacks descriptor");
  if (c->safe_v2)
    return call_v2(c, (unsigned)x->value, args[1], args[2], args[3], q,
                   x->span);
  NtFSpan span = x->span;
  uint64_t error = UINT64_C(0x8000000600000000);
  guard(c, q,
        binary(c, NTF_OP_EQ, args[0], literal(c, 0, TY_RUNTIME, span), TY_BOOL,
               span),
        error, span);
  NtFId version = member(c, args[0], 0, q, span),
        size = member(c, args[0], 8, q, span);
  guard(
      c, q,
      binary(c, NTF_OP_NE, version, literal(c, 1, TY_U64, span), TY_BOOL, span),
      error, span);
  guard(c, q,
        binary(c, NTF_OP_LT, size, literal(c, 88, TY_U64, span), TY_BOOL, span),
        error, span);
  NtFId callback = member(c, args[0], 24 + (unsigned)x->value * 8, q, span);
  NtFId context = member(c, args[0], 16, q, span);
  guard(c, q,
        binary(c, NTF_OP_EQ, callback, literal(c, 0, TY_U64, span), TY_BOOL,
               span),
        error, span);
  args[0] = context;
  static const int registers[] = {1, 2, 8, 9};
  for (unsigned i = 0; i < 4; i++) {
    emit(c, q,
         (NtFStmt){.kind = NTF_S_CALL,
                   .expression =
                       i < count ? args[i] : literal(c, 0, TY_U64, span),
                   .span = span});
    machine2(c, q, "mov", reg_expr(c, registers[i], 64, TY_U64, span),
             reg_expr(c, 0, 64, TY_U64, span), span);
  }
  emit(c, q,
       (NtFStmt){.kind = NTF_S_CALL, .expression = callback, .span = span});
  NtFId target = reg_expr(c, 0, 64, TY_U64, span);
  emit(c, q,
       (NtFStmt){.kind = NTF_S_INSTRUCTION,
                 .name = "call",
                 .expression = target,
                 .span = span});
  return temporary(c, reg_expr(c, 0, 64, TY_U64, span), q);
}
static NtFId lower_bytes(Compiler *c, const NtFExpr *x, Sequence *q) {
  if (c->literal_bytes + x->string_length > 16 * 1024 * 1024)
    fail_at(c, 201, x->span, "Nova constant byte budget exceeded");
  c->literal_bytes += x->string_length;
  if (c->p.type_count >= MAX_VARS)
    fail_at(c, 201, x->span, "Nova literal type limit");
  NtFId type = (NtFId)++c->p.type_count;
  c->p.types[type - 1] = (NtFType){.kind = NTF_T_ARRAY,
                                   .element = TY_U8,
                                   .count = x->string_length,
                                   .bits = 8};
  char *escaped = owned(c, x->string_length * 4 + 1);
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < x->string_length; i++) {
    unsigned b = (unsigned char)x->name[i];
    escaped[i * 4] = '\\';
    escaped[i * 4 + 1] = 'x';
    escaped[i * 4 + 2] = hex[b >> 4];
    escaped[i * 4 + 3] = hex[b & 15];
  }
  NtFId initializer =
      expression_new(c, (NtFExpr){.kind = NTF_X_STRING,
                                  .type = type,
                                  .name = escaped,
                                  .string_length = x->string_length * 4,
                                  .span = x->span});
  char *name = owned(c, 40);
  snprintf(name, 40, "$nova_literal_%zu", c->p.variable_count);
  NtFId var = variable_new(c, name, type, x->span, NTF_DATA, 0);
  VA(c, var).function = 0;
  VA(c, var).section = ".rdata";
  VA(c, var).initializer = initializer;
  NtFId mem = expression_new(c, (NtFExpr){.kind = NTF_X_MEMORY,
                                          .type = TY_BUF,
                                          .resolved = var,
                                          .memory = {.base = {-1, 64, 0},
                                                     .index = {-1, 64, 0},
                                                     .scale = 1,
                                                     .symbol = name},
                                          .span = x->span});
  machine2(c, q, "lea", reg_expr(c, 0, 64, TY_U64, x->span), mem, x->span);
  NtFId pointer = temporary(c, reg_expr(c, 0, 64, TY_U64, x->span), q);
  NtFId result = call_v2(
      c, NV2_LITERAL, pointer, literal(c, x->string_length, TY_U64, x->span),
      literal(c, (uint64_t)x->negative, TY_U64, x->span), q, x->span);
  EX(c, result).type = TY_BUF;
  VA(c, EX(c, result).resolved).type = TY_BUF;
  return result;
}
static void lower_buffer_local(Compiler *c, const NtFStmt *s, Sequence *q) {
  NtFExpr x = EX(c, s->expression);
  NtFSpan span = s->span;
  NtFId pointer = 0, length = 0;
  if ((int)x.kind == X_ALLOC) {
    length = temporary(c, lower_expr(c, x.right, q), q);
    NtFId rt = temporary(c, lower_expr(c, x.left, q), q);
    unsigned width = buffer_width(c, VA(c, s->variable).type);
    guard(c, q,
          binary(c, NTF_OP_GT, length,
                 literal(c, UINT64_MAX / width, TY_U64, span), TY_BOOL, span),
          NOVA_BOUNDS_ERROR, span);
    NtFId bytes = width == 1
                      ? length
                      : binary(c, NTF_OP_MUL, length,
                               literal(c, width, TY_U64, span), TY_U64, span);
    NtFId argsize = expression_new(c, EX(c, bytes));
    EX(c, rt).next = argsize;
    pointer = runtime_call(c,
                           &(NtFExpr){.kind = (NtFExprKind)X_RUNTIME,
                                      .first_arg = rt,
                                      .span = span},
                           q);
    guard(c, q,
          binary(c, NTF_OP_EQ, pointer, literal(c, 0, TY_U64, span), TY_BOOL,
                 span),
          UINT64_C(0x8000000600000000), span);
  } else if ((int)x.kind == X_SLICE) {
    NtFId start = temporary(c, lower_expr(c, x.right, q), q);
    length = temporary(c, lower_expr(c, x.first_arg, q), q);
    unsigned width = buffer_width(c, x.type);
    NtFId base, parent_length;
    if (c->safe_v2) {
      base = temporary(c, lower_expr(c, x.left, q), q);
      parent_length = call_v2(c, NV2_LENGTH, base, 0, 0, q, span);
      if (width > 1) {
        guard(c, q,
              binary(c, NTF_OP_NE,
                     binary(c, NTF_OP_MOD, parent_length,
                            literal(c, width, TY_U64, span), TY_U64, span),
                     literal(c, 0, TY_U64, span), TY_BOOL, span),
              NV2_ARGUMENT, span);
        parent_length = binary(c, NTF_OP_DIV, parent_length,
                               literal(c, width, TY_U64, span), TY_U64, span);
      }
    } else {
      base = name_expr(c, x.resolved, span);
      parent_length = name_expr(c, c->vm[x.resolved - 1].length, span);
    }
    parent_length = temporary(c, parent_length, q);
    guard(c, q, binary(c, NTF_OP_GT, start, parent_length, TY_BOOL, span),
          NOVA_BOUNDS_ERROR, span);
    NtFId available = binary(c, NTF_OP_SUB, parent_length, start, TY_U64, span);
    guard(c, q, binary(c, NTF_OP_GT, length, available, TY_BOOL, span),
          NOVA_BOUNDS_ERROR, span);
    if (c->safe_v2) {
      NtFId byte_start = start, byte_length = length;
      if (width > 1) {
        byte_start = binary(c, NTF_OP_MUL, start,
                            literal(c, width, TY_U64, span), TY_U64, span);
        byte_length = binary(c, NTF_OP_MUL, length,
                             literal(c, width, TY_U64, span), TY_U64, span);
      }
      pointer = call_v2(c, NV2_SLICE, base, byte_start, byte_length, q, span);
    } else {
      guard(c, q,
            binary(c, NTF_OP_GT, base,
                   binary(c, NTF_OP_SUB, literal(c, UINT64_MAX, TY_U64, span),
                          start, TY_U64, span),
                   TY_BOOL, span),
            NOVA_BOUNDS_ERROR, span);
      pointer = binary(c, NTF_OP_ADD, base, start, TY_BUF, span);
    }
  } else if (c->safe_v2 && (x.kind == NTF_X_CALL || (int)x.kind == X_BYTES ||
                            (int)x.kind == X_FIELD || (int)x.kind == X_INDEX)) {
    pointer = lower_expr(c, s->expression, q);
    length = call_v2(c, NV2_LENGTH, pointer, 0, 0, q, span);
    unsigned width = buffer_width(c, VA(c, s->variable).type);
    if (width > 1) {
      guard(c, q,
            binary(c, NTF_OP_NE,
                   binary(c, NTF_OP_MOD, length,
                          literal(c, width, TY_U64, span), TY_U64, span),
                   literal(c, 0, TY_U64, span), TY_BOOL, span),
            NV2_ARGUMENT, span);
      length = binary(c, NTF_OP_DIV, length, literal(c, width, TY_U64, span),
                      TY_U64, span);
    }
  } else if (x.kind == NTF_X_NAME && is_buffer(c, x.type)) {
    pointer = s->expression;
    length = name_expr(c, c->vm[x.resolved - 1].length, span);
  } else
    fail_at(c, 400, span,
            "buffer initializer must be alloc, slice or named buffer");
  emit(c, q,
       (NtFStmt){.kind = NTF_S_LET,
                 .variable = s->variable,
                 .expression = pointer,
                 .span = span});
  emit(c, q,
       (NtFStmt){.kind = NTF_S_LET,
                 .variable = c->vm[s->variable - 1].length,
                 .expression = length,
                 .span = span});
}
static NtFId memory_pointer_type(Compiler *c, unsigned width, NtFSpan span) {
  if (width == 1)
    return TY_BUF;
  if (width == 8)
    return TY_RUNTIME;
  NtFId element = width == 2 ? TY_U16 : TY_U32;
  for (size_t i = 0; i < c->p.type_count; i++)
    if (c->tm[i].kind == 1 && c->tm[i].element == element)
      return (NtFId)i + 1;
  if (c->p.type_count >= MAX_VARS)
    fail_at(c, 201, span, "Nova memory type limit");
  NtFId type = (NtFId)++c->p.type_count;
  c->p.types[type - 1] = (NtFType){.kind = NTF_T_PTR,
                                   .element = element,
                                   .bits = 64,
                                   .space = NTF_SPACE_USER};
  c->tm[type - 1] = (TypeMeta){.kind = 1, .element = element};
  return type;
}
static NtFId safe_address(Compiler *c, const NtFExpr *x, Sequence *q,
                          int writable, NtFId *checked_offset,
                          NtFId *checked_handle) {
  NtFSpan span = x->span;
  NtFId h = temporary(c, lower_expr(c, x->left, q), q);
  NtFId offset;
  unsigned width =
      writable && (int)x->kind == X_FIELD ? 8 : width_of(c, x->type);
  if ((int)x->kind == X_FIELD)
    offset = literal(c, x->value, TY_U64, span);
  else {
    NtFId index = temporary(c, lower_expr(c, x->right, q), q);
    guard(c, q,
          binary(c, NTF_OP_GT, index,
                 literal(c, UINT64_MAX / width, TY_U64, span), TY_BOOL, span),
          NV2_BOUNDS, span);
    offset = width == 1 ? index
                        : binary(c, NTF_OP_MUL, index,
                                 literal(c, width, TY_U64, span), TY_U64, span);
  }
  offset = temporary(c, offset, q);
  if (checked_offset)
    *checked_offset = offset;
  if (checked_handle)
    *checked_handle = h;
  NtFId pointer = call_v2(
      c, NV2_RESOLVE, h, offset,
      literal(c, width | (writable ? (UINT64_C(1) << 63) : 0), TY_U64, span), q,
      span);
  emit(c, q,
       (NtFStmt){.kind = NTF_S_CALL, .expression = pointer, .span = span});
  machine2(c, q, "mov", reg_expr(c, 11, 64, TY_U64, span),
           reg_expr(c, 0, 64, TY_U64, span), span);
  return expression_new(
      c, (NtFExpr){
             .kind = NTF_X_MEMORY,
             .type = memory_pointer_type(c, width, span),
             .memory = {.base = {11, 64, 0}, .index = {-1, 64, 0}, .scale = 1},
             .span = span});
}
static NtFId lower_record(Compiler *c, const NtFExpr *x, Sequence *q) {
  NtFSpan span = x->span;
  NtFId h =
      call_v2(c, NV2_ALLOC,
              literal(c, c->tm[x->type - 1].field_count * 8, TY_U64, span), 0,
              0, q, span);
  EX(c, h).type = x->type;
  VA(c, EX(c, h).resolved).type = x->type;
  for (NtFId arg = x->first_arg; arg; arg = EX(c, arg).next) {
    NtFExpr init = EX(c, arg);
    NtFId value = temporary(c, lower_expr(c, init.left, q), q);
    NtFId pointer = call_v2(
        c, NV2_RESOLVE, h, literal(c, init.value, TY_U64, init.span),
        literal(c, (UINT64_C(1) << 63) | 8, TY_U64, init.span), q, init.span);
    emit(c, q,
         (NtFStmt){.kind = NTF_S_CALL, .expression = pointer, .span = span});
    machine2(c, q, "mov", reg_expr(c, 11, 64, TY_U64, span),
             reg_expr(c, 0, 64, TY_U64, span), span);
    emit(c, q,
         (NtFStmt){.kind = NTF_S_CALL, .expression = value, .span = span});
    NtFId mem = expression_new(c, (NtFExpr){.kind = NTF_X_MEMORY,
                                            .type = TY_RUNTIME,
                                            .memory = {.base = {11, 64, 0},
                                                       .index = {-1, 64, 0},
                                                       .scale = 1},
                                            .span = span});
    machine2(c, q, "store", mem, reg_expr(c, 0, 64, TY_U64, span), span);
  }
  return h;
}
static NtFId buffer_address(Compiler *c, const NtFExpr *x, Sequence *q,
                            int writable, NtFId *checked_index) {
  if (c->safe_v2)
    return safe_address(c, x, q, writable, checked_index, NULL);
  NtFSpan span = x->span;
  NtFId index = temporary(c, lower_expr(c, x->right, q), q);
  if (checked_index)
    *checked_index = index;
  NtFId length = name_expr(c, c->vm[x->resolved - 1].length, span);
  guard(c, q, binary(c, NTF_OP_GE, index, length, TY_BOOL, span),
        NOVA_BOUNDS_ERROR, span);
  NtFId ptr = name_expr(c, x->resolved, span);
  if (c->safe_v2) {
    NtFId pointer = call_v2(
        c, NV2_RESOLVE, ptr, index,
        literal(c, 1 | (writable ? (UINT64_C(1) << 63) : 0), TY_U64, span), q,
        span);
    emit(c, q,
         (NtFStmt){.kind = NTF_S_CALL, .expression = pointer, .span = span});
    machine2(c, q, "mov", reg_expr(c, 11, 64, TY_U64, span),
             reg_expr(c, 0, 64, TY_U64, span), span);
    return expression_new(c, (NtFExpr){.kind = NTF_X_MEMORY,
                                       .type = TY_BUF,
                                       .memory = {.base = {11, 64, 0},
                                                  .index = {-1, 64, 0},
                                                  .scale = 1},
                                       .span = span});
  }
  /* Null is rejected even for a caller claiming positive length. */
  NtFId nulltest =
      binary(c, NTF_OP_EQ, ptr, literal(c, 0, TY_BUF, span), TY_BOOL, span);
  guard(c, q, nulltest, NOVA_BOUNDS_ERROR, span);
  guard(c, q,
        binary(c, NTF_OP_GT, ptr,
               binary(c, NTF_OP_SUB, literal(c, UINT64_MAX, TY_U64, span),
                      index, TY_U64, span),
               TY_BOOL, span),
        NOVA_BOUNDS_ERROR, span);
  emit(c, q, (NtFStmt){.kind = NTF_S_CALL, .expression = ptr, .span = span});
  machine2(c, q, "mov", reg_expr(c, 11, 64, TY_U64, span),
           reg_expr(c, 0, 64, TY_U64, span), span);
  emit(c, q, (NtFStmt){.kind = NTF_S_CALL, .expression = index, .span = span});
  machine2(c, q, "add", reg_expr(c, 11, 64, TY_U64, span),
           reg_expr(c, 0, 64, TY_U64, span), span);
  return expression_new(
      c, (NtFExpr){
             .kind = NTF_X_MEMORY,
             .type = TY_BUF,
             .memory = {.base = {11, 64, 0}, .index = {-1, 64, 0}, .scale = 1},
             .span = span});
}
static NtFId lower_expr(Compiler *c, NtFId id, Sequence *q) {
  if (++c->lowering_budget > MAX_NODES * 4)
    fail_at(c, 201, EX(c, id).span, "Nova lowering budget exceeded");
  enter(c);
  NtFExpr x = EX(c, id);
  NtFId result = id;
  if ((int)x.kind == X_RECORD)
    result = lower_record(c, &x, q);
  else if ((int)x.kind == X_LEN) {
    NtFId h = lower_expr(c, x.left, q);
    result = call_v2(c, NV2_LENGTH, h, 0, 0, q, x.span);
    unsigned width = buffer_width(c, EX(c, x.left).type);
    if (width > 1)
      result = binary(c, NTF_OP_DIV, result, literal(c, width, TY_U64, x.span),
                      TY_U64, x.span);
  } else if ((int)x.kind == X_BYTES)
    result = lower_bytes(c, &x, q);
  else if ((int)x.kind == X_RUNTIME) {
    result = runtime_call(c, &x, q);
  } else if ((int)x.kind == X_ALLOC || (int)x.kind == X_SLICE)
    fail_at(c, 400, x.span, "alloc and slice must initialize a buffer local");
  else if ((int)x.kind == X_INDEX || (int)x.kind == X_FIELD) {
    NtFId mem = buffer_address(c, &x, q, 0, NULL);
    unsigned bits = width_of(c, x.type) * 8;
    machine2(c, q, "load", reg_expr(c, 0, bits, x.type, x.span), mem, x.span);
    result = temporary(c, reg_expr(c, 0, bits, x.type, x.span), q);
  } else if (x.kind == NTF_X_UNARY) {
    EX(c, id).left = lower_expr(c, x.left, q);
  } else if (x.kind == NTF_X_BINARY) {
    NtFId left = temporary(c, lower_expr(c, x.left, q), q);
    if (x.op == (NtFOp)OP_AND || x.op == (NtFOp)OP_OR) {
      NtFId var = variable_new(c, "$logical", TY_BOOL, x.span, NTF_LOCAL, 1);
      emit(c, q,
           (NtFStmt){.kind = NTF_S_LET,
                     .variable = var,
                     .expression = left,
                     .span = x.span});
      Sequence rhs = {0};
      NtFId right = lower_expr(c, x.right, &rhs);
      emit(c, &rhs,
           (NtFStmt){.kind = NTF_S_LET,
                     .variable = var,
                     .expression = right,
                     .span = x.span});
      NtFId condition =
          x.op == (NtFOp)OP_AND
              ? left
              : binary(c, NTF_OP_EQ, left, literal(c, 0, TY_BOOL, x.span),
                       TY_BOOL, x.span);
      emit(c, q,
           (NtFStmt){.kind = NTF_S_IF,
                     .condition = condition,
                     .then_branch = sequence_block(c, rhs, x.span),
                     .span = x.span});
      result = name_expr(c, var, x.span);
    } else {
      NtFId right = temporary(c, lower_expr(c, x.right, q), q);
      EX(c, id).left = left;
      EX(c, id).right = right;
      if (x.op == NTF_OP_DIV || x.op == NTF_OP_MOD)
        guard(c, q,
              binary(c, NTF_OP_EQ, right,
                     literal(c, 0, EX(c, right).type, x.span), TY_BOOL, x.span),
              UINT64_C(0x8000000500000000), x.span);
      if (c->safe_v2 && (x.op == NTF_OP_DIV || x.op == NTF_OP_MOD) &&
          x.type == TY_I64) {
        NtFId minimum =
            binary(c, NTF_OP_EQ, left,
                   literal(c, UINT64_C(0x8000000000000000), TY_I64, x.span),
                   TY_BOOL, x.span);
        NtFId minus_one =
            binary(c, NTF_OP_EQ, right, literal(c, UINT64_MAX, TY_I64, x.span),
                   TY_BOOL, x.span);
        guard(c, q, binary(c, NTF_OP_AND, minimum, minus_one, TY_BOOL, x.span),
              11, x.span);
      }
      if (c->safe_v2 && (x.op == NTF_OP_SHL || x.op == NTF_OP_SHR)) {
        guard(c, q,
              binary(c, NTF_OP_GE, right,
                     literal(c, width_of(c, x.type) * 8, TY_U64, x.span),
                     TY_BOOL, x.span),
              12, x.span);
        if (x.op == NTF_OP_SHR && is_signed(x.type)) {
          emit(c, q,
               (NtFStmt){
                   .kind = NTF_S_CALL, .expression = right, .span = x.span});
          machine2(c, q, "mov", reg_expr(c, 1, 64, TY_U64, x.span),
                   reg_expr(c, 0, 64, TY_U64, x.span), x.span);
          emit(c, q,
               (NtFStmt){
                   .kind = NTF_S_CALL, .expression = left, .span = x.span});
          machine2(c, q, "sar", reg_expr(c, 0, 64, TY_U64, x.span),
                   reg_expr(c, 1, 8, TY_U8, x.span), x.span);
          result = temporary(c, reg_expr(c, 0, 64, x.type, x.span), q);
        }
      }
    }
  } else if (x.kind == NTF_X_CALL) {
    NtFId first = 0, tail = 0;
    for (NtFId a = x.first_arg; a;) {
      NtFId next = EX(c, a).next;
      NtFId v = temporary(c, lower_expr(c, a, q), q);
      append_arg(c, &first, &tail, v);
      a = next;
    }
    EX(c, id).first_arg = first;
    if (c->safe_v2) {
      result = temporary(c, id, q);
      propagate_error(c, q, x.span);
    }
  }
  leave(c);
  return result;
}
static void lower_block(Compiler *c, NtFId block) {
  enter(c);
  NtFId old = ST(c, block).first;
  Sequence q = {0};
  while (old) {
    NtFId next = ST(c, old).next;
    ST(c, old).next = 0;
    NtFStmt s = ST(c, old);
    if (s.kind == NTF_S_LET && is_buffer(c, VA(c, s.variable).type)) {
      lower_buffer_local(c, &s, &q);
      old = next;
      continue;
    } else if (s.kind == NTF_S_BLOCK)
      lower_block(c, old);
    else if (s.kind == NTF_S_IF) {
      ST(c, old).condition = lower_expr(c, s.condition, &q);
      lower_block(c, s.then_branch);
      if (s.else_branch)
        lower_block(c, s.else_branch);
    } else if ((int)s.kind == X_INDEX) {
      NtFExpr x = EX(c, s.condition);
      NtFId checked_index = 0, checked_handle = 0;
      NtFId mem = c->safe_v2 ? safe_address(c, &x, &q, 1, &checked_index,
                                            &checked_handle)
                             : buffer_address(c, &x, &q, 1, &checked_index);
      NtFId address = temporary(c, reg_expr(c, 11, 64, TY_U64, s.span), &q);
      NtFId value = temporary(c, lower_expr(c, s.expression, &q), &q);
      if (c->safe_v2)
        address = call_v2(
            c, NV2_RESOLVE, checked_handle, checked_index,
            literal(c,
                    (UINT64_C(1) << 63) |
                        ((int)x.kind == X_FIELD ? 8 : width_of(c, x.type)),
                    TY_U64, s.span),
            &q, s.span);
      emit(
          c, &q,
          (NtFStmt){.kind = NTF_S_CALL, .expression = address, .span = s.span});
      machine2(c, &q, "mov", reg_expr(c, 11, 64, TY_U64, s.span),
               reg_expr(c, 0, 64, TY_U64, s.span), s.span);
      /* The checked address is snapshotted before evaluating the RHS. */
      emit(c, &q,
           (NtFStmt){.kind = NTF_S_CALL, .expression = value, .span = s.span});
      machine2(c, &q, "store", mem,
               reg_expr(c, 0,
                        (int)x.kind == X_FIELD ? 64 : width_of(c, x.type) * 8,
                        x.type, s.span),
               s.span);
      old = next;
      continue;
    } else if (s.kind == NTF_S_RETURN || s.kind == NTF_S_LET ||
               s.kind == NTF_S_CALL)
      ST(c, old).expression = lower_expr(c, s.expression, &q);
    chain(c, &q.first, &q.tail, old);
    old = next;
  }
  ST(c, block).first = q.first;
  leave(c);
}
static void dispose(Compiler *c) {
  if (!c)
    return;
  free(c->tokens);
  free(c->vm);
  free(c->fm);
  free(c->p.modules);
  free(c->p.functions);
  free(c->p.variables);
  free(c->p.types);
  free(c->p.expressions);
  free(c->p.statements);
  free(c->tm);
  free(c->fields);
  free(c->skip_declaration);
  while (c->owned) {
    Owned *n = c->owned;
    c->owned = n->next;
    free(n->pointer);
    free(n);
  }
  free(c);
}
static void public_entry_v2(Compiler *c) {
  NtFId main = 0;
  for (size_t i = 0; i < c->p.function_count; i++)
    if (!strcmp(c->p.functions[i].name, "main")) {
      if (main)
        fail_at(c, 701, c->p.functions[i].span,
                "Nova ABI2 main is ambiguous across modules");
      main = (NtFId)i + 1;
    }
  if (!main)
    fail_at(c, 701, (NtFSpan){0}, "Nova ABI2 requires main");
  if (c->p.function_count >= MAX_FUNCS)
    fail_at(c, 201, FN(c, main).span,
            "Nova ABI2 wrapper exceeds function limit");
  NtFSpan span = FN(c, main).span;
  c->current_module = FN(c, main).module;
  FN(c, main).name = "$nova_body";
  c->function = (NtFId)++c->p.function_count;
  c->scope = 0;
  NtFFunction *f = &FN(c, c->function);
  *f = (NtFFunction){.name = "main",
                     .high_level_expressions = 1,
                     .module = c->current_module,
                     .abi = "efi-x64-v0",
                     .section = ".text",
                     .span = span,
                     .clobbers = (UINT64_C(1) << 17) | 1,
                     .exported = 1,
                     .return_type = TY_U64,
                     .param_count = 3};
  NtFId ctx = variable_new(c, "$context", TY_RUNTIME, span, NTF_IN, 0);
  f->first_param = ctx;
  NtFId args = variable_new(c, "$arguments", TY_RUNTIME, span, NTF_IN, 0),
        count = variable_new(c, "$argument_count", TY_U64, span, NTF_IN, 0);
  Sequence q = {0}, invalid = {0};
  emit(c, &invalid,
       (NtFStmt){.kind = NTF_S_RETURN,
                 .expression = literal(c, 0, TY_U64, span),
                 .span = span});
  emit(c, &q,
       (NtFStmt){.kind = NTF_S_IF,
                 .condition =
                     binary(c, NTF_OP_EQ, name_expr(c, ctx, span),
                            literal(c, 0, TY_RUNTIME, span), TY_BOOL, span),
                 .then_branch = sequence_block(c, invalid, span),
                 .span = span});
  NtFId size = member(c, name_expr(c, ctx, span), 8, &q, span);
  Sequence short_context = {0};
  emit(c, &short_context,
       (NtFStmt){.kind = NTF_S_RETURN,
                 .expression = literal(c, 0, TY_U64, span),
                 .span = span});
  emit(c, &q,
       (NtFStmt){.kind = NTF_S_IF,
                 .condition =
                     binary(c, NTF_OP_LT, size, literal(c, 48, TY_U64, span),
                            TY_BOOL, span),
                 .then_branch = sequence_block(c, short_context, span),
                 .span = span});
  emit(c, &q,
       (NtFStmt){.kind = NTF_S_CALL,
                 .expression = name_expr(c, ctx, span),
                 .span = span});
  machine2(c, &q, "mov", reg_expr(c, 15, 64, TY_RUNTIME, span),
           reg_expr(c, 0, 64, TY_RUNTIME, span), span);
  NtFId version = member(c, name_expr(c, ctx, span), 0, &q, span);
  guard(
      c, &q,
      binary(c, NTF_OP_NE, version, literal(c, 2, TY_U64, span), TY_BOOL, span),
      NV2_RUNTIME, span);
  propagate_error(c, &q, span);
  guard(c, &q,
        binary(c, NTF_OP_NE, name_expr(c, count, span),
               literal(c, FN(c, main).param_count, TY_U64, span), TY_BOOL,
               span),
        NV2_ARGUMENT, span);
  if (FN(c, main).param_count)
    guard(c, &q,
          binary(c, NTF_OP_EQ, name_expr(c, args, span),
                 literal(c, 0, TY_RUNTIME, span), TY_BOOL, span),
          NV2_ARGUMENT, span);
  NtFId first = 0, tail = 0;
  NtFId loaded_args[64] = {0};
  for (unsigned i = 0; i < FN(c, main).param_count; i++) {
    NtFId arg = member(c, name_expr(c, args, span), i * 8, &q, span);
    loaded_args[i] = arg;
    append_arg(c, &first, &tail, arg);
  }
  for (unsigned i = 0; i < FN(c, main).param_count; i++) {
    NtFId type = VA(c, FN(c, main).first_param + i).type;
    if (is_buffer(c, type)) {
      unsigned width = buffer_width(c, type);
      NtFId n = call_v2(c, NV2_LENGTH, loaded_args[i], 0, 0, &q, span);
      if (width > 1) {
        guard(c, &q,
              binary(c, NTF_OP_NE,
                     binary(c, NTF_OP_MOD, n, literal(c, width, TY_U64, span),
                            TY_U64, span),
                     literal(c, 0, TY_U64, span), TY_BOOL, span),
              NV2_ARGUMENT, span);
        n = binary(c, NTF_OP_DIV, n, literal(c, width, TY_U64, span), TY_U64,
                   span);
      }
      guard(c, &q, binary(c, NTF_OP_NE, n, loaded_args[i + 1], TY_BOOL, span),
            NV2_ARGUMENT, span);
      i++;
    } else if ((integer(type) || type == TY_BOOL) && width_of(c, type) < 8) {
      unsigned bits = width_of(c, type) * 8;
      uint64_t mask = type == TY_BOOL ? 1 : (UINT64_C(1) << bits) - 1;
      NtFId normalized = binary(c, NTF_OP_AND, loaded_args[i],
                                literal(c, mask, TY_U64, span), type, span);
      guard(c, &q,
            binary(c, NTF_OP_NE, loaded_args[i], normalized, TY_BOOL, span),
            NV2_ARGUMENT, span);
    }
  }
  NtFId call = expression_new(c, (NtFExpr){.kind = NTF_X_CALL,
                                           .type = FN(c, main).return_type,
                                           .resolved = main,
                                           .name = "$nova_body",
                                           .first_arg = first,
                                           .span = span});
  NtFId result = temporary(c, call, &q);
  propagate_error(c, &q, span);
  emit(c, &q,
       (NtFStmt){.kind = NTF_S_RETURN, .expression = result, .span = span});
  f->body = sequence_block(c, q, span);
}
static int compile_profile(const NtFInput *inputs, size_t count,
                           NtArtifact *out, int safe_v2, int check_only,
                           int seed_reachable, unsigned seed_policy,
                           NovaSeedReachabilityStats *seed_stats) {
  if (!out)
    return 0;
  memset(out, 0, sizeof *out);
  Compiler *c = calloc(1, sizeof *c);
  if (!c) {
    out->error.code = 900;
    return 0;
  }
  c->out = out;
  c->safe_v2 = safe_v2;
  if (setjmp(c->failure)) {
    dispose(c);
    return 0;
  }
  c->tokens = array(c, MAX_TOKENS, sizeof(Token));
  c->vm = array(c, c->safe_v2 ? MAX_LOCALS : MAX_VARS, sizeof(VariableMeta));
  c->fm = array(c, MAX_FUNCS, sizeof(FunctionMeta));
  c->tm = array(c, MAX_VARS, sizeof(TypeMeta));
  c->fields = array(c, MAX_VARS, sizeof(Field));
  c->skip_declaration = array(c, MAX_TOKENS, sizeof(size_t));
  c->p.modules = array(c, 65, sizeof(NtFModule));
  c->p.functions = array(c, MAX_FUNCS, sizeof(NtFFunction));
  c->p.variables =
      array(c, c->safe_v2 ? MAX_LOCALS : MAX_VARS, sizeof(NtFVariable));
  c->p.types = array(c, MAX_VARS, sizeof(NtFType));
  c->p.expressions = array(c, MAX_NODES, sizeof(NtFExpr));
  c->p.statements = array(c, MAX_NODES, sizeof(NtFStmt));
  c->p.module_count = 1;
  c->current_module = 1;
  c->p.modules[0] =
      (NtFModule){.name = "nova.bootstrap",
                  .target = "x86_64-uefi",
                  .default_abi = c->safe_v2 ? "efi-x64-v0" : "nx64-abi-v0",
                  .features = 1};
  c->p.type_count = 11;
  c->tm[TY_BUF - 1] = (TypeMeta){.kind = 1, .element = TY_U8};
  c->p.types[0] = (NtFType){.kind = NTF_T_U8, .bits = 8};
  c->p.types[1] = (NtFType){.kind = NTF_T_U64, .bits = 64};
  c->p.types[2] = (NtFType){.kind = NTF_T_BOOL, .bits = 8};
  c->p.types[3] = (NtFType){
      .kind = NTF_T_PTR, .element = TY_U8, .bits = 64, .space = NTF_SPACE_USER};
  c->p.types[4] = (NtFType){.kind = NTF_T_PTR,
                            .element = TY_U64,
                            .bits = 64,
                            .space = NTF_SPACE_USER};
  c->p.types[TY_U16 - 1] = (NtFType){.kind = NTF_T_U16, .bits = 16};
  c->p.types[TY_U32 - 1] = (NtFType){.kind = NTF_T_U32, .bits = 32};
  c->p.types[TY_I8 - 1] = (NtFType){.kind = NTF_T_I8, .bits = 8};
  c->p.types[TY_I16 - 1] = (NtFType){.kind = NTF_T_I16, .bits = 16};
  c->p.types[TY_I32 - 1] = (NtFType){.kind = NTF_T_I32, .bits = 32};
  c->p.types[TY_I64 - 1] = (NtFType){.kind = NTF_T_I64, .bits = 64};
  lex(c, inputs, count);
  if (c->safe_v2)
    module_headers(c);
  if (c->safe_v2)
    collect_records(c);
  signatures(c);
  for (size_t i = 0; i < c->p.function_count; i++) {
    c->function = (NtFId)i + 1;
    c->current_module = FN(c, c->function).module;
    c->scope = 0;
    c->at = c->fm[i].start;
    FN(c, c->function).body = parse_block(c);
    if (c->at != c->fm[i].end)
      fail(c, 200, "Nova function boundary mismatch");
    if (!definitely_returns(c, FN(c, c->function).body))
      fail_at(c, 500, FN(c, c->function).span,
              "Nova function has a path without return");
  }
  for (size_t i = 0; i < c->p.function_count; i++) {
    c->function = (NtFId)i + 1;
    c->current_module = FN(c, c->function).module;
    lower_block(c, FN(c, c->function).body);
  }
  if (check_only) {
    dispose(c);
    return 1;
  }
  if (c->safe_v2)
    public_entry_v2(c);
  c->p.verified = 1;
  NtCodeImage image;
  NtCodeDiagnostic diagnostic;
  if (!nt_codegen_x64(&c->p, &image, &diagnostic))
    fail_at(c, diagnostic.code, diagnostic.span, diagnostic.message);
  if (seed_reachable &&
      !nova_seed_compact_image(&image,seed_policy,seed_stats,&diagnostic)) {
    nt_code_image_free(&image);
    fail_at(c,diagnostic.code,diagnostic.span,diagnostic.message);
  }
  out->text = (NtBuffer){image.bytes, image.size, image.capacity};
  out->entry = image.entry;
  out->rdata =
      (NtBuffer){image.rdata.bytes, image.rdata.size, image.rdata.capacity};
  out->data =
      (NtBuffer){image.data.bytes, image.data.size, image.data.capacity};
  image.bytes = NULL;
  image.rdata.bytes = NULL;
  image.data.bytes = NULL;
  if (seed_reachable &&
      !nova_seed_materialize_dir64(&image,out,&diagnostic)) {
    nt_artifact_free(out);
    nt_code_image_free(&image);
    fail_at(c,diagnostic.code,diagnostic.span,diagnostic.message);
  }
  nt_code_image_free(&image);
  dispose(c);
  return 1;
}
int nova_compile(const char *s, size_t n, NtArtifact *out) {
  NtFInput in = {"<nova>", s, n};
  return nova_compile_many(&in, 1, out);
}
int nova_compile_many(const NtFInput *inputs, size_t count, NtArtifact *out) {
  return compile_profile(inputs, count, out, 0, 0, 0, 0, NULL);
}
int nova_compile_many_v2(const NtFInput *inputs, size_t count,
                         NtArtifact *out) {
  return compile_profile(inputs, count, out, 1, 0, 0, 0, NULL);
}
int nova_compile_many_v2_seed_reachable(const NtFInput *inputs,size_t count,
    NtArtifact *out,const NovaSeedReachabilityOptions *options,
    NovaSeedReachabilityStats *stats) {
  if(stats)memset(stats,0,sizeof *stats);
  unsigned policy=options?options->root_policy:NOVA_SEED_ALL_EXPORTS;
  if(options&&(options->version!=1||options->size!=sizeof *options||
      options->reserved||policy>NOVA_SEED_ENTRY_ONLY_CLOSED_APPLICATION)) {
    if(out){
      memset(out,0,sizeof *out);out->error.code=NTCG_E_UNSUPPORTED;
      snprintf(out->error.message,sizeof out->error.message,"invalid seed reachability options");
    }
    return 0;
  }
  return compile_profile(inputs,count,out,1,0,1,policy,stats);
}
int nova_check_many_v2(const NtFInput *inputs, size_t count,
                       NtDiagnostic *out) {
  NtArtifact a;
  int ok = compile_profile(inputs, count, &a, 1, 1, 0, 0, NULL);
  if (out)
    *out = a.error;
  nt_artifact_free(&a);
  return ok;
}
int nova_compile_v2(const char *s, size_t n, NtArtifact *out) {
  NtFInput input = {"<nova>", s, n};
  return nova_compile_many_v2(&input, 1, out);
}
