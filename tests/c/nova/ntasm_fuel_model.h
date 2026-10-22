#ifndef NG_NTASM_FUEL_MODEL_H
#define NG_NTASM_FUEL_MODEL_H

/* ==========================================================================
   The fuel model -- one affine model of the expander's fuel accounting, for
   every gate that claims a fuel figure, sitting beside the frozen
   ntasm_pipeline_parity.h.

   WHAT THIS EXISTS FOR.  Three gates each held a copy of a fuel integer.
   tests_ntasm_validate.c and tests_ntasm_splice.c each carried the corpus
   member's cost as the literals 8 and 7, in two files, neither telling the
   other; tests_ntasm_macro_expand.c carried the meta-for ladder as the
   literals 5 and 8.  When the caller's-walk charge was removed in wave 17
   (macro_expand.nova's walk()), the corpus member's cost went 30 -> 8 and
   BOTH files had to be re-pinned in the same run, and neither learned that
   the other one had moved.  Two copies of one integer, coupled by nothing.

   WHY A MODEL AND NOT A CONSTANT.  A shared header holding one constant fixes
   the duplication and not the agreement: three readers of one literal still
   say three things about whether the number is right.  What was missing was
   the DERIVATION the header should name, so this one is affine in the item
   count with a per-shape intercept, and every number in it is a measured
   ladder rather than a copied figure:

       fuel(shape, items) = base(shape) + per_item(shape) * items

   The parameters were fitted from ladders measured over the SAME source text
   the gates use, on both oracles; the ladders are in
   out/c-bootstrap/nova/evidence/W19FuelModel/.  Change a parameter here and
   every gate that claims a fuel figure goes red.  That is the acceptance
   criterion this file exists to satisfy and it was measured, not asserted.

   ------------------------------------------------------------------------
   THE INTERCEPT IS PER SHAPE, AND THAT IS THE POINT, NOT A DETAIL.

   A model that let the meta-for's numbers decide the flat member's would be
   the defect U29 names wearing one name.  The two are different bodies,
   measured on different ladders, and they disagree:

       shape          items   Nova   reference
       FLAT_RET         0       5        3
       FLAT_RET         1       8        5      <- the corpus member
       FLAT_RET         2      11        7
       META_FOR         0       5     n/a
       META_FOR         1      13     n/a
       META_FOR         8      69     n/a
       FLAT_BLOCK       1      18        5

   FLAT_RET and META_FOR measured the SAME intercept, 5, on two independent
   ladders, and that is a fact about two bodies rather than a shared
   constant: FLAT_BLOCK measured 11 on its own ladder.  Their SLOPES differ
   (3 against 8), their item counts mean different things (added terms inside
   one quoted statement against projected loop items), and their totals
   differ at every count: the meta-for's first rung is 13 and the corpus
   member is 8, so reading the meta-for's ladder at items=1 to learn the flat
   member's cost would be wrong by five.  Nothing in this file lets one
   shape's parameters reach another's.

   ------------------------------------------------------------------------
   THE REFERENCE SIDE, and what it is allowed to claim.

   Two of the three shapes can be asked of both oracles.  META_FOR cannot,
   and that is a measured fact rather than a missing row:

     * the C reference REFUSES the spelling Nova uses for a meta-for
       (`->ast.decl` with `emit quote(decl)`).  frontend.c admits `if` /
       `for` / a plain emit list only when the macro's result is a
       `list<ast.stmt>` or `list<ast.decl>` (the emit_list flag is set at
       frontend.c:3361 and consumed at :3445), so Nova's body is refused at
       the `for` with 200 "expected 'return'";
     * Nova REFUSES the reference's own spelling.  macro_result returns 0 for
       a `list<...>` result, so macro_expand.nova:2204 answers 377 reason 1
       on every one of them.

   So there is no body on which both oracles answer "what does a meta-for of
   n items cost", and a ratio between two numbers for this shape would be a
   ratio between two different questions.  The reference's own meta-for,
   measured on the body it does accept, is FLAT: 2 fuel at n = 0, 1, 2, 3,
   4, 5, 6, 7, 8, 100, 236, 372 and 508 -- no per-item term at all, which
   is the conclusion wave 17 reached, recorded here as a number with the
   caveat that Nova cannot be run on that body.

   For the two comparable shapes the ratio is NOT CONSTANT, and the model
   says so rather than offering a divisor:

       FLAT_RET    (5+3n) : (3+2n)   5:3, 8:5, 11:7, 14:9, ... -> 1.500
       FLAT_BLOCK  (11+7n) : (3+2n)  18:5, 25:7, 32:9, ...     -> 3.500

   It falls with the item count on both, it settles at a different limit on
   each, and the two shapes disagree by more than a factor of two at every
   count.  There is no rate that maps one scheme onto the other, which is
   why removing the walk's charge was a removal and not a scaling.

   A NOTE ON WAVE 17'S RATIO TABLE, because lot briefs keep quoting it and it
   is stale.  23:1, 30:5 and 2565:1 were measured BEFORE the walk removal;
   they are the "Nova (before)" column of that evidence.  Re-measured on the
   current tree, over the same five member levels, Nova charges 0, 0, 0, 0, 8
   and the reference charges 1, 1, 1, 1, 5, so that table is 0:1 four times
   and 8:5 once.  2565 was 25 + 5*508 on a .rdata fixture which is not the
   meta-for shape, and its item count is 508 rather than 498.  Nothing in
   this file depends on any of those numbers.
   ========================================================================== */

#include <stdint.h>
#include <string.h>

/* gcc builds this tree with -Wall -Wextra -Werror and a harness that uses one
   half of this file would otherwise fail on the other half's unused statics.
   Same reason, same attribute, as ntasm_pipeline_parity.h. */
#define NG_FUEL_UNUSED __attribute__((unused))

/* --------------------------------------------------------------------------
   The shapes, named by what they are and not by where they were first
   measured.  `items` means something different in each, and that difference
   is the reason the intercept cannot be shared between them:

     FLAT_RET    one quoted STATEMENT, `return $v+1+1...;`.  items is the
                 number of `+1` terms in it.  items 0 is `return $v;` and
                 items 1 IS the corpus member of the specification's worked
                 example -- the body tests_ntasm_validate.c and
                 tests_ntasm_splice.c both hold a figure for.
     META_FOR    a `for i in $n` projecting `emit quote(decl)`.  items is the
                 projected item count n.
     FLAT_BLOCK  one quoted BLOCK holding `let t:u64 = $v;` lines.  items is
                 the number of lets.  It is here as the counterexample that
                 keeps the intercept honest: its base is 11, not 5.
   -------------------------------------------------------------------------- */
#define NG_FUEL_FLAT_RET_STR "flat_ret: one quoted statement, $v+1+1..."
#define NG_FUEL_META_FOR_STR "meta_for: for i in $n { emit quote(decl) {...} }"
#define NG_FUEL_FLAT_BLOCK_STR "flat_block: one quoted block of let bindings"
#define NG_FUEL_FLAT_RET_FIXTURE \
  "macro ret(v:ast.expr)->ast.stmt { return quote(stmt) { return $v+1; }; }"
#define NG_FUEL_META_FOR_FIXTURE                                      \
  "macro many(n:u64)->ast.decl { for i in $n { "                     \
  "emit quote(decl) { const c:u64 = $i; }; } }"
#define NG_FUEL_FLAT_BLOCK_FIXTURE                                    \
  "macro blk(v:ast.expr)->ast.block { return quote(block) { "         \
  "let t0000:u64 = $v; return t0000; }; }"

typedef enum {
  NG_FUEL_FLAT_RET = 0,
  NG_FUEL_META_FOR = 1,
  NG_FUEL_FLAT_BLOCK = 2,
  NG_FUEL_SHAPE_COUNT = 3
} ng_fuel_shape;

/* Is the C reference able to answer the same question about this shape? */
typedef enum {
  NG_FUEL_REF_COMPARABLE = 0,     /* both oracles expand the same body */
  NG_FUEL_REF_NO_COMMON_BODY = 1  /* neither will run the other's      */
} ng_fuel_ref_status;

typedef struct {
  const char *name;
  const char *fixture;   /* the ladder this row was measured on, in words */
  uint64_t nova_base;    /* fuel at zero items                           */
  uint64_t nova_per_item;/* the marginal, per projected item              */
  uint64_t ref_base;     /* the reference's own intercept, where measured */
  uint64_t ref_per_item; /* the reference's own marginal, where measured  */
  /* The lowest item count this shape was MEASURED at. It is 0 for two of
     the three shapes and 1 for the third, and the difference is a fact about
     the body rather than about the model: a quoted block holding no `let` at
     all is a DIFFERENT body from a quoted block holding lets, and it
     measures 7 where the let-holding shape's fitted intercept is 11. So for
     FLAT_BLOCK the intercept is a FITTED parameter, pinned by the ladder
     above it rather than read at zero, and a gate that wanted a directly
     measured intercept would have to say which of the two it is holding. */
  uint64_t first_measured_item;
  ng_fuel_ref_status ref_status;
  /* When there is no common body: the two measured refusals, one per
     direction, so the row records WHY rather than only that. */
  uint64_t ref_on_nova_spelling_code; /* what the C reference says        */
  uint64_t nova_on_ref_spelling_code; /* what Nova says                   */
  uint64_t nova_on_ref_spelling_reason;
  uint64_t ref_measured_fuel; /* the reference's number, on ITS OWN body  */
  const char *why_not;
} ng_fuel_shape_model;

NG_FUEL_UNUSED static const ng_fuel_shape_model
    ng_fuel_shapes[NG_FUEL_SHAPE_COUNT] = {
        {NG_FUEL_FLAT_RET_STR, NG_FUEL_FLAT_RET_FIXTURE, 5, 3, 3, 2, 0,
         NG_FUEL_REF_COMPARABLE, 0, 0, 0, 0, ""},
        {NG_FUEL_META_FOR_STR, NG_FUEL_META_FOR_FIXTURE, 5, 8, 0, 0, 0,
         NG_FUEL_REF_NO_COMMON_BODY, 200, 377, 1, 2,
         "the C reference admits a meta-for only under a list<> result and "
         "refuses Nova's spelling at the `for` with 200; Nova has no list<> "
         "result and refuses the reference's spelling 377/1, so the two "
         "numbers here are not two views of one figure"},
        {NG_FUEL_FLAT_BLOCK_STR, NG_FUEL_FLAT_BLOCK_FIXTURE, 11, 7, 3, 2, 1,
         NG_FUEL_REF_COMPARABLE, 0, 0, 0, 0, ""},
};

/* --------------------------------------------------------------------------
   THE ONE NAMED FUNCTION THE WHOLE THING EXISTS FOR.  It PRODUCES the figure
   from the shape and the item count; no gate holds the resulting integer.

   For a shape the reference cannot be run on, ng_fuel_reference() returns 0
   and ng_fuel_reference_comparable() is 0 -- a 0 there means "no such
   number", never "measured to be zero", and the gates are told which by
   asking rather than by reading the 0.
   -------------------------------------------------------------------------- */
NG_FUEL_UNUSED static uint64_t ng_fuel_nova(ng_fuel_shape shape,
                                            uint64_t items) {
  const ng_fuel_shape_model *m = &ng_fuel_shapes[(int)shape];
  return m->nova_base + m->nova_per_item * items;
}

NG_FUEL_UNUSED static uint64_t ng_fuel_reference(ng_fuel_shape shape,
                                                 uint64_t items) {
  const ng_fuel_shape_model *m = &ng_fuel_shapes[(int)shape];
  if (m->ref_status != NG_FUEL_REF_COMPARABLE) return 0;
  return m->ref_base + m->ref_per_item * items;
}

NG_FUEL_UNUSED static int ng_fuel_reference_comparable(ng_fuel_shape shape) {
  return ng_fuel_shapes[(int)shape].ref_status == NG_FUEL_REF_COMPARABLE;
}

/* The two marginals, read as the model's own slopes.  A gate that compares a
   MEASURED marginal against one of these is comparing a measurement with the
   model, not with a fourth copy of the number. */
NG_FUEL_UNUSED static uint64_t ng_fuel_nova_marginal(ng_fuel_shape shape) {
  return ng_fuel_shapes[(int)shape].nova_per_item;
}
NG_FUEL_UNUSED static uint64_t ng_fuel_reference_marginal(ng_fuel_shape shape) {
  return ng_fuel_shapes[(int)shape].ref_per_item;
}

/* The ratio of two figures in thousandths.  Both arguments are the CALLER's,
   so a gate may put a measurement on one side and the model on the other, and
   may equally put two measurements on both sides to show that the ratio moved.
   Zero for a zero divisor, because a ratio against nothing is a question and
   not an answer. */
NG_FUEL_UNUSED static uint64_t ng_fuel_ratio_milli(uint64_t nova,
                                                   uint64_t reference) {
  if (reference == 0) return 0;
  return (nova * 1000ull) / reference;
}

/* ==========================================================================
   The compiler bounds that are not the six declared budgets, and the status
   each one can be shown to have.

   A declared bound with no measured enforcement status is a number a reader
   cannot act on: "the expander refuses past 65536 binding words" and "the
   expander refuses past 262144 nodes" are the same sentence with one of them
   true.  macro_expand.nova's own banner says as much and the arms of
   tests_ntasm_macro_expand.c measure it; this is a place a reader can look
   and find the VERDICT rather than the arms.

   ------------------------------------------------------------------------
   SCOPE.  The expander declares EIGHT compiler bounds.  Six are `fn *cap()` --
   hard_node_cap, hard_name_cap, loop_cap, walk_depth_cap, parameter_cap,
   template_item_cap -- and two are literal capacities inside their own push
   functions, 65536 in push_binding and 4096 in push_arg.  THIS TABLE CARRIES
   ALL EIGHT.  It carried four until wave 21, and the four it did not carry
   were carried nowhere: loop_cap, walk_depth_cap, parameter_cap and
   template_item_cap were reachable, and reachable, and read out of another
   source rather than out of a table whose whole purpose is to be looked up.
   A table that holds the four that were hard is not a table of the eight.

   THE PREVIOUS SCOPE SENTENCE IS RETRACTED, and it is left visible because a
   correction that carries its own mistake into the artefact teaches the next
   reader the trap.  It said: "of the expander's eight compiler bounds, four
   are reachable and four are unreachable, and the four in this table are the
   unreachable four."  That was wrong on the reachable/unreachable SIDE.  The
   campaign A5_CAMPAIGN_BOUNDS measured all seven of this lot's bounds with the
   triple -- at the maximum, one past it and one below it -- and hard_name_cap
   is REACHABLE: 32768 items with 107 byte introduced names expand whole, 115
   byte names are refused 900 reason 1, and 99 byte names expand.  So the
   unreachable set is three, not four, and it is the three the table carries
   first.

   ------------------------------------------------------------------------
   THE TEXT COLUMN IS NEW, and it is the answer to a question the campaign
   banner said nothing covered: "aucune campagne n'affirme quoi que ce soit
   sur le texte des diagnostics".  Every row now carries the measured fact
   that the expander's refusal is FOUR UNSIGNED 64 BIT WORDS and no text, so a
   reader who looks a bound up here and then reports its code to a user is not
   reporting a message.  A code that names a family is not a sentence, and
   `900` reason 1 is the same three words for the name table, the node table,
   the binding stack and the argument stack.

   THE FOUR WORDS BECAME SIX IN WAVE 23, and the three macros below say so
   rather than being quietly restated.  What the refusal is has not changed:
   it is this module's own numbers and no text, and what it can now be used
   for has.  Measured over the whole output region of seven refusals at
   seven boundaries, before and after, diagnostic_text_found is 0 both times.
   The added words are numbers, because out is buf<u64>.
   The product does have a text channel -- NtError.message, printed as
   `E<code> <message>` at cli.c:138, :203 and :243 -- and the C REFERENCE
   populates it for these very bounds (frontend.c:3784 "quoted block statement
   limit exceeded", :2244 "meta-for iteration output exceeds 512 statements",
   :4791 "declaration meta-for output exceeds 512").  The Nova tree contains
   three occurrences of those strings and all three are COMMENTS quoting the
   reference; none of them emits.  The asymmetry is the finding.

   (The paragraph above was cut in half by the block below when that block
   was inserted, and is rejoined here rather than left as two sentences with
   nothing between them.)


   ------------------------------------------------------------------------
   THE INSTRUMENT GREW TWO WORDS, AND THE THREE ROWS THAT NAMED A SHADOW
   ARE NOW VISIBLE AS SUCH.  Wave 23 added out[10] and out[11] to the
   refusal: the QUANTITY that crossed the cap, in the cap's own unit, and the
   cap it crossed.  Both are written only under `len(out)>=12`, so a caller
   that allocated the four words the ABI used to require reads byte-identical
   words; that was measured at all six refusal arms, not asserted.

   TEN AND ELEVEN, and not four and five, because out[4] and out[5] are
   node_count and depth_peak on a successful MEASURE.  Publishing there would
   make one position carry two meanings separated only by out[0], and a
   reader who has to hold the code to read the data is not reading data.

   WHAT THE TWO WORDS CHANGED IS WHICH BOUND ANSWERED.  Three of these eight
   rows name a bound whose own arm is refused by a DIFFERENT bound, and the
   quantity says so in the row's own unit:

       binding_stack   publishes  513 against      512   (template_item_cap)
       argument_stack  publishes  129 against      128   (expansion_depth)
       hard_node_cap   publishes 16777248 against 16777216 (arena_bytes)

   None of those three is the number its row declares -- 65536, 4096,
   262144 -- and that is not a fault in the publication.  It is the three
   UNREACHABLE_ARITHMETIC rows measured from the other side: the bound that
   answers is the shadow the `shadow` column already named.  Before this
   change a caller holding 380/2 could not tell loop_cap from
   template_item_cap.  It now can, from the words, without holding the code.

   ALL SEVEN REFUSAL ARMS, MEASURED, one line each, from the wave-23 run:

       parameter_cap     9        against        8   this row's own bound
       walk_depth_cap   65        against       64   this row's own bound
       loop_cap        513        against      512   this row's own bound
       hard_name_cap 8388608      against  4194304   this row's own bound, in BYTES
       binding_stack   513        against      512   a SHADOW answered
       argument_stack  129        against      128   a SHADOW answered
       hard_node_cap 16777248     against 16777216   a SHADOW answered

   And the one that answers the question this table was asked and could not:
   walk_depth_cap publishes 65 against 64, and that pair is HAND-COMPUTED
   from the source rather than fitted to the run -- `if
   depth>walk_depth_cap()` with `walk_depth_cap()==64` and `depth` a u64, so
   the first value that can satisfy the guard is 65 whatever the body.  The
   same control, run against the SHIPPED bytes, fails with offending 0 and
   limit 0; that failure is the evidence the control is not vacuous.

   WHAT IS STILL NOT PUBLISHED, and the reason is the shape of the thing and
   not a missing formatter: out is buf<u64>.  Every word is a number, so a
   "message" is a number the CALLER renders, and diagnostic_text_found is 0
   before and after.  A formatter would be a formatter in the caller.

   ONE SITE THAT HAD NO CHANNEL, AND NOW DOES.  RETRACTED IN WAVE 24, and the
   retraction is left here because the sentence was TRUE when it was written
   and a reader six weeks out should not meet it as if it still were.
   declares_below guards `if depth>walk_depth_cap()` and returns a BOOLEAN, so
   a declaration scan that reached the cap answered "no declarations found
   below" -- a wrong answer, not a terse one -- and published nothing, because
   it raised no diagnostic for a quantity to travel in.  Wave 24 repaired it
   AT THE SITE, by calling note_bound before the return, so the depth is
   carried even on a boolean path.  The shape is the part worth keeping: a
   guard that answers with a value rather than a refusal still has to say what
   it refused on, and note_bound exists for exactly that case.

   ------------------------------------------------------------------------
   ONE UNIT WAS WRONG AND IS CORRECTED HERE.  hard_name_cap's `unit` read "name
   table words" and this row converted 4194304 words into 524288 entries of 8
   words each, which is 33554432 bytes -- eight times the ceiling that is
   actually enforced.  reserve_names (macro_expand.nova:642-648) reads

       let mut want:u64=env.name_cap;
       while want*8<(env.name_bytes+extra_bytes) { want=want*2; }
       if want*8>hard_name_cap() { return 1; }
       let words:buf<u64>=alloc(runtime(),want);

   `want` is a WORD count, because alloc hands back `want` u64.  So `want*8` is
   a BYTE count, and 4194304 bounds 4 MiB OF INTRODUCED NAME TEXT.  The
   `words`/`per_entry`/`entries` triple is unchanged and still straddles the
   declared number, because the correction is to the LABEL: 4194304 bytes is
   524288 words is 524288 entries of 8 bytes.  The arithmetic survived; the
   name did not.
   ========================================================================== */

typedef enum {
  NG_FUEL_BOUND_REACHABLE = 0,
  /* Enforced in code and never the thing that answers, and the reason is
     arithmetic rather than exhaustion: another declared bound answers first,
     at a count that arithmetic fixes. */
  NG_FUEL_BOUND_UNREACHABLE_ARITHMETIC = 1,
  /* A DIFFERENT FACT, and a table that collapsed the two would be a table a
     reader cannot act on.

     UNREACHABLE_ARITHMETIC is a SHADOW: the site refuses, and it refuses on a
     DIFFERENT quantity, because another declared bound answers first at a
     count that arithmetic fixes. The row is wrong about which bound governs,
     and the caller's correction is to be told WHICH one answered -- which is
     what the shadow column and the published out[10]/out[11] are for.

     UNREACHABLE_CALLERS is a DEAD ARM: the site CANNOT REFUSE AT ALL, because
     no call site in the module can pass an argument that reaches the guard.
     There is no shadow to name and no quantity to publish, because no
     production path produces the input. The row is CORRECT, the guard is
     defence in depth, and NOTHING CAN BE OBSERVED HERE.

     They look identical in a column of verdicts and they have opposite
     consequences: a shadow is a live instrument reporting the wrong bound, a
     dead arm is documentation. Do not merge them, and do not relabel a shadow
     as this. */
  NG_FUEL_BOUND_UNREACHABLE_CALLERS = 2
} ng_bound_status;

typedef struct {
  const char *name;
  uint64_t words;      /* the declared bound, in the unit named below      */
  const char *unit;    /* what the number counts -- READ THIS, not `words` */
  uint64_t per_entry;  /* what one entry occupies, 0 when the unit is nodes */
  uint64_t entries;    /* what `words` holds, in the unit                    */
  ng_bound_status status;
  uint64_t shadow_code;   /* the code the shadow answers with, 0 if none    */
  uint64_t shadow_reason;
  const char *shadow;     /* which declared bound answers first, and why     */
  /* The measured state of the diagnostic itself.  `words` above is about the
     BOUND; this is about the INSTRUMENT, and a reader who stops at the row
     above would never learn the difference. */
  const char *diag_text;  /* what the caller receives at the boundary        */
  const char *diag_promise;   /* what that instrument is good for           */
  const char *diag_lacks;      /* what it cannot be used for, stated         */
} ng_bound_model;


/* THE NO TEXT, STATED ONCE, because seven rows repeating it would be seven
   opportunities to write it differently.  Measured by A5_CAMPAIGN_BOUNDS: the
   whole output region of seven refusals at seven boundaries, scanned for
   printable byte runs of four or more, zero runs at every one.  The positive
   control was a SUCCESSFUL expansion, whose name table the same scanner reads
   as "__ntm$1$e1$t0000u64..."; a scanner that found nothing there would be
   broken and every negative it produced would be void. */
#define NG_DIAG_THE_FOUR_WORDS                                                  \
  "SIX unsigned 64 bit words on a refusal and no text: out[0] code, out[1] "    \
  "line, out[2] column, out[3] reason, out[10] the QUANTITY that crossed the " \
  "cap in the cap's own unit, out[11] the cap. The name is kept because six "  \
  "rows of prose about it would be six opportunities to write it differently. " \
  "The last two arrived in wave 23 and are written only under len(out)>=12, so " \
  "a caller holding the four words the ABI used to require reads "             \
  "byte-identical words; measured, not asserted. Measured over the WHOLE "    \
  "region the caller receives, not only those words."

#define NG_DIAG_PROMISES                                                       \
  "a family, a position, a reason, and since wave 23 the quantity and the cap "  \
  "it crossed. Enough to route a diagnostic, to point a user at a line, and "   \
  "to tell WHICH bound answered when two share a code."

#define NG_DIAG_LACKS                                                          \
  "it still never says a sentence. A code is not a message, and this product "  \
  "has a text channel the Nova expander does not use; out is buf<u64>, so "    \
  "every word here is a number and rendering it is the CALLER's work. What "    \
  "was retracted in wave 23: it used to say this instrument 'never names the " \
  "limit that was crossed, never the value that was reached', and that became " \
  "false when out[10] and out[11] were added."

/* The three rows whose own arm is refused by a SHADOW, measured in wave 23.
   The bound each row names is not the bound that answered, and the published
   quantity is how a reader sees that without holding the code. */
#define NG_DIAG_SHADOW_QUANTITY(what, off, lim)                                 \
  "this refusal is NOT this bound's: out[10]/out[11] publish " what " against " \
  off "/" lim ", in the SHADOW's unit. The number this row declares is never " \
  "the one that answers, which is what UNREACHABLE_ARITHMETIC means measured " \
  "from the other side. Before wave 23 the code alone could not say so."

/* NINE rows, and the ninth is not a budget.  The eight below it are the six
   comptime budgets and the compiler bounds the expander declares.  `put_words`
   is a BYTE cap on a packed word inside one function, and it is here because
   it is the only other guard in macro_expand.nova that compares an argument
   against a limit and refuses -- so it was the only other candidate for the
   property the wave-23 audit was run to find, and its answer had to be a row
   rather than a silence.  It is a DEAD ARM and not a shadow, and the
   distinction is the entire reason it is worth a row. */
NG_FUEL_UNUSED static const ng_bound_model ng_fuel_bounds[9] = {
    /* The three whose DECLARED MAXIMUM CANNOT BE ASKED FOR.  A bound nothing
       can reach cannot fail, so it protects nothing, and saying so is the
       whole reason these three are listed first. */
    {"binding_stack", 65536, "binding stack words", 7, 9362,
     NG_FUEL_BOUND_UNREACHABLE_ARITHMETIC, 380, 2,
     "template_item_cap 512: the 9363rd entry needs 65541 words, five more than "
     "the 65536 the table holds, and a body that pushes 9363 entries holds 9363 "
     "statements, which template_item_cap refuses 380/2 at 512 -- eighteen "
     "times earlier. Measured by the triple: 510 lets and 511 lets expand "
     "whole, 512 lets are refused 380/2.",
     NG_DIAG_THE_FOUR_WORDS,
     NG_DIAG_SHADOW_QUANTITY("513 items against 512 items", "template_item_cap",
                             "512"),
     "promises nothing at 9363 entries, and says nothing about 65536 words "
     "being enforced by being reached, because it never is"},
    {"argument_stack", 4096, "argument stack words", 4, 1024,
     NG_FUEL_BOUND_UNREACHABLE_ARITHMETIC, 201, 5,
     "the expansion_depth budget at its declared maximum of 128: a comptime "
     "block may only lower a budget, so 1024 chain levels cannot be asked for. "
     "Measured by the triple: 126 and 127 levels expand whole, 128 is refused "
     "201/5, and the measured expansion depth at the 127 level ceiling is the "
     "declared 128 -- eight times below.",
     NG_DIAG_THE_FOUR_WORDS,
     NG_DIAG_SHADOW_QUANTITY("129 expansion levels against 128",
                             "the expansion_depth budget", "128"),
     "promises nothing at 1024 chain levels, and says nothing about 4096 words "
     "being enforced by being reached, because it never is"},
    {"hard_node_cap", 262144, "published nodes", 0, 174762,
     NG_FUEL_BOUND_UNREACHABLE_ARITHMETIC, 201, 3,
     "arena_bytes, twice over. node_bytes is 96 and max_arena is frozen at "
     "16777216, so the arena answers at 16777216/96 = 174762 charges, below "
     "the 262144 at which reserve_nodes would refuse, for every body. AND the "
     "arena's own ceiling is above a host ceiling: an earlier run of the "
     "campaign reached runtime=4 (NV2_BOUNDS) with code 0 and nothing "
     "published at 32704 items. Which of the two runtime_v2 sites raised it "
     "was NOT isolated. reserve_nodes is dead code, kept as a declared bound.",
     NG_DIAG_THE_FOUR_WORDS,
     NG_DIAG_SHADOW_QUANTITY("16777248 arena bytes against 16777216",
                             "arena_bytes", "max_arena"),
     "promises nothing at 262144 published nodes, and says nothing about a "
     "host error arriving with a zero diagnostic code"},

    /* The five that are REACHABLE and measured with the triple.  They were
       reachable before this table listed them; that is not the same as being
       findable here, and a table of the hard four is not a table of the eight. */
    {"hard_name_cap", 4194304, "name table BYTES", 8, 524288,
     NG_FUEL_BOUND_REACHABLE, 900, 1,
     "none: the name table is a counter of its own and the node budget is "
     "another, so a body can be refused by the name table while the same item "
     "count with short names expands. Measured by the triple at 32768 items, "
     "where the arena is 3.1 MB and well inside its own ceiling: 107 byte "
     "introduced names expand whole, 115 byte names are refused 900/1, 99 byte "
     "names expand. THE UNIT IS BYTES, not words -- see the correction above.",
     NG_DIAG_THE_FOUR_WORDS, NG_DIAG_PROMISES,
     "900 reason 1 is the same three words for the name table, the node table, "
     "the binding stack and the argument stack, so the code does not say which "
     "of the four ran out"},
    {"loop_cap", 512, "projected template items", 0, 512,
     NG_FUEL_BOUND_REACHABLE, 380, 2,
     "none at the declared fuel maximum: 511 items and 512 items expand whole "
     "and 513 is refused 380/2. AT THE SHAPE'S OWN 4096 FUEL the ceiling is "
     "511, not 512, and that is a fuel ceiling reported under this cap's name "
     "unless the budget is named. Two quantities, and the row says which.",
     NG_DIAG_THE_FOUR_WORDS, NG_DIAG_PROMISES,
     "reason 2 covers BOTH a count past this cap and a body that repeats more "
     "template items than the reference's table holds. The code still does not "
     "say which fired; since wave 23 out[10]/out[11] do, and this row's own arm "
     "publishes 513 against 512 while the sibling row publishes the same pair "
     "for a different declared bound"},
    {"walk_depth_cap", 64, "walk depth", 0, 0,
     NG_FUEL_BOUND_REACHABLE, 375, 9,
     "none. Measured by the triple in the body's own unit, which is NESTING "
     "LEVELS and not walk depth: 29 levels and 30 levels expand whole, 31 is "
     "refused 375/9. So entries stays 0 -- there is still no DERIVATION from "
     "levels to depth and there should not be one. WHAT CHANGED IN WAVE 23 IS "
     "NOT THE MAPPING BUT THE REFUSAL: the depth no longer has to be derived, "
     "because the refusal publishes it. out[10] is the walk depth that crossed "
     "the cap and out[11] is 64, measured 65 against 64 at 31 levels and 66 "
     "against 64 at 35. The published value is the depth AT WHICH THE REFUSAL "
     "FIRED, not the body's level count: `depth` is walk()'s own parameter and "
     "the guard hands that same value to the refusal, and no level count exists "
     "anywhere in the expander. The 65 is HAND-COMPUTED, not fitted -- the guard "
     "is `>` on a u64 against a literal 64, so 65 is the first value that can "
     "satisfy it at any body depth. The same control against the SHIPPED bytes "
     "fails with 0 and 0, which is what makes it a control and not a reading.",
     NG_DIAG_THE_FOUR_WORDS, NG_DIAG_PROMISES,
     "RETRACTED IN WAVE 23, and the retraction is the row's reason for "
     "changing: it used to read 'THE REFUSAL CARRIES NO DEPTH. A caller cannot "
     "tell whether the cap was crossed at 65 or at 200.' That was TRUE of the "
     "shipped bytes -- four words at every refusing site, and no field of Env "
     "holding the walk depth -- and it is false now. What is still missing is "
     "the DERIVATION from body levels to walk depth, and the SENTENCE: out is "
     "buf<u64>, so this is a number the caller renders"},
    {"parameter_cap", 8, "macro parameters", 0, 8,
     NG_FUEL_BOUND_REACHABLE, 372, 2,
     "none. Measured by the triple: 7 parameters and 8 parameters expand "
     "whole, 9 is refused 372/2. This is the one bound whose body parameter IS "
     "its declared unit, which is why its triple needs no conversion.",
     NG_DIAG_THE_FOUR_WORDS, NG_DIAG_PROMISES,
     "372 reason 2 covers an arity mismatch, a kind mismatch and a shape "
     "mismatch. The code still does not say which one it was; out[10]/out[11] "
     "publish this row's arm as 9 against 8, which is the arity one"},
    {"template_item_cap", 512, "top level items of one macro body", 0, 512,
     NG_FUEL_BOUND_REACHABLE, 380, 2,
     "none at this count: 510 and 511 expand whole, 512 are refused 380/2. It "
     "is the bound that answers where child_count used to stop walking at 1024 "
     "and report a truncated body as a success. NOT RE-MEASURED by the wave-21 "
     "campaign -- that campaign's list named seven bounds and this is the "
     "eighth -- so this row carries the status other arms measured and says so "
     "rather than carrying a number this lot did not take.",
     NG_DIAG_THE_FOUR_WORDS, NG_DIAG_PROMISES,
     "shares 380/2 with loop_cap, so a caller holding that code cannot tell "
     "which of the two fired"},

    /* THE DEAD ARM, and the reason this row exists at all.

       THE ARGUMENT, FROM THE BYTES, so a reader can re-run it:

         grep -n 'put_words(env,' compiler/nova/macros/macro_expand.nova

       returns EIGHT call sites, every one of them inside put_mark, and every
       one passing a LITERAL n: one call with n=1, four with n=2, three with
       n=6. The guard at macro_expand.nova:845 is `if n>24`. So the largest
       value any caller can pass is 6, and the cap is 24 -- unreachable by a
       factor of FOUR. put_words is not exported either: the module's only two
       `export fn` are expand and measure, so no external caller can supply a
       larger n from outside either. There is therefore no input, from any
       source, that reaches this guard. */
    {"put_words_bytes", 24, "bytes in one packed name word", 0, 6,
     NG_FUEL_BOUND_UNREACHABLE_CALLERS, 800, 2,
     "NO SHADOW, AND THAT IS THE DIFFERENCE FROM THE THREE ROWS ABOVE. Those "
     "refuse on a different quantity because another bound answers first; this "
     "one cannot refuse at all, because no caller can pass a value that reaches "
     "it. put_words is private, its eight call sites all live in put_mark and "
     "all pass a literal n in {1,2,6}, and the cap is 24. Re-run the grep in "
     "the comment above this row to check it; the entries figure is 6, the "
     "largest n any caller passes, and it is BELOW words by a factor of four.",
     NG_DIAG_THE_FOUR_WORDS, NG_DIAG_PROMISES,
     "NOTHING CAN BE OBSERVED HERE, and that is the row's whole content. There "
     "is no triple to run, no arm to measure and no input to drive: the guard "
     "is defence in depth on a private function, and the published out[10]/"
     "out[11] that wave 23 gave it are correct code on a path no production "
     "input reaches. Do not read this row as a bound that is merely hard to "
     "reach -- it is not measured-unreachable, it is unreachable by "
     "construction. NO TEST EXISTS FOR IT AND NONE CAN: driving it would mean "
     "exporting a private function to serve a check that could only ever pass "
     "on values no production path produces, which is a hole in a product "
     "surface shaped like a test. The checkable fact is the grep, and it is "
     "one line."},
};

NG_FUEL_UNUSED static const ng_bound_model *ng_fuel_bound(const char *name) {
  /* The lookup is by NAME and the table now holds all NINE rows, so a reader
     asking for a bound the previous four-row table did not carry gets a row
     instead of a null.  A null here means the name is a typo; it is not how
     "this one was never measured" is spelled, and it is NOT how either
     unreachable verdict is spelled -- those are rows, found by name, with
     their reasons in them. */
  for (unsigned i = 0; i < sizeof ng_fuel_bounds / sizeof ng_fuel_bounds[0];
       i++)
    if (!strcmp(name, ng_fuel_bounds[i].name)) return &ng_fuel_bounds[i];
  return 0;
}

#endif /* NG_NTASM_FUEL_MODEL_H */
