/* Gate for the A8 corpus fixed point: the seven pinned programs of
 * examples/ntasm-v0/c-bootstrap/ must assemble to byte identical objects from
 * the C producer and from the Nova producer, in both directions.
 *
 * WHAT THIS HARNESS IS NOT. It is not a restatement of the producer. Every
 * expectation on the Nova side is either the C reference bytes, or a refusal
 * the C reference also produced. Nothing here is transcribed from what the
 * Nova producer currently emits, so a regression in the producer turns this
 * gate red rather than silently rewriting the pin.
 *
 * THE TWO DIRECTIONS, which are different questions and are both asked.
 *   C_TO_NOVA: the C producer's object is read back with nt_object_read, fed to
 *     the C materializer, and the resulting image is compared against the Nova
 *     object. This asks whether the Nova object is a legal member of the format
 *     the C materializer accepts, independent of how the Nova producer spelled
 *     it.
 *   NOVA_TO_C: the Nova object's own bytes are written to a file, read back with
 *     nt_object_read, and rewritten with nt_object_write. The rewrite is
 *     compared to the original bytes. This asks whether the Nova object is in
 *     canonical form, again independent of the producer.
 *   OBJECT_PARITY: the C producer's serialized object bytes and the Nova
 *     producer's serialized object bytes compared directly, and the two PEs
 *     compared directly. This is the headline.
 *
 * A member converges only when the C builds it AND the Nova builds it AND the
 * two object byte streams are equal AND the two PE byte streams are equal. Any
 * member that does not converge is named with the measured cause: which side
 * refused, and with which code.
 *
 * THE BANNER IS NOT "THE CORPUS CONVERGES". One of the seven is still refused
 * by the Nova producer, for a reason measured and located in the tree, and a
 * failures=0 that leaves it refused would be a green overstating what is true.
 * It is therefore NAMED in the banner, listed in KNOWN_UNCONVERGED below, and
 * its set is asserted: a member that starts
 * refusing without being in that table, or one that leaves the table without
 * converging, turns this gate red. The table is a measured baseline, not a
 * licence. */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL %s\n", (m)); } } while (0)
/* Reports the corpus member alongside the expectation it belongs to. */
#define CHECKL(c, m, l) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL %s [%s]\n", (l), (m)); } } while (0)

#define OUTCAP 262144
#define MAXOBJ 65536
#define MAXPE 262144

/* The corpus members this gate lowers, AS LITERALS. An earlier version of this
 * comment claimed the list is "read from the tree rather than restated here as
 * literals" and that a member added to the corpus is therefore a member this
 * gate covers. Both halves were false: CORPUS is a literal array, this gate
 * never reads scripts/ntbuild.sh, and the only occurrence of the string
 * "ntbuild" in this file was inside that sentence. A comment that promises a
 * coupling the code does not have is the same defect as a citation that has
 * drifted, and it is corrected here rather than left to brief the next reader.
 *
 * WHY THIS LIST MAY BE SHORTER THAN THE PINNED CORPUS, which is a question
 * whoever adds a member here has to answer in this paragraph rather than
 * assume. The corpus grew a multi-module member, app.ntasm plus math.ntasm,
 * and it is deliberately NOT below. This gate drives one Nova entry,
 * x64_lower_nxo.build_function_bodies, over a single source file, and it has
 * not measured what that entry does with a two-module program with a real
 * import: the Nova producer names an unresolved import after its ALIAS while
 * the reference names it after its import PATH (api.echo against m.helper),
 * so a real multi-module member is where that disagreement would show, and it
 * is measured nowhere. Adding the literal before that is measured would turn a
 * gate that asks a real question into one that asserts an unmeasured answer.
 * Whoever adds it owes this paragraph a rewrite saying what was measured.
 *
 * The discipline the two lists in this file DO share is asserted rather than
 * claimed: see KNOWN_UNCONVERGED below, which the run compares against what
 * it actually saw refuse, in both directions.
 *
 * WHAT THIS LIST IS CALLED, decided 30 September 2026 by the lot that owns the
 * definition, which lives in scripts/ntbuild.sh under the heading
 * `THE DEFINITION OF "CORPUS"`. "Corpus" was one word with three referents in
 * three files and the counts disagreed because they counted different things.
 * The three names are: the PINNED CORPUS (RECORDED_EXAMPLES in
 * scripts/ntbuild.sh, 8 programs, one PE sha256 each), the COVERAGE CORPUS
 * (CORPUS[] below, 7 members, does the Nova producer converge) and the
 * BOUNDARY SHAPES (BOUNDARY[] further down, 14 rows, does it converge or refuse
 * for a given shape). This array is the second of the three. It is a deliberate
 * SUBSET of the first and is never edited to match it; the paragraph above says
 * which member it omits and why.
 */
static const char *CORPUS[] = {
    "return42", "return43", "returnmax", "helper-first",
    "static-data", "mutable-data", "comptime-macro"
};
static const char *DIR = "examples/ntasm-v0/c-bootstrap/";

/* The members the Nova producer still refuses, with the measured cause of each
 * refusal. This list is ASSERTED, not read: corpus_member records what it
 * actually saw refuse and the run compares the two sets, so the list cannot
 * quietly fall out of date in either direction. It is a statement of a known
 * gap with its location, which is what makes failures=0 honest.
 *
 *   helper-first   the C reference builds it (1184 byte object, 3072 byte PE,
 *                  PE digest identical to the pin at scripts/ntbuild.sh) and
 *                  the Nova producer refuses with 800. It is NOT one refusal
 *                  in one producer: mode 4, the framed profile, answers 800
 *                  for this member as well, and it is not a fallback -- it
 *                  answers 800 for return42, return43, returnmax and
 *                  comptime-macro too, and only for static-data and
 *                  mutable-data does it answer 0.
 *
 *                  WHERE THE 800 COMES FROM, on the frameless route, which is
 *                  the only route this member can reach. The site is
 *                  x64_lower_nxo.nova:1902, the sole delegation to the
 *                  framed producer and it fires on "the section declares a
 *                  parameter" or "the module has a data section". This member
 *                  has neither, so it is
 *                  always lowered by the frameless word-record path, where
 *                  layout_body sends every return through return_immediate and
 *                  x64_lower_nxo.nova:588 refuses an operand constant_eval
 *                  cannot fold. `helper()+40` holds a call, so that is the
 *                  refusal.
 *
 *                  A RETRACTION, left in place. The previous text of this entry
 *                  said the cause was the `value.kind!=94` test in layout_body
 *                  and that a return operand had to be a bare integer literal.
 *                  That is STALE, and it was wrong in a way that would have
 *                  sent the next reader to the wrong line: the fold at
 *                  x64_lower_nxo.nova:587
 *                  exists, and `return 2+40` builds, 768 bytes, byte identical
 *                  to the C reference. x64_lower_nxo.nova:588 is the live
 *                  line, and the shape is "a return operand constant_eval
 *                  cannot fold", which is wider
 *                  than a literal and wider than a call.
 *
 *                  THE CAUSE IS NOT A CALLEE, and not a two-function section.
 *                  Measured 29 September 2026 on copies, each built by this
 *                  file's own harness: the same source with `return 42` in main
 *                  builds, callee and all, 768 bytes, byte identical; with the
 *                  callee deleted it builds, 512 bytes, byte identical.
 *
 *                  THE CLASS IS WIDER THAN A CALL, and this is the part that
 *                  matters for what the corpus does not cover. Measured, each
 *                  of these refuses with 800 on its own with NO call anywhere
 *                  in the source: `let x:u64=2` then `return 42`; the same
 *                  `let` then `return x`; `mov rax,2` then `return rax`. So
 *                  `let` is independently fatal and a return of a name is
 *                  independently fatal. The class is: a parameterless,
 *                  data-free function whose body is anything other than a
 *                  single return of a foldable constant.
 *
 *                  THAT CLASS HAS A SECOND FACE, AND IT IS WORSE THAN A
 *                  REFUSAL. A copy of this member with `mov rax,2` added
 *                  before `return 42`, still no data section, does not refuse:
 *                  it DIVERGES. C builds 1120 bytes with a framed main --
 *                  pushf, thirteen pushes, sub rsp, the snapshot stores, call,
 *                  add, epilogue -- and the frameless producer builds 768
 *                  bytes and 32 bytes of .text with no frame at all. The
 *                  instruction is not dropped, since changing the immediate
 *                  changes the object; the FRAME is missing. So on one shape
 *                  this producer refuses and on the next it emits code the
 *                  reference would never emit, and NO MEMBER OF THIS CORPUS
 *                  SITS ON THE SECOND SHAPE. A corpus of seven members that
 *                  all converge says what those seven do and nothing about the
 *                  shape they share.
 *
 *                  FIX SHAPE, three parts, and NOT one site. (1) Widen the
 *                  delegation at x64_lower_nxo.nova:1902 so a source whose
 *                  functions would not take codegen's raw-entry shortcut also
 *                  reaches the framed producer; that predicate already exists,
 *                  parameterless_takes_shortcut at x64_lower_nxo.nova:3544.
 *                  (2) Make x64_lower_nxo.nova:3677 emit
 *                  the raw-entry body rather than drop the function, which is
 *                  `mov rax,imm64; ret`, exactly the 11 bytes the reference
 *                  emits for `helper`. (3) Lower a call as the left operand of
 *                  an arithmetic expression in scan_expression, whose aux==40
 *                  arm today requires a qualified name node. The framed
 *                  profile refuses this member today for (2) and (3) as well.
 *                  Fixing the frameless return alone would make this member
 *                  converge with wrong bytes, which is the state this banner
 *                  exists to prevent.
 *
 *   comptime-macro NOT A GAP ANY MORE, kept here because the entry was written
 *                  when it was one and the table above is asserted in BOTH
 *                  directions: leaving a paragraph for a member that converges
 *                  invites the next reader to add it back to the array, and
 *                  doing so turns this gate red. The history, kept because it
 *                  is the shape of the last one of these: the cause was the
 *                  top level declaration walk of x64_lower_nxo.nova refusing
 *                  anything but module, target and section, and the fix was to
 *                  accept and discard a top level comptime block and a top
 *                  level macro definition, and then to expand `expand
 *                  NAME(args)` in a body. It builds today, 512 bytes, byte
 *                  identical to the C reference. What is not established here
 *                  is WHICH of those two parts closed it, and a reader should
 *                  not assume the first one did.
 *
 *   helper-first NOT A GAP ANY MORE, and the fix was THREE parts, not one.
 *                  The same paragraph, kept for the same reason comptime-macro
 *                  is kept, and with the measured boundary of the class stated
 *                  here rather than left to the next reader to rediscover.
 *
 *                  WHAT CLOSED IT, and the order is the answer to "which of the
 *                  three causes was the real one". Measured 30 September 2026,
 *                  each part alone, on copies, through this file's own harness:
 *
 *                    (1) the framed path DROPPING a parameterless function
 *                        whose body takes the raw entry shortcut
 *                        (x64_lower_nxo.nova, collect_frame_signature). Alone
 *                        it closes nothing and converges nothing: the callee
 *                        of `return helper()+40` is `return 2`, so this part is
 *                        what makes the framed producer ABLE to hold a unit
 *                        with a second function at all. With it alone, the
 *                        member still answers 800.
 *                    (2) the DELEGATION, which sent the source to the frameless
 *                        producer because it fired only on "declares a
 *                        parameter OR has a data section". Alone it moves the
 *                        member from one 800 to another 800, on the other
 *                        path. With (1) and (2) and no third part, the member
 *                        CONVERGES WITH WRONG BYTES -- which is why the third
 *                        part is not optional and why "fix the return" was
 *                        never going to be a green.
 *                    (3) the BINARY EXPRESSION: statement_class refused a
 *                        return whose expression is not a literal, a name or a
 *                        call, and the emitters had no arm for one. This is the
 *                        part that decides the lot, because (1) and (2) alone
 * *                        leave the member building an object whose bytes the
 *                        reference would never have emitted.
 *
 *                  SO NONE OF THE THREE MOVED ALONE, and the honest statement
 *                  is that they are one change: (2) is what routes the member,
 *                  (1) is what lets the route hold it, and (3) is what makes
 *                  the bytes the reference's. A lot that fixed (3) alone would
 *                  have converged nothing, because the member never reaches the
 *                  expression emitter.
 *
 *                  THE CLASS, and the part of it that is STILL refused, because
 *                  a closed member is not a closed class and the two are easy
 *                  to confuse. What is now covered, measured: a section that
 *                  declares a function BESIDE the entry, with a call site and
 *                  its REL32 relocation, symbol order across two functions, a
 *                  callee on the raw entry shortcut, frame construction for the
 *                  entry, and a consumer of the call's result. That is the
 *                  class the corpus never exercised, and helper-first was its
 *                  only member, so six converging members proved nothing about
 *                  it until now.
 *
 *                  What the class turned out to be WIDER than the brief, and
 *                  this is measured on the same copies, not inferred. The
 *                  shapes the previous paragraph called fatal on their own --
 *                  `let x:u64=2` then `return 42`, the same `let` then
 *                  `return x`, and `let x:u64=helper()` then `return x` --
 *                  were each refused with 800 before this change and each
 *                  CONVERGES BYTE IDENTICAL now (1456 and 1424 byte objects,
 *                  3584 byte PEs, equal on both sides). They were not refused
 *                  by anything specific to a `let`: they were refused because
 *                  the framed path could not hold a unit with a second
 *                  function, and a `let` makes the entry a framed body even
 *                  when it holds no call at all. So the class was never "a
 *                  call"; it was "a parameterless, data-free body the
 *                  reference FRAMES", and a `let` is one.
 *
 *                  What is still refused, each measured the same way, with the
 *                  C reference on one side and the producer on the other:
 *                    - a bare `helper()` as a STATEMENT. Both sides refuse, and
 *                      the reference's own answer is 200 "expected expression":
 *                      this is not a shape the product owes, not a gap here.
 *                    - `mov rax,2` then `return rax`, and `mov rax,2` then
 *                      `return 42`, with the empty clobber set. The reference
 *                      refuses both with 502, an inferred clobber the function
 *                      does not declare, so again a shape the product does not
 *                      owe. Note what that means for a number quoted earlier
 *                      about a "mov" body that DIVERGES: the divergence needed
 *                      a `clobbers {rax}` to exist at all, and the shape as
 *                      written in the corpus is one the reference refuses.
 *                    - a call naming a function the section does not declare.
 *                      The reference refuses with 301, the producer with 800.
 *                    - the binary arm covers +, -, &, | and ^ only. *, /, %,
 *                      << and >> are refused, because their register forms are
 *                      not the group opcode x64_fixed already encodes: imul is
 *                      the two operand 0f af form, a shift moves the amount
 *                      into rcx, and a divide emits cqo or xor first.
 *                    - a binary whose operand is a variable of a width below
 *                      64 bits is refused, because the reference normalises the
 *                      RESULT to the expression's declared type and the parser
 *                      records no type on an expression node.
 *                    - a machine instruction in a parameterless body whose
 *                      clobber set is empty is still refused. That one predates
 *                      this change and is unchanged by it.
 *
 *                  WHAT IS NOT ESTABLISHED, superseded on 30 September 2026
 *                  and kept so the next reader sees the sentence that was
 *                  there: "a callee WITH PARAMETERS. No member of this corpus
 *                  declares one, the c-bootstrap-multi corpus is pinned
 *                  against the C producer alone, and this change was measured
 *                  over parameterless functions only."
 *
 *                  THAT SENTENCE WAS TRUE AND IT IS NOW MEASURED, twice over,
 *                  and the answer is not the one it asked for. A callee with
 *                  parameters converges -- `fn helper(in a:u64 @rcx,in
 *                  b:u64 @rdx)` called as `return helper(21,21)` builds 1584
 *                  byte objects on both sides, byte identical, and so does the
 *                  one-parameter and the zero-parameter form beside it. What
 *                  does NOT converge is a callee marked `export`, at every
 *                  arity: the same source with `export fn helper(...)`
 *                  instead of `fn helper(...)` is refused 800, and the C
 *                  reference builds the SAME number of bytes either way, so
 *                  the reference does not see the difference and the producer
 *                  does. Measured with one keyword moved and equal-length
 *                  module names; see BOUNDARY below, which asserts every one of
 *                  these so none of it can change silently. */
static const char *KNOWN_UNCONVERGED[] = {NULL};
/* The count of entries that are not the NULL terminator. A zero length array is
 * not portable C and a table holding one NULL is not an empty table, so the
 * emptiness is expressed as a terminator and counted here. */
static unsigned known_unconverged_count(void)
{
    unsigned n = 0;
    while (KNOWN_UNCONVERGED[n]) n++;
    return n;
}

static char unconverged[16][64];
static unsigned unconverged_count;

/* ============================ THE SECOND CORPUS ============================
 *
 * WHY A SECOND LIST AND NOT A WIDENED FIRST. `converged=7 of 7` is a number
 * the register and several reports already carry, and it means something
 * precise about the seven pinned members of examples/ntasm-v0/c-bootstrap/.
 * Adding members here would change what that number means for every record of
 * it. So these are a second corpus with its own pins and its own count, and
 * they are NOT added to scripts/ntbuild.sh either: that file pins corpus
 * MEMBERS, programs the C producer builds through the CLI, and these are not
 * members of it. They live here, in the gate that asks the question about
 * them, and the seven are untouched.
 *
 * WHY THIS IS NOT A SECOND CONVENTION, which is the objection this paragraph
 * owes an answer rather than a reassurance. The convention this file already
 * has is: a list of things to lower, a driver that lowers one, memcmp against
 * the C reference, and a table of what must happen that the run compares
 * against what it actually saw, in BOTH directions. This adds a second list to
 * the first two and reuses the third and the fourth without changing either.
 * What would be a second convention is a second DRIVER, a second comparison,
 * or a second assertion style, and none of those is added: the function below
 * is corpus_member's three directions and its two-directions assertion, and it
 * calls the same run_nova, the same c_object and the same compare.
 *
 * WHAT A COUNT AT ZERO GAPS IS. Every entry here is either a convergence or a
 * refusal with a named code, and `failures=0` therefore does NOT mean the
 * producer handles calls, imports and framed bodies. It means the rows in this
 * table still do what this table says, and nothing at all about any shape not
 * in it. The banner prints the table's size next to the count for exactly that
 * reason: a number whose scope is not stated is a number about an unbounded
 * set, and this project has been bitten by that shape before.
 *
 * `nova` is the expectation: 0 means the two producers' object bytes must be
 * equal, and any other value is the exact refusal code the producer must still
 * answer. A shape the C reference builds and the producer refuses is not a
 * shape the product owes, but it IS a coverage edge, and a table that records
 * only the successes cannot say where the edge is.
 *
 * `c_object` and `c_pe` are ASSERTED against the C reference on every run.
 * They are what makes this table falsifiable in the direction that matters: a
 * row whose source has stopped meaning what it meant turns this gate red
 * instead of continuing to report a verdict about a shape that has moved.
 *
 * Exactly one of `path` and `source` is non-NULL per row, and the run asserts
 * that. A row with both is ambiguous and a row with neither is empty; both are
 * red, because a table entry that can be read two ways is a table entry that
 * will be read the wrong way. */
typedef struct {
    const char *name;
    const char *dir;      /* the corpus directory the C reference is given */
    const char *path;     /* file name under `dir`, or NULL */
    const char *source;   /* the source as a literal, or NULL */
    unsigned long c_object;
    unsigned long c_pe;
    uint64_t nova;        /* 0 = must converge byte identical, else the code */
    /* `nova_was` is the WIDENING RECORD: the refusal code this row used to be
     * pinned at, and 0 for a row that was never pinned as a refusal.
     *
     * It exists because the two facts a MOVED row has to carry do not fit in
     * one column. `nova` alone can hold either and not both: leave it at 800
     * and boundary_row takes the refusal path, which compares the CODE and
     * emits no bytes, so the gate never runs a byte comparison on a shape the
     * producer now builds; move it to 0 and the comparison runs, but the fact
     * that this row used to be a refusal is no longer in the file at all. The
     * column that records the widening is therefore NOT the expectation --
     * the expectation must follow the measurement -- but a second column
     * beside it, which must not.
     *
     * Zero is "no recorded widening", not "used to converge", and the
     * distinction is carried by the assertion in main rather than by a second
     * sentinel: a row may only widen FROM a refusal, so `nova_was != 0`
     * requires `nova == 0`. A row that recorded where it came from while still
     * refusing would be asserting a history the run cannot corroborate, since a
     * refusal emits no bytes. */
    uint64_t nova_was;
} Boundary;


static const Boundary BOUNDARY[] = {
    /* ---- the framed-body class: a parameterless, data-free body the
     * reference FRAMES. These three were all refused with 800 before the
     * framed path could hold a unit with a second function, and a `let` makes
     * the entry a framed body even when it holds no call at all. */
    { "framed_let_const", "examples/ntasm-v0/c-bootstrap/", NULL,
      "module boundary.let_const\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "    export fn main()->u64\n    effects {}\n    clobbers {rax} {\n"
      "        let x:u64=2\n        return 42\n    }\n}\n",
      1168, 3584, 0, 0 },
    { "framed_let_name", "examples/ntasm-v0/c-bootstrap/", NULL,
      "module boundary.let_name\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "    export fn main()->u64\n    effects {}\n    clobbers {rax} {\n"
      "        let x:u64=2\n        return x\n    }\n}\n",
      1152, 3584, 0, 0 },
    { "framed_let_call", "examples/ntasm-v0/c-bootstrap/", NULL,
      "module boundary.let_call\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "    fn helper()->u64\n    effects {}\n    clobbers {} {\n        return 2\n    }\n"
      "    export fn main()->u64\n    effects {}\n    clobbers {rax} {\n"
      "        let x:u64=helper()\n        return x\n    }\n}\n",
      1456, 3584, 0, 0 },

    /* ---- calls, PRIVATE callee. Converge, at every arity measured here. This
     * is the first measurement in this project of a call with ARGUMENTS, and
     * it is the answer to the sentence the header used to carry: a callee with
     * parameters is not the gap. */
    { "call_private_arity0", "examples/ntasm-v0/c-bootstrap/", NULL,
      "module expt.a0_private\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "    fn helper()->u64\n    effects {}\n    clobbers {} {\n        return 2\n    }\n"
      "    export fn main()->u64\n    effects {}\n    clobbers {rax} {\n"
      "        return helper()\n    }\n}\n",
      1136, 3072, 0, 0 },
    { "call_private_arity2", "examples/ntasm-v0/c-bootstrap/", NULL,
      "module expt.a2_private\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "    fn helper(in a:u64 @rcx,in b:u64 @rdx)->u64\n    effects {}\n    clobbers {} {\n"
      "        return a+b\n    }\n"
      "    export fn main()->u64\n    effects {}\n    clobbers {rax} {\n"
      "        return helper(21,21)\n    }\n}\n",
      1584, 3584, 0, 0 },

    /* ---- calls, EXPORTED callee. THE FINDING. One keyword is the only
     * difference between call_private_arity2 above and call_exported_arity2
     * below: same parameters, same body, same call site, same operator, and
     * the C reference builds the SAME 1584 bytes for both. The producer
     * converges on one and answers 800 on the other, and the two module names
     * are the same length so a name cannot be the cause either. Every
     * converging call in this project to date -- helper-first, and everything
     * measured alongside it -- has a PRIVATE callee, so these rows are the
     * first thing that says the class has an edge at all. */
    { "call_exported_arity0", "examples/ntasm-v0/c-bootstrap/", NULL,
      "module expt.b0_exported\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "    export fn helper()->u64\n    effects {}\n    clobbers {} {\n        return 2\n    }\n"
      "    export fn main()->u64\n    effects {}\n    clobbers {rax} {\n"
      "        return helper()\n    }\n}\n",
      1136, 3072, 800, 0 },
    { "call_exported_arity2", "examples/ntasm-v0/c-bootstrap/", NULL,
      "module expt.b2_exported\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "    export fn helper(in a:u64 @rcx,in b:u64 @rdx)->u64\n    effects {}\n    clobbers {} {\n"
      "        return a+b\n    }\n"
      "    export fn main()->u64\n    effects {}\n    clobbers {rax} {\n"
      "        return helper(21,21)\n    }\n}\n",
      1584, 3584, 800, 0 },
    /* and the clobber set is not the cause: dropping main's `clobbers {rax}`
     * leaves the refusal standing and the reference still builds it */
    { "call_exported_arity2_noclobber", "examples/ntasm-v0/c-bootstrap/", NULL,
      "module expt.c2_exported_noclobber\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "    export fn helper(in a:u64 @rcx,in b:u64 @rdx)->u64\n    effects {}\n    clobbers {} {\n"
      "        return a+b\n    }\n"
      "    export fn main()->u64\n    effects {}\n    clobbers {} {\n"
      "        return helper(21,21)\n    }\n}\n",
      1600, 3584, 800, 0 },

    /* ---- a PRIVATE three-parameter callee as the left operand of a binary:
     * refused, while the one- and two-parameter forms of the same shape
     * converge. This is a SECOND edge and it is not the export edge, so the
     * two are recorded as two rows rather than merged into one claim. That a
     * fourth incoming register is the cause is NOT excluded by this
     * measurement, and is not asserted here either. */
    { "call_private_arity3_operand", "examples/ntasm-v0/c-bootstrap/", NULL,
      "module ladder.operand_arity_3\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "    fn helper(in a:u64 @rcx,in b:u64 @rdx,in c:u64 @r8)->u64\n    effects {}\n"
      "    clobbers {} {\n        return a+b+c\n    }\n"
      "    export fn main()->u64\n    effects {}\n    clobbers {rax} {\n"
      "        return helper(1,2,3)+0\n    }\n}\n",
      1712, 3584, 800, 0 },

    /* ---- the two-unit call, WRITTEN AS A STATEMENT. Every converging call
     * above reaches its callee as an EXPRESSION: `return helper()`, or a `let`
     * initialised from one. This row is the same two units in one file with
     * the same private callee, and the only difference is that the call is
     * its own statement followed by a `return`. It converges, 1440 object
     * bytes against the reference's 1440, identical on both sides.
     *
     * WHY IT IS HERE, because the answer it gives is the one the import rows
     * below used to give. Those two rows are refusal rows, and both carry an
     * import, so the table said -- for two members and no measurement
     * otherwise -- that a program calling a unit it does not declare is what
     * the producer cannot do. That reading is wrong, and this row is what
     * makes it wrong in the table rather than in a report: a program calling a
     * unit it does declare, in the same file, converges. The capability the
     * import rows are about is joining a unit declared ELSEWHERE, and nothing
     * in these two rows was ever about calling one.
     *
     * A member of `examples/ntasm-v0/c-bootstrap/` rather than a literal in
     * this table, so that a reader can open the program the row is about; and
     * the callee is PRIVATE, so the row is not silently the exported-callee
     * refusal three rows above wearing a different name. */
    { "call_private_stmt_body", "examples/ntasm-v0/c-bootstrap/",
      "call-private-stmt.ntasm", NULL, 1440, 3584, 0, 0 },

    /* ---- the IMPORTED callee. Read from disk rather than copied here,
     * because it is a pinned corpus member and a literal copy would be a
     * second version of a file scripts/ntbuild.sh already pins. The C
     * reference builds it, 1168 bytes, naming the unresolved import after its
     * PATH; the producer refuses 374, whose stated meaning is "capture of a
     * symbol of the caller".
     *
     * That message is not merely misapplied here, it is UNSTATEABLE on the
     * path that fires it, and that is a stronger finding than a wrong wording.
     * The predicate the message names is a walk over the caller's
     * declarations, and its list of declaration kinds is constants, data,
     * functions and parameters. The expander has no constant for an import at
     * all -- `grep -n "k_import" compiler/nova/macros/macro_expand.nova`
     * returns nothing -- so a kind-9 import node falls through both arms of
     * that walk and matches no spelling in it. The walk cannot encounter the
     * thing it is named for. `grep -n 374 compiler/nova/macros/macro_expand.nova`
     * returns the diagnostic's own comment and the one `fail` that raises it,
     * the latter inside `fn resolve_name`, which fires when a name in a
     * template position is not a macro parameter and not a comptime binding.
     * The honest description of this refusal is: the template names `add`, the
     * product has no notion of a name arriving from another unit, and there is
     * no other outcome to return.
     *
     * So the refusal is NOT reached through the call at all, and it is not
     * reached because of anything this row's shape does. */
    { "imported_callee_macro", "examples/ntasm-v0/c-bootstrap-multi/",
      "app.ntasm", NULL, 1168, 3072, 374, 0 },

    /* ---- THE SAME IMPORT WITH NO CALL ANYWHERE. This is the row that answers
     * "is the product unable to join units, or is the entry?", and it is here
     * because the answer is not the one the row above suggests.
     *
     * imported_callee_macro is refused 374, "capture of a caller symbol", which
     * reads like a macro problem and is not one: it is the FIRST wall, and it
     * hides the second. Rewrite the macro body to `return 21+21` and the call
     * disappears entirely -- no call, no capture, no reference to `add` in the
     * body at all -- and the refusal becomes 800, while the C reference builds
     * the member and still names the unresolved import after its PATH. So the
     * import is refused IN ITS OWN RIGHT, on a source that never calls
     * anything. What the two rows together establish is narrower than "a
     * capability the product does not have" and narrower than "a capability it
     * has"; both of those have been carried in this file and in three briefs,
     * and both are wrong. What is measured:
     *
     *   - An import-aware producer EXISTS. `x64_lower_nova` carries one, and
     *     its own gate is green. It is not a fiction.
     *   - It converges ONE shape, and that shape is one the C reference
     *     REFUSES, so it produces nothing useful. Measured: the import
     *     producer builds the call-then-bare-ret spelling and answers 800 on
     *     every spelling the reference builds, including a single import the
     *     reference builds at 1408 bytes.
     *   - NO PRODUCTION PATH REACHES IT. The only callers of its two exported
     *     entry points are two test entries and `x64_lower_nxo_pe.build`,
     *     which is itself reached only from a test entry. The general
     *     producer's own top-level walk refuses a kind-9 import before any
     *     body is enumerated, so control cannot reach the import-aware code
     *     from the entry the project converges on.
     *   - The CONTRACT is not missing. Where the import producer does emit an
     *     import symbol, its name is the dotted PATH and not the alias, its
     *     flags are import|function, and its contract text is the imported
     *     declaration's own -- all three read out of the reference and
     *     identical, the only differences being the caller's size and the
     *     relocation offset, which are what the body spelling changes.
     *
     * The two rows below are therefore REFUSAL rows and the text above is not
     * to be read as a claim that an import lowers. A reader who takes the
     * existence of the producer as the capability would be wrong in the
     * direction that costs the most, because the gate checks convergence and
     * not existence, and a green gate beside a row that reads "implemented"
     * would be believed.
     *
     * Two further facts, both measured. First, the ENTRY takes one source
     * buffer, so two whole programs concatenated, each of which builds alone,
     * are refused 800: a two-MODULE corpus has no way to reach the producer
     * through this gate. That is a statement about two modules, and it is not
     * a statement about two UNITS, which is what `call_private_stmt_body`
     * above measures and converges. Second, the reference will not even build
     * an import followed directly by `section` -- it answers 200 "expected
     * 'effects'" -- so a one-module member carrying an import is only
     * expressible in the comptime-and-macro form this row uses.
     *
     * So the import is refused on every path this table can drive, and that is
     * the whole of the claim: a corpus here would be a corpus of refusals
     * wearing a heading about multi-module coverage, which is worse than no
     * corpus, and the reason this table pins these two refusals instead. It is
     * NOT the claim that the import is unreachable in the producer, which is a
     * separate fact with a separate answer -- see the paragraph above. */
    { "imported_module_no_call", "examples/ntasm-v0/c-bootstrap-multi/", NULL,
      "module app\ntarget x86_64-nexora-uefi\n"
      "comptime(fuel=16,call_depth=4,arena_bytes=262144,ast_nodes=256,expansion_depth=4,constant_bytes=64) {\n"
      "    return (5+3)*4;\n}\n"
      "import math.add as add: fn(in a:u64 @rcx,in b:u64 @rdx)->u64\n"
      "effects {}\nclobbers {}\n"
      "macro twice_plus(v:ast.expr)->ast.stmt {\n"
      "    return quote(stmt) { return 21+21; };\n}\n"
      "section .text {\n    export fn main()->u64\n    effects {}\n    clobbers {rax} {\n"
      "        expand twice_plus(21)\n    }\n}\n",
      736, 3072, 800, 0 },

    /* ==================== THE CLASS THE SEVEN NEVER REACHED ====================
     *
     * THE ENUMERATION, printed before the conclusion and checkable by reading
     * the seven files rather than by taking this paragraph's word for it. Each
     * row is one member of CORPUS; the columns are the ones the conclusion
     * rests on, and "one return" counts RETURNS IN THE BODY AS THE PRODUCER
     * SEES IT, so comptime_macro is counted after its macro is expanded.
     *
     *   member            sections  fns  non-entry fn  branches  returns in
     *                                       declared             the entry
     *   return42            1      1        0          0           1
     *   return43            1      1        0          0           1
     *   returnmax           1      1        0          0           1
     *   helper-first        1      2        1          0           1
     *   static-data         2      1        0          0           1
     *   mutable-data        2      1        0          0           1
     *   comptime-macro      1      1        0          0           1
     *
     * The last column is the one that matters, and it is the one the seventh
     * member did not change. The description the seven used to carry was
     * "one function, and it is the entry"; helper-first destroyed that, and
     * what replaced it is NOT "two functions": counting functions is the
     * question the seventh member answered, so the property that survived it
     * is the one it also happens to satisfy. Every one of the seven, macro
     * expanded, is STRAIGHT LINE WITH ONE EXIT -- no if, no label, no jmp, no
     * loop, and exactly one `return`, which is also the last statement of the
     * body. That is the property, and it is a property of CONTROL FLOW, which
     * is a different thing from a property of declarations.
     *
     * Two further columns would also have come out uniform, and are recorded
     * so that the row below is not mistaken for the first probe of them: the
     * entry takes NO PARAMETERS in all seven, and five of the seven have no
     * data section. The row below is deliberately built to preserve both, so
     * that the branch is the ONLY difference between it and return42 -- a
     * single-variable experiment against a member this table already measures.
     * Had it also added a parameter or a data section it would have changed
     * two things and proved nothing about either.
     *
     * WHAT IS EXPECTED, AND WHEN IT WAS WRITTEN. The paragraph above and this
     * one were written BEFORE the row was ever run through this gate, and the
     * expectation is stated here rather than inferred afterwards from whatever
     * the producer happened to answer:
     *
     *   EXPECTED: the C reference BUILDS the member, and the Nova producer
     *   REFUSES it with 800.
     *
     * >>> THIS PREDICTION WAS WRONG. It is left exactly as it was written, and
     * >>> the member CONVERGES byte identical. Read THE MEASUREMENT below
     * >>> before reading this. Do not shorten this paragraph to match the
     * >>> result: a pre-registered expectation edited into agreement is not a
     * >>> test afterwards, and this one is the only record that the reasoning
     * >>> above was wrong rather than merely unused.
     *
     * The reason is in the file's own header: the framed producer is reached
     * only when the section declares a parameter or the module has a data
     * section, and this member has neither, so it lands on the frameless
     * word-record path, where layout_body routes every return through
     * return_immediate. A body with two returns has no single word record to
     * route, so 800 is the prediction and the alternative -- an object that
     * silently keeps one arm -- is worse and is exactly what the byte
     * comparison below exists to catch.
     *
     * WHICH SIDE A FAILURE WOULD BE ON, stated before the run for the same
     * reason. NOT this gate's, and not the table's. This row transcribes no
     * Nova-side expectation beyond the recorded refusal code: the object the
     * producer is compared against is built by nt_object_compile from this
     * row's own source AT RUN TIME, so a divergence between them is a fact
     * about the two producers and not about a table that could be wrong in
     * the producer's favour. The four outcomes separate as:
     *   - C builds, Nova refuses  -> the product cannot do this. Expected.
     *   - C builds, Nova builds, bytes differ -> THE PRODUCT IS WRONG, and
     *     compare() below names the first differing offset. The gate goes red
     *     and the red is the finding.
     *   - C builds, Nova builds, bytes equal -> the class is covered.
     *   - C refuses -> neither producer is at fault; the reference language
     *     does not have this shape on this target. The gate is red, and that
     *     red is the gate's own, because the row promised a reference build.
     * So the anti-vacuity answer is: on the expected outcome the lot's value
     * is a located edge, and on the only outcome that would make the gate
     * itself wrong, the gate says so instead of passing.
     *
     * ============================ THE MEASUREMENT ============================
     *
     * THE PREDICTION WAS WRONG. The member CONVERGES, byte identical, and the
     * difference between what was written above and what the gate measured is
     * the finding. Nothing below is written to soften it, and the expectation
     * is left in the file exactly as it was written rather than edited into
     * agreement, because an expectation edited into agreement is not a test
     * afterwards.
     *
     *   expected   the reference builds, the producer answers 800
     *   measured   the reference builds; the producer answers 0; and the two
     *              object streams are EQUAL -- 1520 bytes each, both
     *              sha256 866408105946f00ede0bf3c90d0d129c5ff56ff505a00646c
     *              eafc048d8d9e963 -- and the two PE streams are equal at
     *              3584 bytes, both sha256 1af76e82545b4f39885043184b17bc65
     *              ca703c6bf7ebe33b818151b4f8226026. All three directions ran:
     * C_TO_NOVA, NOVA_TO_C and PARITY. The producer does not silently drop an
     * arm, which was the worse of the two outcomes the prediction named.
     *
     * WHY THE PREDICTION FAILED, which is the part worth keeping. It is not
     * that the producer is more capable than the reasoning assumed: the
     * condition is a LITERAL, and the reference folds it in its own front end
     * before anything is lowered. So the body that reaches the producer has
     * ONE return, not two, and the frameless word-record path was never asked
     * the question the prediction asked it. The prediction was a statement
     * about a body with two returns; the member is a body with one return and
     * a dead arm.
     *
     * SO WHAT IS AND IS NOT COVERED BY THIS ROW, stated as scope because the
     * number is otherwise about an unbounded set. Covered from this date: a
     * parameterless, data-free, single-function entry whose body is an if/else
     * whose condition the front end can fold. NOT covered, and not addressed by
     * this row in any way: an if/else whose condition is computed at run time,
     * which is the shape that actually reaches the word-record path with two
     * live returns. Reaching it needs either a parameter -- and a parameter on
     * the section is what this file's own header names as the condition for
     * delegating to the framed producer -- or a bool local, and a `let` makes
     * the entry a framed body. So the residue sits on the FRAMED path, which is
     * the path another lot was repairing while this row was measured, and
     * taking it now would have meant reporting a number about their repair.
     * That member is the next one to write, on a green tree, and this row is
     * deliberately not it.
     *
     * A NOTE ON THE FIRST MEASUREMENT, because a number that moved between two
     * runs of the same file is a fact about the tree and not about the member,
     * and it is the reason this row's pin was not fixed on the first run. The
     * first run of this row answered 800 -- the prediction. That run was taken
     * at 05:00 on a tree where framed_let_const, framed_let_name,
     * framed_let_call and call_private_arity0 had all moved off their pinned
     * convergence, so the tree was demonstrably not in the state this table
     * describes. Those four are all FRAMED-class members -- each carries a
     * `let` or a call -- and this row carries none of those, so the repair was
     * argued not to be on its path. That argument was WRONG in its conclusion,
     * which is the useful part: the refusal was an artefact of a tree being
     * repaired, and pinning 800 on it would have written a green gate that
     * meant nothing. The tree closed at 05:05 and the same binary, unmodified,
     * on the same source, answers 0. So the 800 was never a property of this
     * member and the row's pin waited for a tree where nothing else had moved.
     *
     * The reference's own numbers -- 1520 bytes, a 3584 byte PE, the digest
     * printed beside the row on every run -- were the same in both runs, and
     * the reference is C, which nobody in this lot's path was editing. That is
     * the one measurement here that needed no green tree, and it is why the
     * C-side pin was fixed before the Nova-side pin was.
     *
     * THE OTHER WAY THE PREDICTION WAS WRONG, kept because a pre-registered
     * expectation that only ever gets confirmed is not a test. It was also
     * wrong about the member itself: the first version of this row's condition
     * was `1 < 2`, and the C reference REFUSES that with 401. See
     * examples/ntasm-v0/c-bootstrap-controlflow/README.md, which keeps the
     * refused source on disk and states what was found: the product accepts a
     * shape the reference refuses, which is the opposite direction from every
     * other divergence measured in this project, and which no byte-parity gate
     * in this tree can see. So the prediction was wrong twice, once about the
     * reference and once about the producer, and the two errors had nothing to
     * do with each other.
     *
     * Read from disk rather than copied inline, for the reason
     * imported_callee_macro gives: a literal here would be a second version
     * of a file, and a corpus member that exists only inside a C array is a
     * member no reader can open. */
    { "branching_entry", "examples/ntasm-v0/c-bootstrap-controlflow/",
      "branching-entry.ntasm", NULL, 1520, 3584, 0, 0 },

    /* ================ THE MEMBER branching_entry NAMED AND DID NOT WRITE ====
     *
     * WHAT THIS ROW IS, in one line: the shape the row above says it is not.
     * An if/else whose condition is computed at RUN TIME -- `if x == 0` on a
     * parameter -- instead of the LITERAL `if true` branching-entry.ntasm
     * carries. It is a member of
     * examples/ntasm-v0/c-bootstrap-controlflow/branching-runtime.ntasm, read
     * from disk for the reason the row above states.
     *
     * WHY IT ROUTES TO THE FRAMED PRODUCER, which is what the README above
     * says this shape needs, and which is a claim about a predicate rather
     * than about this file. The delegation at x64_lower_nxo.nova:2614 fires
     * on `declares_parameter(tree,section_id)==1 || data_seen==1 ||
     * any_body_is_framed(tree,section_id)==1`, and `main` here declares a
     * kind-19 parameter, so the first term is 1 and the source goes to
     * build_framed_functions. Measured on the tree, not read off the
     * predicate: the parse tree this member produces carries exactly one
     * kind-19 node, on the entry, and no data section, so the second term is
     * 0 and the first is the one that fires.
     *
     * ---------------------------------------------------------------
     * PRE-REGISTERED EXPECTATION. Written into this file BEFORE the row was
     * ever run through this gate, and kept whatever it turned out to be.
     * ---------------------------------------------------------------
     *
     * (1) THE C REFERENCE: it BUILDS the member. Grounds, from the tree and
     *     not from this row: spec/ntasm/ntasm.md:296-299 records that `let b:bool =
     *     x < 1` on a real parameter is accepted and that `if x == 0`,
     *     `if x < 1`, `if x < y` are accepted, and that the TRIGGER is the
     *     FOLD and neither the `if` nor the operator nor the value. The
     *     README above carries the same fact from the other side, at its
     *     :134-136: a comparison that does not fold takes the `else` at
     *     frontend.c:1791 and is never range-checked at all. So a
     *     non-folding comparison on a parameter is a shape the reference
     *     ACCEPTS, established before this member existed.
     *     WHICH SIDE A FAILURE WOULD BE ON: the REFERENCE, and it would be a
     *     specification-versus-reference disagreement in the direction this
     *     project's README says is the dangerous one -- the reference
     *     refusing what the specification admits -- and not a product
     *     defect. A reader must not file a refusal here as a product bug
     *     without re-reading that paragraph first.
     *
     * (2) THE NOVA PRODUCER: it REFUSES, with a code I do not name in
     *     advance, on BOTH routes -- mode 0 and mode 4 -- so the row does not
     *     depend on which of the two the delegation picks.
     *     WHICH SIDE A FAILURE WOULD BE ON: the PRODUCT, specifically the
     *     framed producer reached through the delegation above. If the
     *     producer had answered 0 on this source, the two things that would
     *     have to be true are that the framed path lowers a two-armed if/else
     *     AND that it lowers this condition; the paragraph below records
     *     that the first is already measured true on a sibling source, so a
     *     0 here would have isolated the second.
     *
     * (3) THE PINS, which this file ASSERTS on every run: C object 1600,
     *     C PE 4096, Nova 800. If the C object pin is wrong the gate is red
     *     and the row says so; it is not a number to be adjusted until it
     *     stops being red.
     *
     * (4) WHAT THE GATE ITSELF WILL PRINT: rows=14, converged=7,
     *     pinned_refusals=7, and this row observed=AS_PINNED. The literal
     *     `converged == 7` above is NOT changed by this row, and that is the
     *     point of it being a literal: a row added as a REFUSAL must not
     *     move the convergence count, and a reader who wanted the count to
     *     move would be describing a different row.
     *
     * ---------------------------------------------------------------
     * AN HONESTY CLAUSE THAT IS PART OF THE EXPECTATION, because leaving it
     * out would make the paragraph above a lie. A THROWAWAY probe outside
     * this repository -- not a file in the tree, not a gate, deleted after
     * the measurement -- had already asked (1) and (2) of the exact source
     * that is now on disk, through the same C libraries and the same Nova
     * host image this file builds, and had already seen 1600 and a refusal,
     * BEFORE this text was written. So (1) and (2) are a RECORD, not a blind
     * prediction, and quoting them as a prediction would be a comment
     * asserting something about the past that is not true of it. What
     * remained genuinely unrun when this was written, and is what the gate
     * run actually tests, is (3) and (4): the pins this file asserts, and the
     * verdict the run compares in both directions.
     * ---------------------------------------------------------------
     * MEASURED AFTERWARDS, AND IT CORRECTS THE ROW ABOVE RATHER THAN ONLY
     * ADDING TO IT. The row above says, at its :698-705, that the prediction
     * failed because the condition is a LITERAL and "the reference folds it in
     * its own front end before anything is lowered. The body that reaches the
     * producer therefore has ONE return, not two". That is FALSE, on both
     * sides, and the measurement is not a reading of this file:
     *
     *   - The Nova front end does not fold it. The parse tree the producer
     *     entry receives for branching-entry.ntasm holds an if (kind 30) with
     *     THREE children -- the condition and two blocks -- and each block
     *     carries a return (kind 29). Two live children, two returns, exactly
     *     as on the member this row adds.
     *   - The C reference does not fold it either. Its own .text for
     *     branching-entry.ntasm carries a Jcc rel32 at 334, a jmp rel32 at
     *     679, and BOTH immediates 42 and 43. A body with one return and a
     *     dead arm contains neither a conditional branch nor both arm
     *     immediates.
     *
     * So the frameless word-record path WAS asked the two-return question, and
     * it answered it correctly and byte identically, and branching_entry
     * already carries two live children into the producer. What is NOT
     * corrected is the row above's other claim, that the residue sits on the
     * FRAMED path: that is confirmed by the member below, which reaches the
     * framed path by measurement of the delegation's first term. The row above
     * was right about where the residue is and wrong only about why
     * branching_entry did not reach it. Both halves are stated because
     * discarding a correct routing claim along with an incorrect mechanism is
     * the same error as making the refutation too broad.
     *
     * WHAT THE ROW BELOW THEREFORE DID NOT ESTABLISH, and this is the part a
     * reader of the table is most likely to over-read: it did NOT close the
     * child-ordering question. Its member carries two live children to the
     * producer and the producer then refuses, so it emits no bytes and no
     * ordering is ever compared. The ordering question is NARROWED, not
     * answered: the linkage is correct on the literal condition and on both
     * routes, and on the run-time condition the producer never gets far enough
     * to order anything. What would close it is a member on this shape the
     * producer BUILDS, and on today's tree there is none.
     *
     * ---------------------------------------------------------------
     * AND NOW IT DOES, because that paragraph above has become true in the
     * only way a paragraph in this file can become true: the pin moved and
     * the bytes are compared on every run from here on. The three-column
     * shape is what made the move possible to record without erasing.
     * ---------------------------------------------------------------
     *
     * WHY THIS ROW'S PIN MOVED, and the reason is not "the probe said so".
     * The producer's comparison encoder for a run-time-computed condition
     * landed -- a cmp+setcc lowering for the two-armed `if` whose condition
     * is a parameter -- so the shape that was the second corpus's hardest
     * refusal now BUILDS. The rows above, the ones that measured the residue,
     * are unchanged and none of their claims is disturbed: branching_entry
     * still converges, and the routing analysis above still says what it said.
     * What changes is only this row's verdict.
     *
     * WHAT WAS CERTIFIED BEFORE, stated plainly because the pin alone would
     * hide it. While `nova` was 800 the run took the REFUSAL path: it compared
     * the code against 800, printed the reference's PE, and emitted nothing to
     * compare. So for as long as the row sat on 800, the convergence of this
     * member was certified by NOTHING in this repository -- a throwaway probe
     * outside the tree, measured with the same libraries, was the only
     * instrument that had ever compared these bytes. A pin that names a
     * verdict the gate no longer takes is a claim about a measurement that is
     * not being made, which is why leaving it was not the conservative choice
     * but the untruthful one.
     *
     * WHAT IS CERTIFIED NOW, and by which line of the log: `nova` is 0, so the
     * row takes the convergence path and runs the same three directions every
     * other converging row runs -- C_TO_NOVA, NOVA_TO_C, and PARITY over the
     * 1600-byte object and the 4096-byte PE. Both pins above were already
     * correct and are asserted on this path too, so the row did not need a new
     * number to become falsifiable; it needed to be put back on the path that
     * compares something. C_PE sha256 c3866554...fd is unchanged, which is the
     * half of the story that says the REFERENCE did not move either.
     *
     * WHY `nova_was` IS NOT 0 HERE. It is the whole record. A reader of this
     * file must be able to see that this row used to be pinned as an 800
     * refusal, because the table is the only place in the project where that
     * fact survives -- the encoding landed and the refusal is otherwise gone
     * from every record this gate keeps. 0 in this column means "no recorded
     * widening" and is what the thirteen rows above carry; this row is the one
     * that carries a code, and main asserts that a row holding one is a row
     * whose expectation is now a convergence. A widening recorded here and a
     * pin edited silently from 800 to 0 look identical in the log, which is
     * precisely the pair this column exists to separate.
     * --------------------------------------------------------------- */
    { "branching_runtime", "examples/ntasm-v0/c-bootstrap-controlflow/",
      "branching-runtime.ntasm", NULL, 1600, 4096, 0, 800 }
};

#define BOUNDARY_N (sizeof BOUNDARY / sizeof BOUNDARY[0])

/* What the run actually saw, one entry per row, compared against the table in
 * both directions in main: a row whose verdict changed without the table being
 * updated is red, exactly as for KNOWN_UNCONVERGED. */
static uint64_t boundary_seen[BOUNDARY_N];
static unsigned boundary_measured;

static char *loadf(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long z = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
    if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) { free(b); fclose(f); return NULL; }
    fclose(f);
    b[z] = 0;
    *n = (size_t)z;
    return b;
}

static uint64_t r64(const uint8_t *b)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) v |= (uint64_t)b[i] << (i * 8);
    return v;
}

/* The Nova producer, driven through the general multi-function entry. out is
 * [nxo_size:u64][pe_size:u64][nxo][pe]. The entry is the one the function
 * bodies gate drives, so this harness adds no new entry and therefore no new
 * second convention for reaching the producer. */
static uint64_t run_nova(const NovaHostImage *i, const char *source, uint64_t mode,
                         uint8_t *out, size_t cap)
{
    NovaContextV2 c = {0};
    uint64_t sh, oh, args[5], code;
    CHECK(nova_context_init_v2(&c), "context init");
    sh = nova_borrow_v2(&c, (void *)source, strlen(source), 0);
    oh = nova_borrow_v2(&c, out, cap, 1);
    args[0] = sh; args[1] = (uint64_t)strlen(source); args[2] = mode;
    args[3] = oh; args[4] = (uint64_t)cap;
    code = i->entry(&c, args, 5);
    CHECK(c.error == 0, "runtime clean");
    CHECK(nova_context_destroy_v2(&c), "context cleanup");
    cases++;
    return code;
}

/* The C reference object for one corpus member, from nt_object_compile alone:
 * the frontend, the codegen, the symbol ordering, the module qualification and
 * the contract texts are all the reference's own. Serialized with
 * nt_object_write so the comparison is on the same bytes both producers
 * produce. */
static int c_object(const char *source, uint8_t **bytes, size_t *size,
                    NtObject *keep, char *why, size_t room)
{
    NtFInput input = {(char *)DIR, (char *)source, strlen(source)};
    NtObject object = {0};
    NtDiagnostic error = {0};
    NtBuffer file = {0};
    int ok = 0;
    if (!nt_object_compile(&input, 1, &object, &error)) {
        snprintf(why, room, "nt_object_compile %u %s", error.code, error.message);
        return 0;
    }
    if (!nt_object_write(&object, &file, &error)) {
        snprintf(why, room, "nt_object_write %u %s", error.code, error.message);
        nt_object_free(&object);
        return 0;
    }
    *bytes = file.bytes;
    *size = file.size;
    if (keep) *keep = object; else nt_object_free(&object);
    why[0] = 0;
    ok = 1;
    return ok;
}

/* The reference materializer allocates five buffers and frees none of them.
 * Every harness that drives it carries its own copy of this, so this is a copy
 * of the convention rather than a second way of doing it. */
static void free_artifact(NtArtifact *a)
{
    if (a->pe.bytes) { free(a->pe.bytes); a->pe.bytes = NULL; }
    if (a->text.bytes) { free(a->text.bytes); a->text.bytes = NULL; }
    if (a->rdata.bytes) { free(a->rdata.bytes); a->rdata.bytes = NULL; }
    if (a->data.bytes) { free(a->data.bytes); a->data.bytes = NULL; }
    free(a->base_relocations);
    memset(a, 0, sizeof *a);
}

/* The C materializer and PE writer applied to a set of object bytes. This is
 * the C side of both directions: it is what reads the Nova object back. */
static int materialize(const uint8_t *object_bytes, size_t object_size,
                       uint8_t **pe, size_t *pe_size, uint64_t *entry,
                       char *why, size_t room)
{
    NtObject readback = {0};
    NtArtifact artifact = {0};
    NtDiagnostic error = {0};
    memset(&artifact, 0, sizeof artifact);
    if (!nt_object_read(object_bytes, object_size, &readback, &error)) {
        snprintf(why, room, "nt_object_read %u %s", error.code, error.message);
        return 0;
    }
    if (!nt_object_materialize(&readback, &artifact, &error)) {
        snprintf(why, room, "nt_object_materialize %u %s", error.code, error.message);
        nt_object_free(&readback);
        return 0;
    }
    if (!nt_make_pe(&artifact)) {
        snprintf(why, room, "nt_make_pe %u %s", artifact.error.code, artifact.error.message);
        free_artifact(&artifact);
        nt_object_free(&readback);
        return 0;
    }
    *pe = artifact.pe.bytes;
    *pe_size = artifact.pe.size;
    if (entry) *entry = (uint64_t)artifact.entry;
    artifact.pe.bytes = NULL;
    free_artifact(&artifact);
    nt_object_free(&readback);
    why[0] = 0;
    return 1;
}

/* Byte comparison with a located first difference, because a member that does
 * not converge is only useful if the divergence is named.
 *
 * The two streams are NAMED BY THE CALLER. An earlier version printed the
 * labels "C" and "Nova" from inside this function while two of its call sites
 * passed the streams in the other order, so the byte it printed as C was often
 * the Nova byte. On the one divergence this gate had it reported
 * "C=0x00 Nova=0xe0" for a C byte of 0xe0 and a Nova byte of 0x00: the values
 * were right and the names were inverted, which is the worst pair of ways to
 * be wrong, because a reader who believes the names concludes the reference
 * is the side that moved. The labels belong to the call site, the only place
 * that knows which stream is which. */
static int compare(const uint8_t *a, const char *an_name, size_t an,
                   const uint8_t *b, const char *bn_name, size_t bn,
                   size_t *first, char *detail, size_t room)
{
    /* *first is the offset of the first differing byte, or the length of the
     * common prefix when the two agree over it. It is never 0 for two equal
     * non-empty inputs, so an equality test is "same length AND *first == that
     * length", never "*first == 0". */
    size_t lim = an < bn ? an : bn, i = 0;
    while (i < lim && a[i] == b[i]) i++;
    *first = i;
    if (i == lim && an == bn) { detail[0] = 0; return 1; }
    if (i == lim)
        snprintf(detail, room, "length differs: %s=%zu %s=%zu, common prefix identical",
                 an_name, an, bn_name, bn);
    else
        snprintf(detail, room, "byte %zu: %s=0x%02x %s=0x%02x", i,
                 an_name, a[i], bn_name, b[i]);
    return 0;
}

/* The symbol name table of an object, read back with the C reader, one name per
 * line, so a naming divergence is reported as a name rather than as an offset
 * into a string blob. */
static void names_of(const uint8_t *bytes, size_t size, char *out, size_t room)
{
    NtObject readback = {0};
    NtDiagnostic error = {0};
    size_t at = 0;
    out[0] = 0;
    if (!nt_object_read(bytes, size, &readback, &error)) {
        snprintf(out, room, "<unreadable: %s>", error.message);
        return;
    }
    for (size_t k = 0; k < readback.symbol_count && at + 1 < room; k++) {
        int n = snprintf(out + at, room - at, "%s%s@%llu",
                         k ? " " : "", readback.symbols[k].name,
                         (unsigned long long)readback.symbols[k].offset);
        if (n < 0 || (size_t)n >= room - at) break;
        at += (size_t)n;
    }
    nt_object_free(&readback);
}
/* A digest, printed BEFORE the verdict that depends on it.
 *
 * WHY. Every comparison this gate makes answers a question about a set of
 * bytes, and a length is a number about that set rather than a name for any
 * of it: two objects of 1184 bytes may be equal or may differ in one byte, and
 * only the second case is what the gate exists to catch. Printing a digest of
 * each stream makes a run checkable from its log alone -- by eye, by grep, by
 * a later run that must reproduce the same string -- instead of leaving the
 * reader to trust that an in-memory memcmp ran.
 *
 * It is a self contained FIPS 180-4 SHA-256, because this tree has no digest
 * helper to call and a gate that reaches outside its own translation unit for
 * one would be a new convention rather than a reuse. The three digests a
 * converging member prints are the C reference object, the Nova object, and
 * the recorded reference the corpus pin carries for its PE. */
typedef struct { uint32_t h[8]; } Sha256;

static uint32_t sha_ror(uint32_t x, int r) { return (x >> r) | (x << (32 - r)); }

static void sha256_block(Sha256 *s, const uint8_t *p)
{
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 |
               (uint32_t)p[i*4+2] << 8 | (uint32_t)p[i*4+3];
    for (; i < 64; i++) {
        uint32_t s0 = sha_ror(w[i-15],7) ^ sha_ror(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = sha_ror(w[i-2],17) ^ sha_ror(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = sha_ror(e,6) ^ sha_ror(e,11) ^ sha_ror(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t S0 = sha_ror(a,2) ^ sha_ror(a,13) ^ sha_ror(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        t1 = h + S1 + ch + K[i] + w[i];
        t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha256(const uint8_t *p, size_t n, char *out /* 65 */)
{
    static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    Sha256 s;
    uint8_t tail[128];
    size_t i, r, pad;
    uint64_t bits = (uint64_t)n * 8;
    memcpy(s.h, iv, sizeof iv);
    for (i = 0; i + 64 <= n; i += 64) sha256_block(&s, p + i);
    r = n - i;
    memcpy(tail, p + i, r);
    tail[r] = 0x80;
    pad = (r < 56) ? 64 : 128;
    memset(tail + r + 1, 0, pad - r - 1 - 8);
    for (int k = 0; k < 8; k++) tail[pad-1-k] = (uint8_t)(bits >> (k*8));
    sha256_block(&s, tail);
    if (pad == 128) sha256_block(&s, tail + 64);
    for (i = 0; i < 8; i++) sprintf(out + i*8, "%08x", s.h[i]);
    out[64] = 0;
}

/* The recorded reference for one member, transcribed from the pin the build
 * script asserts. It is NOT read from that script: this file never reads
 * scripts/ntbuild.sh, and a gate that did would be coupled to a shell array
 * this translation unit cannot see. It is a third independent name for the
 * same bytes, which is the point -- the C object here, the Nova object here,
 * and the digest the build asserts independently outside this gate. The
 * comparison is a CHECK, not a comment, so a producer that changed the bytes
 * while the two sides of this gate still agreed with each other would be red
 * here rather than silently different from what the build ships. */
static const char *recorded_reference(const char *name)
{
    static const struct { const char *member, *pe; } pins[] = {
        {"return42",     "1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457"},
        {"return43",     "5811fda51dd2e115eabb39cc2d5c688fcc494da29660e4ac817794bc2b127ac3"},
        {"returnmax",    "f91e4ba4a0aa3901baebf42f227b05fc97439368584b00737e88ae944cd2bbb5"},
        {"helper-first", "c74c7db2e1cf0e6f21e96eac129fee50ef77f705d2bbe9e8ee477c6ea4e5e9c3"},
        {"static-data",  "43fddd77fe59b29b11e6e1d0d05ec05e02d159a357484da8090bfe5fe1dc207a"},
        {"mutable-data", "42f6e3459bdf7bf32280dbea534165d453c361a5fe9228135ae7562f48420690"},
        {"comptime-macro","1ecdb7eec14d2db1a2ff47923b9bf213ffa149618c42c54b7ec1b6922da99457"},
    };
    for (size_t k = 0; k < sizeof pins / sizeof pins[0]; k++)
        if (!strcmp(pins[k].member, name)) return pins[k].pe;
    return NULL;
}

static void corpus_member(const NovaHostImage *image, const char *name)
{
    char path[512], why[256], detail[256];
    char c_names[2048], nova_names[2048];
    char *source = NULL;
    size_t source_size = 0;
    uint8_t *c_bytes = NULL, *nova_bytes = NULL;
    size_t c_size = 0;
    uint8_t nova_out[OUTCAP];
    uint64_t nova_code, nxo_size, pe_size, c_entry = 0, nova_entry = 0;
    uint8_t *c_pe = NULL, *nova_pe = NULL, *cross_pe = NULL;
    size_t c_pe_size = 0, nova_pe_size = 0, cross_pe_size = 0;
    size_t first = 0;
    int c_ok, nova_ok;

    snprintf(path, sizeof path, "%s%s.ntasm", DIR, name);
    source = loadf(path, &source_size);
    CHECKL(source != NULL, "the corpus member is on disk", name);
    if (!source) return;

    /* ---- side one: the C reference. Recorded whatever it does, including a
     * refusal, because a refusal is a measured fact and not a reason to skip
     * the member. */
    c_ok = c_object(source, &c_bytes, &c_size, NULL, why, sizeof why);
    if (!c_ok)
        fprintf(stderr, "CORPUS %s C_REFUSED %s\n", name, why);

    /* ---- side two: the Nova producer. mode 0 is build_function_bodies, the
     * general producer, and it is the ONLY mode this harness asks: lines 511,
     * 512 and 524 ask mode 0 as well, and no other mode is ever passed to
     * run_nova. An earlier version of this comment said the framed route,
     * mode 4, "is asked separately so a member the bare route refuses is still
     * measured". It is not asked, and the sentence was worse than a stale
     * number: it claimed the coverage that would have caught a real defect.
     * Measured 29 September 2026, driving the entry directly: mode 4 answers
     * 800 for return42, return43, returnmax, comptime-macro and helper-first,
     * and 0 for static-data and mutable-data, so the framed profile is not a
     * second opinion on this corpus at all -- it is refused wherever the
     * frameless profile is the one that works. Asking it here would therefore
     * not have caught helper-first; it would have refused five more members.
     * What would have caught it is named in KNOWN_UNCONVERGED below: a member
     * on the shape the frameless profile lowers WITHOUT a frame, which no
     * member of this corpus is on. Do not shorten this comment to "mode 0
     * only" without keeping the reason, because the reason is what makes it
     * checkable. */
    memset(nova_out, 0xcc, sizeof nova_out);
    nova_code = run_nova(image, source, 0, nova_out, sizeof nova_out);
    if (nova_code == 0) {
        nxo_size = r64(nova_out);
        pe_size = r64(nova_out + 8);
        nova_ok = nxo_size && pe_size && 16 + nxo_size + pe_size <= sizeof nova_out;
        if (nova_ok) {
            nova_bytes = malloc(nxo_size);
            memcpy(nova_bytes, nova_out + 16, nxo_size);
            nova_pe = nova_out + 16 + nxo_size;
            nova_pe_size = pe_size;
        } else {
            nova_ok = 0;
        }
    } else {
        nova_ok = 0;
    }
    CHECKL(nova_ok || c_ok, "at least one producer builds the member", name);
    if (!c_ok && !nova_ok) {
        fprintf(stderr, "CORPUS %s BOTH_REFUSED nova=%llu c=%s\n", name,
                (unsigned long long)nova_code, why);
        free(source);
        return;
    }
    if (!nova_ok) {
        /* A member the C reference builds and the Nova producer refuses does not
         * converge, and saying so here is the whole point: the run records the
         * name and main compares the recorded set with KNOWN_UNCONVERGED, so a
         * refusal nobody has accounted for is a red and a baseline entry that
         * is no longer true is a red. */
        if (c_ok && unconverged_count < sizeof unconverged / sizeof unconverged[0])
            snprintf(unconverged[unconverged_count++], sizeof unconverged[0], "%s", name);
        fprintf(stderr, "CORPUS %s NOVA_REFUSED code=%llu c_object=%zu\n", name,
                (unsigned long long)nova_code, c_size);
        free(c_bytes);
        free(source);
        return;
    }

    names_of(nova_bytes, nxo_size, nova_names, sizeof nova_names);

    /* ---- direction C_TO_NOVA: the C reader and materializer accept the Nova
     * object, and the PE it builds from it is the PE the Nova producer
     * shipped. This is the direction that would catch a Nova object that is
     * self consistent but not in the format the reference reads. */
    {
        char cross_why[256];
        int readback_ok = materialize(nova_bytes, nxo_size, &cross_pe, &cross_pe_size,
                                      &nova_entry, cross_why, sizeof cross_why);
        CHECKL(readback_ok, "the C materializer reads the Nova object", name);
        if (readback_ok) {
            CHECKL(cross_pe_size == nova_pe_size &&
                   !memcmp(cross_pe, nova_pe, nova_pe_size),
                   "C_TO_NOVA: the C materializer on the Nova object rebuilds the Nova PE", name);
            free(cross_pe);
        } else {
            fprintf(stderr, "CORPUS %s C_TO_NOVA_REFUSED %s\n", name, cross_why);
        }
    }

    /* ---- direction NOVA_TO_C: the Nova object is canonical, so writing it
     * back out through the C writer reproduces the same bytes. */
    {
        NtObject rb = {0};
        NtDiagnostic error = {0};
        NtBuffer rewritten = {0};
        char why2[256];
        if (nt_object_read(nova_bytes, nxo_size, &rb, &error)) {
            if (nt_object_write(&rb, &rewritten, &error)) {
                compare((const uint8_t *)rewritten.bytes, "C rewrite", rewritten.size,
                        (const uint8_t *)nova_bytes, "Nova", nxo_size,
                        &first, detail, sizeof detail);
                CHECKL(rewritten.size == nxo_size && !memcmp(rewritten.bytes, nova_bytes, nxo_size),
                       "NOVA_TO_C: the C writer reproduces the Nova object bytes", name);
                free(rewritten.bytes);
            } else {
                snprintf(why2, sizeof why2, "nt_object_write %u %s", error.code, error.message);
                CHECKL(0, "NOVA_TO_C: the C writer accepts the Nova object", name);
                fprintf(stderr, "CORPUS %s NOVA_TO_C_REFUSED %s\n", name, why2);
            }
            nt_object_free(&rb);
        } else {
            CHECKL(0, "NOVA_TO_C: the C reader accepts the Nova object", name);
        }
    }

    /* ---- the headline: both object streams, then both PE streams. */
    if (c_ok) {
        /* THE THREE DIGESTS, PRINTED BEFORE THE VERDICT THAT DEPENDS ON THEM.
         * The C object, the Nova object, and the reference the build pins.
         * A `converged=7 of 7` without them is a claim; with them it is a
         * measurement a reader can check without re-running anything. */
        {
            char dc[65], dn[65];
            sha256(c_bytes, c_size, dc);
            sha256(nova_bytes, nxo_size, dn);
            fprintf(stderr, "CORPUS %s DIGEST C_OBJECT   sha256=%s\n", name, dc);
            fprintf(stderr, "CORPUS %s DIGEST NOVA_OBJECT sha256=%s\n", name, dn);
        }
        names_of((const uint8_t *)c_bytes, c_size, c_names, sizeof c_names);
        compare((const uint8_t *)c_bytes, "C", c_size,
                (const uint8_t *)nova_bytes, "Nova", nxo_size,
                &first, detail, sizeof detail);
        fprintf(stderr, "CORPUS %s OBJECT C=%zu Nova=%zu verdict=%s first=%zu %s\n",
                name, c_size, nxo_size,
                (c_size == nxo_size && !memcmp(c_bytes, nova_bytes, nxo_size)) ? "IDENTICAL" : "DIVERGES",
                first, detail);
        fprintf(stderr, "CORPUS %s NAMES C=[%s]\n", name, c_names);
        fprintf(stderr, "CORPUS %s NAMES Nova=[%s]\n", name, nova_names);
        CHECKL(c_size == nxo_size && !memcmp(c_bytes, nova_bytes, nxo_size),
               "OBJECT_PARITY: the C and the Nova object bytes are equal", name);
        if (materialize((const uint8_t *)c_bytes, c_size, &c_pe, &c_pe_size,
                        &c_entry, why, sizeof why)) {
            {
                char dp[65], dn[65];
                const char *pin = recorded_reference(name);
                sha256(c_pe, c_pe_size, dp);
                sha256(nova_pe, nova_pe_size, dn);
                fprintf(stderr, "CORPUS %s DIGEST C_PE       sha256=%s\n", name, dp);
                fprintf(stderr, "CORPUS %s DIGEST NOVA_PE    sha256=%s\n", name, dn);
                if (pin) fprintf(stderr, "CORPUS %s DIGEST RECORDED_REFERENCE sha256=%s\n", name, pin);
                /* The third digest is asserted, not only printed. A member
                 * whose C object no longer materializes to the bytes the build
                 * ships is a different artefact wearing the same name, and the
                 * two producers agreeing with each other would not notice. */
                CHECKL(pin && !strcmp(pin, dp),
                       "the C reference PE equals the digest the build records for this member", name);
                CHECKL(pin && !strcmp(pin, dn),
                       "the Nova PE equals the digest the build records for this member", name);
            }
            compare(nova_pe, "Nova", nova_pe_size, c_pe, "C", c_pe_size,
                    &first, detail, sizeof detail);
            fprintf(stderr, "CORPUS %s PE C=%zu Nova=%zu verdict=%s first=%zu %s\n",
                    name, c_pe_size, nova_pe_size,
                    (c_pe_size == nova_pe_size && !memcmp(nova_pe, c_pe, nova_pe_size)) ? "IDENTICAL" : "DIVERGES",
                    first, detail);
            CHECKL(c_pe_size == nova_pe_size && !memcmp(nova_pe, c_pe, nova_pe_size),
                   "PE_PARITY: the C and the Nova PE bytes are equal", name);
            CHECKL(c_entry == nova_entry, "the two producers agree on the entry offset", name);
            free(c_pe);
        } else {
            CHECKL(0, "the C materializer reads the C object", name);
            fprintf(stderr, "CORPUS %s C_OBJECT_UNREADABLE %s\n", name, why);
        }
    } else {
        fprintf(stderr, "CORPUS %s CONVERGENCE impossible: the C reference refused this member\n", name);
    }

    free(c_bytes);
    free(nova_bytes);
    free(source);
}

/* One row of BOUNDARY, measured. This is corpus_member's three directions and
 * its two-directions assertion, with the C reference given the row's OWN
 * directory instead of the single-file DIR, because two rows live in
 * c-bootstrap-multi and a reference compiled against the wrong directory would
 * resolve a different import path and quietly answer about a different
 * program. The comparison is the same memcmp, through the same compare().
 *
 * The three directions, so a row is as falsifiable as a member:
 *   C_TO_NOVA  the C materializer reads the Nova object and rebuilds its PE
 *   NOVA_TO_C  the C writer reproduces the Nova object's bytes
 *   PARITY     the two object streams, then the two PE streams, and the entry
 *              offset -- for the rows whose expectation is a convergence
 * For the rows whose expectation is a refusal, the code is compared against the
 * exact value in the table and nothing else is asked, because there are no
 * bytes to compare. */
/* A row that never reached the producer records ROW_UNMEASURED here, and not
 * the zero it is initialised to. boundary_seen[] is static and zero-filled, and
 * a row the C reference refused used to return before writing anything, so the
 * assertion in main compared an UNWRITTEN cell against a pin of 0, found them
 * equal and printed `observed=AS_PINNED` for a row that had measured nothing.
 * Measured 30 September 2026, on the branching_entry row: BOUNDARY_SUMMARY
 * reported it as AS_PINNED in the same run that printed
 * `BOUNDARY branching_entry C_REFUSED nt_object_compile 401`. A cell that
 * cannot be written cannot be read, and reading one is not the same as
 * measuring it. The sentinel is a value no producer returns, so a skipped row
 * can never satisfy a pin by accident. */
#define ROW_UNMEASURED (~(uint64_t)0)
static void row_skipped(unsigned idx) { boundary_seen[idx] = ROW_UNMEASURED; }

static void boundary_row(const NovaHostImage *image, unsigned idx)
{
    const Boundary *b = &BOUNDARY[idx];
    char path[512], why[256], detail[256];
    char *source = NULL;
    size_t source_size = 0;
    uint8_t *c_bytes = NULL, *nova_bytes = NULL;
    size_t c_size = 0;
    uint8_t nova_out[OUTCAP];
    uint64_t nova_code, nxo_size, pe_size;
    uint8_t *c_pe = NULL, *nova_pe = NULL, *cross_pe = NULL;
    size_t c_pe_size = 0, cross_pe_size = 0, first = 0;
    int c_ok;

    CHECKL((b->path != NULL) != (b->source != NULL),
           "the row names a file OR a literal source, never both and never neither",
           b->name);

    if (b->source) {
        source_size = strlen(b->source);
        source = malloc(source_size + 1);
        memcpy(source, b->source, source_size + 1);
    } else {
        snprintf(path, sizeof path, "%s%s", b->dir, b->path);
        source = loadf(path, &source_size);
    }
    CHECKL(source != NULL, "the row's source is available", b->name);
    if (!source) { row_skipped(idx); return; }

    /* ---- the C reference, in the row's own directory. */
    {
        NtFInput input = {(char *)b->dir, source, source_size};
        NtObject object = {0};
        NtDiagnostic error = {0};
        NtBuffer file = {0};
        if (!nt_object_compile(&input, 1, &object, &error)) {
            snprintf(why, sizeof why, "nt_object_compile %u %s", error.code, error.message);
            CHECKL(0, "the C reference builds this row's source", b->name);
            fprintf(stderr, "BOUNDARY %s C_REFUSED %s\n", b->name, why);
            row_skipped(idx);
            free(source);
            return;
        }
        if (!nt_object_write(&object, &file, &error)) {
            snprintf(why, sizeof why, "nt_object_write %u %s", error.code, error.message);
            CHECKL(0, "the C reference serializes this row's object", b->name);
            row_skipped(idx);
            nt_object_free(&object);
            free(source);
            return;
        }
        c_bytes = file.bytes;
        c_size = file.size;
        nt_object_free(&object);
        c_ok = 1;
    }
    (void)c_ok;

    /* ---- the row's pinned sizes. Asserted on EVERY run, so a row whose source
     * has drifted stops reporting a verdict about a shape that has moved. */
    fprintf(stderr, "BOUNDARY %s C object=%zu\n", b->name, c_size);
    CHECKL(c_size == b->c_object, "the C object is the pinned size for this row", b->name);

    /* ---- the Nova producer, the same entry and the same mode as a member. */
    memset(nova_out, 0xcc, sizeof nova_out);
    nova_code = run_nova(image, source, 0, nova_out, sizeof nova_out);

    if (b->nova != 0) {
        /* A refusal is the expectation, so the comparison is against the exact
         * code and not against "non-zero". A producer that started answering a
         * DIFFERENT refusal would satisfy a non-zero test, and that is a change
         * of shape dressed as a pass. */
        boundary_seen[idx] = nova_code;
        boundary_measured++;
        CHECKL(nova_code == b->nova, "the Nova producer still answers the pinned code", b->name);
        fprintf(stderr, "BOUNDARY %s NOVA refused=%llu expected=%llu C_object=%zu "
                        "verdict=%s\n", b->name, (unsigned long long)nova_code,
                (unsigned long long)b->nova, c_size,
                nova_code == b->nova ? "AS_PINNED" : "MOVED");
        /* THE REFERENCE PE OF A REFUSAL ROW, MEASURED AND PRINTED, NOT ASSERTED
         * -- and the reason it is not asserted is a finding, recorded here
         * rather than acted on.
         *
         * The c_pe column is written for every row and was consulted only for
         * the converging ones, which is the shape of a pin nobody checks. An
         * earlier version of this block DID assert it here, on the reasoning
         * that a field is a field. It was measured on this tree and it turned
         * two rows red that had been green for as long as they existed:
         * imported_callee_macro and imported_module_no_call both FAIL "the C
         * materializer reads the C object for this row". So the C reader
         * declines to read back the reference's OWN object for a source that
         * carries an unresolved import. That is a real fact and it is probably
         * the same wall the import rows are already pinned against from the
         * producer side; it is also not this row's business, and turning two
         * long-standing rows red to prove a point about a third one is exactly
         * the widening this file's own header warns against.
         *
         * So the size and the digest are PRINTED and nothing is asserted, which
         * means the number for a refusal row exists in the log as a durable
         * artefact -- branching_entry's is 3584, sha256 1af76e82...26026, and a
         * reader who wants it asserted has the two lines that would do it. A
         * reader who wants to know WHY those two import rows cannot be
         * materialized has the answer above, which is the more useful of the
         * two facts and is the only one that was not already written down. */
        if (materialize(c_bytes, c_size, &c_pe, &c_pe_size, NULL, why, sizeof why)) {
            char dp[65];
            sha256(c_pe, c_pe_size, dp);
            fprintf(stderr, "BOUNDARY %s REFUSAL_ROW C_PE=%zu table_c_pe=%lu "
                            "DIGEST C_PE sha256=%s\n", b->name, c_pe_size, b->c_pe, dp);
            free(c_pe);
        } else {
            fprintf(stderr, "BOUNDARY %s REFUSAL_ROW C_PE=none table_c_pe=%lu "
                            "the C reader declines the reference's own object: %s\n",
                    b->name, b->c_pe, why);
        }
        free(c_bytes);
        free(source);
        return;
    }

    if (nova_code != 0) {
        boundary_seen[idx] = nova_code;
        boundary_measured++;
        CHECKL(0, "this row must converge and the Nova producer refused", b->name);
        fprintf(stderr, "BOUNDARY %s NOVA refused=%llu expected=CONVERGE C_object=%zu "
                        "verdict=DIVERGES\n", b->name, (unsigned long long)nova_code, c_size);
        free(c_bytes);
        free(source);
        return;
    }
    nxo_size = r64(nova_out);
    pe_size = r64(nova_out + 8);
    CHECKL(nxo_size && pe_size && 16 + nxo_size + pe_size <= sizeof nova_out,
           "the Nova producer's output header is usable", b->name);
    if (nxo_size == 0 || pe_size == 0 || 16 + nxo_size + pe_size > sizeof nova_out) {
        row_skipped(idx);
        free(c_bytes); free(source); return;
    }
    nova_bytes = malloc(nxo_size);
    memcpy(nova_bytes, nova_out + 16, nxo_size);
    nova_pe = nova_out + 16 + nxo_size;
    boundary_seen[idx] = 0;
    boundary_measured++;

    /* C_TO_NOVA */
    {
        char cross_why[256];
        uint64_t nova_entry = 0;
        if (materialize(nova_bytes, nxo_size, &cross_pe, &cross_pe_size,
                        &nova_entry, cross_why, sizeof cross_why)) {
            CHECKL(cross_pe_size == pe_size && !memcmp(cross_pe, nova_pe, pe_size),
                   "C_TO_NOVA: the C materializer on the Nova object rebuilds the Nova PE",
                   b->name);
            free(cross_pe);
        } else {
            CHECKL(0, "C_TO_NOVA: the C materializer reads the Nova object", b->name);
            fprintf(stderr, "BOUNDARY %s C_TO_NOVA_REFUSED %s\n", b->name, cross_why);
        }
    }
    /* NOVA_TO_C */
    {
        NtObject rb = {0};
        NtDiagnostic error = {0};
        NtBuffer rewritten = {0};
        if (nt_object_read(nova_bytes, nxo_size, &rb, &error) &&
            nt_object_write(&rb, &rewritten, &error)) {
            compare((const uint8_t *)rewritten.bytes, "C rewrite", rewritten.size,
                    (const uint8_t *)nova_bytes, "Nova", nxo_size,
                    &first, detail, sizeof detail);
            CHECKL(rewritten.size == nxo_size && !memcmp(rewritten.bytes, nova_bytes, nxo_size),
                   "NOVA_TO_C: the C writer reproduces the Nova object bytes", b->name);
            free(rewritten.bytes);
        } else {
            CHECKL(0, "NOVA_TO_C: the C writer accepts the Nova object", b->name);
        }
        nt_object_free(&rb);
    }
    /* PARITY: the headline, with the digests printed beside each other. */
    /* The digests, printed BEFORE the verdict that depends on them and on the
     * same convention the seven members use, so a reader who cannot re-run this
     * gate can still check the claim against two hex strings. The two sides are
     * named at the call site and never from inside a helper that does not know
     * which stream is which -- inverting that label once cost this file a
     * reader, and the comment on compare() says so. */
    {
        char dc[65], dn[65];
        sha256(c_bytes, c_size, dc);
        sha256(nova_bytes, nxo_size, dn);
        fprintf(stderr, "BOUNDARY %s DIGEST C_OBJECT   sha256=%s\n", b->name, dc);
        fprintf(stderr, "BOUNDARY %s DIGEST NOVA_OBJECT sha256=%s\n", b->name, dn);
    }
    compare(c_bytes, "C", c_size, (const uint8_t *)nova_bytes, "Nova", nxo_size,
            &first, detail, sizeof detail);
    fprintf(stderr, "BOUNDARY %s OBJECT C=%zu Nova=%zu verdict=%s first=%zu %s\n",
            b->name, c_size, nxo_size,
            (c_size == nxo_size && !memcmp(c_bytes, nova_bytes, nxo_size)) ? "IDENTICAL" : "DIVERGES",
            first, detail);
    CHECKL(c_size == nxo_size && !memcmp(c_bytes, nova_bytes, nxo_size),
           "OBJECT_PARITY: the C and the Nova object bytes are equal", b->name);
    if (materialize(c_bytes, c_size, &c_pe, &c_pe_size, NULL, why, sizeof why)) {
        fprintf(stderr, "BOUNDARY %s PE C=%zu Nova=%zu pinned_C=%lu\n",
                b->name, c_pe_size, pe_size, b->c_pe);
        CHECKL(c_pe_size == b->c_pe, "the C PE is the pinned size for this row", b->name);
        {
            char dp[65], dn[65];
            sha256(c_pe, c_pe_size, dp);
            sha256((const uint8_t *)nova_pe, pe_size, dn);
            fprintf(stderr, "BOUNDARY %s DIGEST C_PE       sha256=%s\n", b->name, dp);
            fprintf(stderr, "BOUNDARY %s DIGEST NOVA_PE    sha256=%s\n", b->name, dn);
        }
        compare((const uint8_t *)nova_pe, "Nova", pe_size, c_pe, "C", c_pe_size,
                &first, detail, sizeof detail);
        fprintf(stderr, "BOUNDARY %s PE C=%zu Nova=%zu verdict=%s first=%zu %s\n",
                b->name, c_pe_size, pe_size,
                (c_pe_size == pe_size && !memcmp(nova_pe, c_pe, pe_size)) ? "IDENTICAL" : "DIVERGES",
                first, detail);
        CHECKL(c_pe_size == pe_size && !memcmp(nova_pe, c_pe, pe_size),
               "PE_PARITY: the C and the Nova PE bytes are equal", b->name);
        free(c_pe);
    } else {
        CHECKL(0, "the C materializer reads the C object for this row", b->name);
    }
    free(c_bytes);
    free(nova_bytes);
    free(source);
}

/* The negative instrument. A producer that emitted the wrong bytes for a corpus
 * member must be able to turn this gate red, and a harness that has never been
 * seen to fail is a harness that has not been tested. This feeds the two
 * producers two DIFFERENT sources and asserts they do not compare equal, which
 * is the property a byte comparison actually rests on: two unequal inputs do
 * not produce equal objects. Without it, a comparison that compared every
 * member against itself would pass. */
/* The negative instrument, and the reason it is here.
 *
 * Every assertion above is a COMPARISON, and a comparison that has only ever
 * been seen to succeed has not been shown able to fail. Three properties, each
 * one a way the headline comparison could be broken without turning this gate
 * red:
 *
 *   1. STABLE: the same source twice yields byte identical objects. Without
 *      this, a comparison that is really comparing run order or uninitialised
 *      bytes would pass everything above.
 *   2. SENSITIVE: two sources that differ in one immediate yield different
 *      objects. Without this, a comparison reading the wrong offset would
 *      report every member identical.
 *   3. RED ON A KNOWN DIFFERENCE: the exact comparison the headline uses, fed a
 *      C object and a copy of that same object with one byte flipped, must
 *      report DIVERGES and name the flipped offset. This is the one that makes
 *      OBJECT_PARITY falsifiable: it is the comparison function, on the
 *      comparison's own inputs, asked a question whose answer is known. */
static void negative_proof(const NovaHostImage *image)
{
    static uint8_t a[OUTCAP], b[OUTCAP], a2[OUTCAP];
    static uint8_t flipped[MAXOBJ];
    static const char *A =
        "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
        "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n}\n";
    static const char *B =
        "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
        "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 2\n}\n}\n";
    char why[256], detail[256];
    uint64_t ca, cb, ca2, na, nb, na2;
    uint8_t *c_bytes = NULL;
    size_t c_size = 0, first = 0;
    const size_t FLIP = 40;  /* an interior byte, past the 16 byte out header */

    memset(a, 0xcc, sizeof a);
    memset(b, 0xcc, sizeof b);
    memset(a2, 0xcc, sizeof a2);

    /* 1. STABLE */
    ca = run_nova(image, A, 0, a, sizeof a);
    ca2 = run_nova(image, A, 0, a2, sizeof a2);
    CHECKL(ca == 0 && ca2 == 0, "the negative instrument's source builds twice", "negative");
    if (ca != 0 || ca2 != 0) return;
    na = r64(a); na2 = r64(a2);
    compare(a + 16, "first build", na, a2 + 16, "second build", na2,
            &first, detail, sizeof detail);
    CHECKL(na == na2 && first == na,
           "NEGATIVE stable: the same source twice yields byte identical objects", "negative");
    fprintf(stderr, "NEGATIVE_PROOF stable bytes=%llu first=%zu %s\n",
            (unsigned long long)na, first, detail);

    /* 2. SENSITIVE */
    cb = run_nova(image, B, 0, b, sizeof b);
    CHECKL(cb == 0, "the negative instrument's second source builds", "negative");
    if (cb != 0) return;
    nb = r64(b);
    compare(a + 16, "source A", na, b + 16, "source B", nb,
            &first, detail, sizeof detail);
    CHECKL(!(na == nb && first == nb),
           "NEGATIVE sensitive: two sources differing in one immediate do NOT compare equal",
           "negative");
    fprintf(stderr, "NEGATIVE_PROOF sensitive first_difference=%zu %s\n", first, detail);

    /* 3. RED ON A KNOWN DIFFERENCE, on the headline's own comparison */
    if (!c_object(A, &c_bytes, &c_size, NULL, why, sizeof why)) {
        CHECKL(0, "the C reference builds the negative instrument's source", "negative");
        fprintf(stderr, "CORPUS negative C_REFUSED %s\n", why);
        return;
    }
    if (c_size > MAXOBJ || c_size <= FLIP) {
        CHECKL(0, "the negative instrument's C object is a usable size", "negative");
        free(c_bytes);
        return;
    }
    memcpy(flipped, c_bytes, c_size);
    flipped[FLIP] = (uint8_t)(flipped[FLIP] ^ 0xff);
    compare(flipped, "flipped", c_size, c_bytes, "C", c_size,
            &first, detail, sizeof detail);
    CHECKL(first == FLIP, "NEGATIVE red: one flipped byte is located by the comparison", "negative");
    fprintf(stderr, "NEGATIVE_PROOF flipped_byte=%zu located=%zu %s\n",
            (size_t)FLIP, first, detail);
    free(c_bytes);
}

int main(void)
{
    const char *paths[] = {
        "tests/nova/tests/x64-lower-nxo-function-bodies-entry.nova",
        "compiler/nova/backend/x64/x64_lower_nxo.nova",
        "compiler/nova/backend/x64/x64_lower_control.nova",
        "compiler/nova/backend/x64/x64_lower_fixed.nova",
        "compiler/nova/backend/x64/x64_fixed.nova",
        "compiler/nova/analysis/types/register_widths.nova",
        "compiler/nova/analysis/abi/abi.nova",
        "compiler/nova/analysis/abi/clobbers.nova",
        "compiler/nova/formats/nxo/nxo_pe.nova",
        "compiler/nova/formats/nxo/nxo.nova",
        "compiler/nova/formats/pe/pe.nova",
        "compiler/nova/frontend/parser.nova",
        "compiler/nova/frontend/ast.nova",
        "compiler/nova/frontend/lexer.nova"
    ,
        "compiler/nova/macros/macro_splice.nova",
        "compiler/nova/macros/macro_expand.nova",
        "compiler/nova/macros/constant_eval.nova"};
    char *sources[17] = {0};
    NtFInput inputs[17];
    int all = 1, compiled;
    NtArtifact compiler = {0};
    NovaHostImage image = {0};
    unsigned i;

    for (i = 0; i < 17; i++) {
        size_t n = 0;
        sources[i] = loadf(paths[i], &n);
        inputs[i] = (NtFInput){paths[i], sources[i], n};
    }
    for (i = 0; i < 17; i++) if (!sources[i]) all = 0;
    CHECK(all, "sources load");
    compiled = all && nova_compile_many_v2(inputs, 17, &compiler);
    CHECK(compiled, "Nova modules compile");
    if (!compiled) fprintf(stderr, "E%u %zu:%zu %s\n", compiler.error.code,
                           compiler.error.line, compiler.error.column, compiler.error.message);
    CHECK(compiled && nova_host_map(&compiler, &image), "host map");

    if (image.memory) {
        for (i = 0; i < sizeof CORPUS / sizeof CORPUS[0]; i++)
            corpus_member(&image, CORPUS[i]);
        /* The second corpus. Run in the SAME place and under the SAME host
         * image, and not behind a flag: a check behind a flag is a check that
         * runs in exactly one state. */
        for (i = 0; i < BOUNDARY_N; i++)
            boundary_row(&image, i);
        negative_proof(&image);
    }

    /* The baseline assertion. Every member the run found unconverged must be
     * in KNOWN_UNCONVERGED, and every member in KNOWN_UNCONVERGED must have
     * been found unconverged: a refusal nobody listed, and a listed gap that
     * quietly closed without anyone updating the table, are both red. The
     * count is asserted too, because a set comparison that only checks
     * membership would accept a table with a duplicated entry. None of the
     * three is guarded by another: a check that only runs when some other
     * check has already passed is a check that has been exercised in one state
     * only, which is the defect this file exists to remove. */
    {
        unsigned k, j, known;
        known = known_unconverged_count();
        CHECK(unconverged_count == known,
              "the number of corpus members the Nova producer refuses is the measured one");
        for (k = 0; k < unconverged_count; k++) {
            int found = 0;
            for (j = 0; j < known; j++)
                if (!strcmp(unconverged[k], KNOWN_UNCONVERGED[j])) found = 1;
            CHECK(found, "every unconverged member is named in KNOWN_UNCONVERGED");
            fprintf(stderr, "CORPUS_UNCONVERGED %s\n", unconverged[k]);
        }
        for (j = 0; j < known; j++) {
            int found = 0;
            for (k = 0; k < unconverged_count; k++)
                if (!strcmp(KNOWN_UNCONVERGED[j], unconverged[k])) found = 1;
            CHECK(found, "every KNOWN_UNCONVERGED member is still unconverged");
        }
    }

    /* The same baseline assertion for the second corpus, in both directions and
     * over the COUNT. A row whose verdict moved without the table being updated
     * is red; a table row the run never reached is red, because a pinned shape
     * that stopped being measured is the same hole this file exists to close,
     * and `boundary_measured` is what makes "every row ran" a claim about the
     * rows rather than about the counter. The convergence count is asserted as
     * a literal and not merely summed, so a row silently reclassified from
     * refusal to convergence cannot leave the number still adding up. */
    /* TWO INDEPENDENT GUARDS AGAINST A ROW THAT WAS NEVER MEASURED, because one
     * guard is a guard and two are a boundary, and because a fix that only
     * hardens the COUNT would leave the per-row comparison able to pass alone.
     *   COUNT  boundary_measured is incremented by the same code that records a
     *          verdict, so it disagrees with BOUNDARY_N exactly when a row was
     *          skipped. It does not read boundary_seen[] at all.
     *   CELL   every cell is rejected if it holds ROW_UNMEASURED, BEFORE it is
     *          compared to the pin. This is what makes the sentinel
     *          distinguishable from a legitimate zero: the pin for a
     *          converging row is 0, and a sentinel of 0 would satisfy the
     *          comparison by construction. ROW_UNMEASURED is ~0, which no
     *          producer returns, so a skipped row cannot match any pin and
     *          cannot be counted as a convergence.
     * Both were shown to fire on one deliberately skipped row; the mutation
     * that did it is recorded beside the sentinel's definition and is a COPY
     * of the tree, never this one. */
    {
        unsigned k, converged = 0, skipped = 0, widened = 0;
        CHECK(boundary_measured == BOUNDARY_N,
              "every row of the second corpus was measured on this run");
        for (k = 0; k < BOUNDARY_N; k++) {
            int unmeasured = (boundary_seen[k] == ROW_UNMEASURED);
            /* the CELL guard, stated on its own and not as a consequence of
             * the comparison below */
            CHECKL(!unmeasured, "this row was measured, not skipped", BOUNDARY[k].name);
            if (unmeasured) skipped++;
            CHECKL(!unmeasured && boundary_seen[k] == BOUNDARY[k].nova,
                   "every second-corpus row still answers what the table pins",
                   BOUNDARY[k].name);
            /* THE WIDENING INVARIANT, which is what makes the fourth column a
             * record rather than a decoration. A row may widen FROM a refusal,
             * so a non-zero `nova_was` requires a zero `nova`. The converse
             * shape -- a row that records a refusal it came from while still
             * refusing -- is refused here, because a refusal emits no bytes:
             * there is no measurement that could corroborate such a history,
             * and a column a run cannot check is a comment with extra steps.
             *
             * Stated as its own CHECK and not folded into the comparison above,
             * for the same reason the CELL guard is: a reader who wants to know
             * whether the table's shape is legal should not have to infer it
             * from a message about a different property. */
            CHECKL(BOUNDARY[k].nova_was == 0 || BOUNDARY[k].nova == 0,
                   "a row records a widening only from a refusal to a convergence",
                   BOUNDARY[k].name);
            if (BOUNDARY[k].nova == 0 && !unmeasured && boundary_seen[k] == 0) converged++;
            if (BOUNDARY[k].nova_was) widened++;
            /* The row line carries BOTH facts for a widened row, in one line,
             * because that is what the acceptance is: `expect=` names the
             * current pin, `widened_from=` names the pin the row carried
             * before it, and `observed=` names what this run measured. For a
             * row with no recorded widening the clause is absent rather than
             * printed as `widened_from=none`, so a reader scanning the log for
             * widened rows cannot mistake an explicit zero for a code. The
             * byte verdict is NOT on this line and is not invented here: the
             * comparison that produced it is asserted inside boundary_row,
             * and this row reaching this line at all is what means it passed. */
            {
                char was[48] = "";
                if (BOUNDARY[k].nova_was)
                    snprintf(was, sizeof was, " widened_from=REFUSAL(%llu)",
                             (unsigned long long)BOUNDARY[k].nova_was);
                fprintf(stderr, "BOUNDARY_ROW %s expect=%s%s observed=%s\n",
                        BOUNDARY[k].name,
                        BOUNDARY[k].nova ? "REFUSAL" : "CONVERGENCE", was,
                        unmeasured ? "UNMEASURED"
                                   : (boundary_seen[k] == BOUNDARY[k].nova ? "AS_PINNED" : "MOVED"));
            }
        }
        CHECK(skipped == 0, "no row of the second corpus was skipped");
        /* EIGHT, and the literal is asserted rather than summed precisely so
         * that it cannot be left saying seven. It said seven from the day
         * call_private_stmt_body converged until branching_runtime stopped
         * being refused, which is the eighth. The count is a literal and not
         * BOUNDARY_N minus the refusal rows because a computed count cannot
         * catch a row whose pin was changed from a refusal to a convergence,
         * which is exactly the move that was made here and exactly the move
         * that would silently redefine what the other rows say.
         *
         * SO THIS LITERAL MOVING IS THE FILE'S OWN INSTRUMENT FIRING, and
         * stating it that way is the point: the paragraph above warns that a
         * reclassification must not leave the number still adding up, and it
         * did not. The row that reclassified carries 800 in `nova_was`, so
         * the run says both things -- this row used to be a refusal, and the
         * corpus now converges on eight rows -- instead of one. A pin edited
         * from 800 to 0 without that column would have left the log claiming
         * seven and the file quietly claiming a row it had never measured. */
        CHECK(converged == 8,
              "the second corpus converges on the eight rows pinned as converging");
        /* `widened` is how many rows carry a recorded widening, and it is
         * printed because a summary that reports only converged and refusals
         * cannot say whether a reclassification ever happened -- the reader
         * would have to diff the table against an older copy of itself to
         * learn that, which is the review this file exists to replace. */
        fprintf(stderr, "BOUNDARY_SUMMARY rows=%lu converged=%u pinned_refusals=%lu "
                        "widened=%u "
                        "scope=the rows in BOUNDARY only; it says nothing about any "
                        "shape not listed there\n",
                BOUNDARY_N, converged, BOUNDARY_N - converged, (unsigned)widened);
    }

    if (image.memory) nova_host_unmap(&image);
    if (compiled) nt_artifact_free(&compiler);
    for (i = 0; i < 17; i++) free(sources[i]);
    /* The banner states what its counts cover, in the gate's own output and not
     * in a report, because a boundary written in a report is a boundary that
     * has drifted by the time it is needed. `converged=... of ...` is the seven
     * pinned members of CORPUS and nothing else; the second corpus carries its
     * own count on the BOUNDARY_SUMMARY line above. Neither figure is a claim
     * about any shape outside its own list. */
    fprintf(stderr, "NTASM_NOVA_X64_LOWER_NXO_CORPUS checks=%u failures=%u cases=%u "
                    "converged=%zu of %zu known_gaps=%u "
                    "scope=the members of CORPUS; it says nothing about any shape "
                    "not in that list\n",
            checks, failures, cases,
            sizeof CORPUS / sizeof CORPUS[0] - unconverged_count,
            sizeof CORPUS / sizeof CORPUS[0], unconverged_count);
    return failures != 0;
}
