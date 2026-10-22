/* tests_ntasm_machine_x64.c -- the CONSUMER'S REFUSAL GATE.
 *
 * WHAT THIS ASSERTS, in one sentence: for each body in the corpus below, the
 * pipeline returns THIS code at THIS stage, and where it is green it produces
 * THESE exact bytes.  A checker that silently stops refusing is the failure
 * this gate exists to catch, so every refusal is asserted by its EXACT code
 * and never by "non-zero".
 *
 * ------------------------------------------------------------------
 * WHY THE ASSERTION IS A REFUSAL AND NOT A SUCCESS
 * ------------------------------------------------------------------
 * machine_x64.nova carries the project's own sentence about this level: a wrong
 * machine instruction is worse than a refusal, because the Machine IR is
 * target-independent and NAMES NO REGISTER.  `mir_bind` and `mir_clobber` keep
 * a WIDTH and drop the register, so every two-operand instruction needs a
 * register assignment this level does not own.  `constraints` is that promise
 * made executable.  A gate here that asserted `add rax, 1` should ENCODE would
 * be a demand contrary to the product, not a test of it.  So the green cases
 * are the zero-operand forms the consumer really can encode, and the red cases
 * are the operand-carrying ones, and BOTH are pinned.
 *
 * ------------------------------------------------------------------
 * THE FINDING THAT SHAPED THE CORPUS: ONE SHAPE, TWO CODES
 * ------------------------------------------------------------------
 * The brief asked for "a two-operand form".  Measured, a two-operand
 * `mir_asm` is refused under TWO DIFFERENT CODES, and which one fires is
 * decided by the OPCODE and not by the operand count:
 *
 *     add rax, 1    -> 963 E_REGISTER   report=[11 963  2 2]   op=2  OP_ADD
 *     add rax, rcx  -> 963 E_REGISTER   report=[11 963  2 2]   op=2  OP_ADD
 *     mov rax, 1    -> 961 E_OPCODE    report=[11 961  1 1]   op=1  OP_COPY
 *     sub rax, 1    -> 961 E_OPCODE    report=[11 961  3 2]   op=3  OP_SUB
 *
 * REBASED 7 October 2026 (A7), one word: `mov rax, 1` measured [11 961 1 2]
 * when this file was written and measures [11 961 1 1] since machine_ir.nova
 * lowers `mov <register>, <source>` as a copy whose destination register is
 * NOT an operand (its `at_operand==1` arm reads the register's width and
 * moves on; the A7 emitter writes the copy's result to that register).  So
 * the operand-count half of the claim below is carried by `sub rax, 1`, which
 * still has two operands and is still 961, and `mov` keeps the opcode half.
 * Neither code moved.  Before the rebase: `FAIL mov rax,1: report[3] is 1 and
 * this gate expects 2`, failures=1 of 488.
 *
 * `add` and `sub` carry two operands and `report[3]` is 2 in both.  The split is
 * `covered_op`: `add` is the one two-operand opcode the module has an encoder
 * for (`x64_fixed.encode_rr` names it), so its refusal is the MISSING REGISTER
 * ASSIGNMENT (E_REGISTER); `mov`, `sub` and everything else are refused one
 * line earlier, at `covered_op(op)==false`, as E_OPCODE.  Both sites are at
 * machine_x64.nova's `k_asm` arm, E_REGISTER at the `taken!=0` line that
 * follows the `covered_op` line.
 *
 * CONSEQUENCE FOR THIS FILE, and it is why the corpus has five red cases and
 * not one: a gate that pinned 963 for "a two-operand form" would be red on
 * three of its four two-operand rows, and the fix a reader would reach for --
 * loosening the expectation to "961 or 963" -- is exactly the softening this
 * project forbids.  So each row pins its own code, and the PAIR is what is
 * being witnessed: the checker distinguishes "I have no encoder for this
 * opcode" from "I have an encoder and no registers to give it".
 *
 * ------------------------------------------------------------------
 * report[0] IS OVERLOADED, AND THE EXPECTATIONS BELOW KNOW IT
 * ------------------------------------------------------------------
 * `machine_x64.place()` writes report[0]=record, report[1]=code, report[2]=op,
 * report[3]=taken -- read at the source, not assumed.  But `constraints` does
 * NOT go through `place` on the accepting path: its last act is
 * `report[0]=count; report[1]=0; report[2]=executable; report[3]=0`.  So on a
 * GREEN case report[0] is the RECORD COUNT and report[2] is the EXECUTABLE
 * COUNT, while on a RED case report[0] is the RECORD ID and report[2] is the
 * OPCODE.  One column, two meanings, and the two are told apart by report[1]:
 * zero on the accepting path (a code of zero IS the acceptance) and the
 * refusal code otherwise.
 *
 * Every expectation below therefore pins all four words, and the header of
 * each row says which meaning it is pinning.  A gate that pinned report[0]
 * alone would be pinning a number whose meaning depends on the verdict, which
 * is the shape of an instrument that can be right for the wrong reason.
 *
 * ------------------------------------------------------------------
 * THE MEASUREMENT METHOD, because two wrong artefacts were produced first
 * ------------------------------------------------------------------
 * ONE PROCESS, every body, in this order.  Both artefacts below were measured
 * and discarded before this file was written, and they are named here so a
 * reader does not have to rediscover them:
 *
 *   (1) FRESH PROCESS PER MODE.  Modes 3, 5, 6, 7 and 8 read an image that
 *       mode 2 (ntir.build) and mode 4 (machine_ir.lower) put in the SAME
 *       buffers.  Run alone in a fresh process, modes 7 and 8 answer 800 and
 *       mode 3/4 answer 946, because the guard this file fills the scratch
 *       with is read as a record count.  Those are isolation artefacts and
 *       they are NOT the pipeline's verdicts.  Every stage below is reached
 *       over the precondition the entry names, in the same buffer.
 *
 *   (2) A MULTI-BODY SWEEP THAT LET BODIES INTERFERE.  An earlier probe of
 *       mine reported `nop;return 0` at 963 on one pass and 0 on the next,
 *       with a report of [10 0 3 0] on the second -- which is not a verdict
 *       about `return 0` at all, it is another body's record count.  The
 *       cause was the probe's own scratch: a stage that returns early without
 *       writing leaves the PREVIOUS body's image in `out`.  Two things fix it
 *       here and both are in the code below: the entry's preconditions are
 *       honoured, and `report` and `text` are re-filled with the guard on
 *       EVERY call, so a buffer still at the guard is a stage that wrote
 *       nothing and can be told from one carrying a stranger's bytes.
 *
 * AND EVERY CASE RUNS TWICE.  `measure()` is called twice per case and the two
 * verdicts are compared word for word, because a sweep that has produced a
 * wrong answer once should not be trusted to produce a right one silently.
 *
 * ------------------------------------------------------------------
 * WHAT THIS DOES NOT ESTABLISH, in the file rather than only in a report
 * ------------------------------------------------------------------
 *  - The serialize LENGTH is not pinned, deliberately.  `machine_ir.serialize`
 *    writes SOURCE SPANS, so its byte count is a function of the corpus TEXT:
 *    `module m` measures 1345 and `module mm` measures 1346, one byte of source
 *    for one byte of output.  A length is therefore a property of the strings
 *    below and not of the pipeline, and pinning it would pin this file's
 *    whitespace.  The stage's RETURN CODE is pinned; its length is not, and the
 *    difference is the whole reason.
 *  - Nothing here compares the emitted bytes against the C reference.  The
 *    green cases pin the bytes this producer emits (`90 c3`, `c3`, `90 90 c3`
 *    -- NOP then RET), which is a statement about machine_x64 and not about
 *    agreement with codegen.c.
 *  - Nothing here measures register assignment.  963 is the refusal that says
 *    the assignment is missing; the day it stops being a refusal, this gate goes
 *    red, and that red is the signal the next lot needs -- not a defect in
 *    this gate.  Read the failure message before "fixing" the expectation.
 *  - `covered_op` and `COVERED_COUNT` belong to machine_x64.nova and were being
 *    edited while this file was written.  The corpus pins the codes those two
 *    produce TODAY; a change to the covered set moves `report[1]` and the gate
 *    says so by name.
 *
 * ------------------------------------------------------------------
 * THE NEGATIVE PROOFS, and there are TWO because they cut in opposite
 * directions.  A gate nobody has seen red is an assumption, and one
 * perturbation of one expectation would not have shown that the RED ROWS are
 * load-bearing rather than merely present.
 * ------------------------------------------------------------------
 *
 *   (1) ONE EXPECTED CODE MOVED.  The `add rax,1` row's expectation went from
 *       963 to 961 at three stages.  Printed:
 *
 *         FAIL add rax,1: verify+constraints answers 963 and this gate
 *              expects 961 -- the stage moved, or the checker stopped refusing
 *         FAIL add rax,1: emit_text answers 963 and this gate expects 961 ...
 *         FAIL add rax,1: build_object answers 963 and this gate expects 961 ...
 *         FAIL a two-operand asm the consumer CAN encode is refused as 963 and
 *              one it CANNOT as 961: the two arms are distinguishable ...
 *
 *       failures=4 of 488.  The fourth is the vocabulary check at the end of
 *       main() firing on its own, which is the shape a discriminating check
 *       should have: the perturbation did not only fail the row it touched,
 *       it failed the claim the row belongs to.
 *
 *   (2) THE CORPUS MOVED INSTEAD OF THE EXPECTATION, which is the direction
 *       that matters.  The `mov rax,1` row's BODY was changed to `add rax, 1`
 *       while its expectation stayed at 961.  A gate that had learned the
 *       numbers instead of the refusal would have gone green here, because
 *       963 IS what that body produces and the row's own expectation is not
 *       what moved.  Printed:
 *
 *         FAIL mov rax,1: verify+constraints answers 963 and this gate
 *              expects 961 ...
 *         FAIL mov rax,1: report[1] is 963 and this gate expects 961 ...
 *         FAIL mov rax,1: report[2] is 2 and this gate expects 1 ...

 *       failures=5 of 488, and the two report failures are the ones that say
 *       the row is reading a refusal and not a count.  Both perturbations
 *       were restored and the gate returned to `checks=488 failures=0
 *       cases=8`.
 *
 * AND A THIRD THING WENT RED BEFORE ANY EXPECTATION WAS WRITTEN, recorded here
 * because it is the same defect this project keeps meeting: the first
 * executable version copied the emitted bytes out of `text` after EVERY stage,
 * and `build_object` leaves the NXO container in that one buffer.  Three of
 * eight cases were red comparing the expected `90 c3` against the object's
 * `4e 58` -- the NXO magic -- with every code and every report word already
 * correct.  The capture is now bound to the one stage whose output is the
 * program's text.  It is written here because the fix looks arbitrary without
 * it, and an unexplained line in a gate is an invitation to "simplify" it back
 * into the bug.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", m);                                        \
    }                                                                          \
  } while (0)

#define WORDS 262144
#define TEXT 1048576
#define REPORT 256
#define GUARD UINT64_C(0xcccccccccccccccc)

#define BANNER "NTASM_NOVA_MACHINE_X64 checks=%u failures=%u cases=%u"

/* Every module the entry reaches, by import closure: machine_x64 imports
 * machine_ir, x64_fixed and ntasm_nxo; machine_ir imports ntir and
 * register_widths; ntir imports ntasm_ast and register_widths; ntasm_ast
 * imports nothing; and machine_x64_entry imports the parser, the lexer, ntir,
 * machine_ir, machine_x64 and ir_image, ir_image importing ntasm_pe. */
static const char *const PATHS[] = {
    "tests/nova/tests/machine-x64-entry.nova",
    "compiler/nova/backend/x64/machine_x64.nova",
    "compiler/nova/ir/machine_ir.nova",
    "compiler/nova/formats/ntir/ntir.nova",
    "compiler/nova/backend/x64/x64_fixed.nova",
    "compiler/nova/formats/nxo/nxo.nova",
    "compiler/nova/ir/ir_image.nova",
    "compiler/nova/formats/pe/pe.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/lexer.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/analysis/types/pointer_spaces.nova",
    "compiler/nova/frontend/versions.nova"};
#define PATHS_N ((unsigned)(sizeof PATHS / sizeof PATHS[0]))

static char *loadf(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *p = n >= 0 ? (char *)malloc((size_t)n + 1) : NULL;
  if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) {
    free(p);
    fclose(f);
    return NULL;
  }
  fclose(f);
  p[n] = 0;
  *length = (size_t)n;
  return p;
}

/* THE CORPUS, written out in full and byte for byte, because the bodies are
 * inputs and not descriptions.  Four shape classes, eight rows:
 *
 *   ZERO-OPERAND GREEN   the only forms the consumer can encode today: NOP and
 *                        a `return` with no operand.  Three of them, because
 *                        one green case is a single point and the three differ
 *                        in the TEXT they must produce (`c3`, `90 c3`,
 *                        `90 90 c3`), which is the part worth pinning.
 *   OPERAND ON A RETURN  `return 0` / `return 42`.  The `0` is an OPERAND on the
 *                        return record, and the operand count is 1, so the
 *                        return is refused at the same E_REGISTER line the
 *                        two-operand `add` is -- with a DIFFERENT report[2],
 *                        30 (OP_RET) against 2 (OP_ADD).
 *   TWO-OPERAND, COVERED `add rax, 1` and `add rax, rcx`.  Both operands are
 *                        named registers and the opcode IS covered, so the
 *                        refusal is E_REGISTER: well formed, no assignment.
 *   TWO-OPERAND, UNCOVERED
 *                        `mov rax, 1` and `sub rax, 1`.  The same shape, and
 *                        the refusal is E_OPCODE one line earlier.
 *
 * The immediate and register variants are both present on purpose: `add rax,1`
 * and `add rax,rcx` are the SAME case to the checker, and a gate that only
 * carried the immediate would not know that, because it would have no row that
 * could disagree. */
typedef struct {
  const char *name;
  const char *body;
} Body;

#define PROLOGUE "module m\ntarget x86_64-nexora-none\nsection .text {\n" \
                 "fn main()->u64\neffects {}\nclobbers "
#define EPILOGUE "}\n}\n"

static const Body BODIES[] = {
    {"nop;return", PROLOGUE "{} {\nnop\nreturn\n" EPILOGUE},
    {"return", PROLOGUE "{} {\nreturn\n" EPILOGUE},
    {"nop;nop;return", PROLOGUE "{} {\nnop\nnop\nreturn\n" EPILOGUE},
    {"return 0", PROLOGUE "{rax} {\nnop\nreturn 0\n" EPILOGUE},
    {"add rax,1", PROLOGUE "{rax} {\nnop\nadd rax, 1\nreturn rax\n" EPILOGUE},
    {"add rax,rcx", PROLOGUE "{rax} {\nnop\nadd rax, rcx\nreturn rax\n" EPILOGUE},
    {"mov rax,1", PROLOGUE "{rax} {\nnop\nmov rax, 1\nreturn rax\n" EPILOGUE},
    {"sub rax,1", PROLOGUE "{rax} {\nnop\nsub rax, 1\nreturn rax\n" EPILOGUE},
};
#define BODIES_N ((unsigned)(sizeof BODIES / sizeof BODIES[0]))

/* THE SIX STAGES, by the entry's own mode number, with the precondition each
 * one names.  `pre` is the mode that must have run into the same buffers
 * first: 0 means none. */
typedef struct {
  uint64_t mode;
  uint64_t pre;
  const char *label;
} Stage;

static const Stage STAGES[] = {
    {2, 0, "ntir.build"},          /* parse + ntir.build into `words`      */
    {4, 2, "machine_ir.lower"},    /* lower `words` into `out`, no verify   */
    {0, 0, "verify+constraints"},  /* the whole pipeline up to the checker  */
    {1, 0, "emit_text"},           /* the whole pipeline plus emission      */
    {7, 4, "serialize"},           /* over the image mode 4 just produced  */
    {8, 4, "build_object"},        /* over the image mode 4 just produced  */
};
#define STAGES_N ((unsigned)(sizeof STAGES / sizeof STAGES[0]))

/* WHAT EACH STAGE ANSWERS, per body.  Six codes, then the four report words
 * read off the `verify+constraints` stage, then the emitted bytes when the
 * body is green.  Every number here was MEASURED on this tree; none is
 * derived from the source by reading, and the codes in particular are not
 * W133's or this file's guess at them. */
typedef struct {
  const char *name;
  uint64_t code[STAGES_N];
  /* report[0..3] after `verify+constraints`.  On a green row report[0] is the
   * RECORD COUNT and report[2] the EXECUTABLE COUNT (constraints' accepting
   * tail); on a red row report[0] is the RECORD ID and report[2] the OPCODE
   * (place()).  The green rows are marked in the comment beside each. */
  uint64_t report[4];
  uint64_t text_len;              /* 0 when the body is refused            */
  const uint8_t *text;            /* NULL when the body is refused         */
} Expectation;

#define OP_NONE_ 0
static const uint8_t T_RET[] = {0xc3};
static const uint8_t T_NOP_RET[] = {0x90, 0xc3};
static const uint8_t T_2NOP_RET[] = {0x90, 0x90, 0xc3};

static const Expectation EXPECT[] = {
    /* MIR1.1 adds one return-signature metadata record before each body. */
    /* green: report = [RECORD COUNT, 0, EXECUTABLE COUNT, 0] */
    {"nop;return",     {0, 0, 0, 0, 0, 0}, {10, 0, 2, 0}, 2, T_NOP_RET},
    {"return",         {0, 0, 0, 0, 0, 0}, {9, 0, 1, 0}, 1, T_RET},
    {"nop;nop;return", {0, 0, 0, 0, 0, 0}, {11, 0, 3, 0}, 3, T_2NOP_RET},
    /* red: report = [RECORD ID, CODE, OPCODE, OPERAND COUNT].
     *
     * The opcodes below are 30 for OP_RET, 2 for OP_ADD, 1 for OP_COPY and 3
     * for OP_SUB, read at machine_ir.nova's own `export fn OP_...` constants.
     * They are not renumbered here: a module that renumbers them makes this
     * gate red on a fact it exists to report, and a gate that fails for a
     * reason its own comment denies is a gate nobody reads.  report[3] is the
     * OPERAND COUNT `constraints` read off the record -- 1 for the
     * return-with-a-value, 2 for every `mir_asm` -- and it is the number that
     * makes the 961/963 split legible, because the operand count is the SAME
     * on both sides of it. */
    {"return 0",       {0, 0, 963, 963, 0, 963}, {12, 963, 30, 1}, 0, NULL},
    {"add rax,1",      {0, 0, 962, 962, 0, 962}, {12, 962, 2, 2}, 0, NULL},
    {"add rax,rcx",    {0, 0, 962, 962, 0, 962}, {12, 962, 2, 2}, 0, NULL},
    {"mov rax,1",      {0, 0, 962, 962, 0, 962}, {12, 962, 1, 1}, 0, NULL},
    {"sub rax,1",      {0, 0, 962, 962, 0, 962}, {12, 962, 3, 2}, 0, NULL},
};
#define EXPECT_N ((unsigned)(sizeof EXPECT / sizeof EXPECT[0]))

typedef struct {
  uint64_t returned, runtime;
  uint64_t *words;   /* the NTIR image        */
  uint64_t *image;   /* the Machine IR image  */
  uint64_t *report;
  uint64_t length[4];
  uint8_t *text;
} Run;

static void run_init(Run *r) {
  r->words = (uint64_t *)malloc(WORDS * sizeof(uint64_t));
  r->image = (uint64_t *)malloc(WORDS * sizeof(uint64_t));
  r->report = (uint64_t *)malloc(REPORT * sizeof(uint64_t));
  r->text = (uint8_t *)malloc(TEXT);
  memset(r->text, 0xcc, TEXT);
}
static void run_free(Run *r) {
  free(r->words);
  free(r->image);
  free(r->report);
  free(r->text);
}

/* ONE ENTRY CALL.  Ten parameters of which six are buffers, so SIXTEEN flat
 * slots; each buffer takes a handle and an ELEMENT count.  Dropping one slot
 * shifts every later one and the boundary answers NV2_LIFETIME with a zero and
 * nothing written, which reads exactly like a buffer bug and is an
 * argument-count bug.
 *
 * `report`, `length` and `text` are re-guarded on EVERY call and NOT the two
 * image buffers: `report` and `text` are OUTPUTS, so a buffer left at the
 * guard is a stage that wrote nothing, while `words` and `image` are the
 * entry's own scratch and are carried from the stage that fills them. */
static uint64_t run(const NovaHostImage *image, const char *source, size_t size,
                    uint64_t mode, Run *r) {
  NovaContextV2 c = {0};
  for (unsigned i = 0; i < REPORT; i++)
    r->report[i] = GUARD;
  for (unsigned i = 0; i < 4; i++)
    r->length[i] = GUARD;
  memset(r->text, 0xcc, TEXT);
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)source, size, 0);
  uint64_t wh = nova_borrow_v2(&c, r->words, WORDS * sizeof(uint64_t), 1);
  uint64_t ih = nova_borrow_v2(&c, r->image, WORDS * sizeof(uint64_t), 1);
  uint64_t th = nova_borrow_v2(&c, r->text, TEXT, 1);
  uint64_t lh = nova_borrow_v2(&c, r->length, 4 * sizeof(uint64_t), 1);
  uint64_t rh = nova_borrow_v2(&c, r->report, REPORT * sizeof(uint64_t), 1);
  uint64_t args[] = {sh,     size,   mode,  0,     wh, WORDS, WORDS, ih,
                     WORDS,  WORDS,  th,    TEXT,  lh, 4,     rh,    REPORT};
  r->returned = image->entry(&c, args, 16);
  r->runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return r->returned;
}

/* ONE VERDICT PER STAGE.  `out` receives the code; the report and the text
 * length are returned through pointers so the caller can pin them without
 * running the stage twice. */
typedef struct {
  uint64_t code[STAGES_N];
  uint64_t report[4];
  uint64_t text_len;
  uint8_t text[TEXT];
} Verdict;

static void measure(const NovaHostImage *image, const char *body, Verdict *v) {
  Run r;
  run_init(&r);
  size_t len = strlen(body);
  for (unsigned s = 0; s < STAGES_N; s++) {
    /* The precondition, in the same buffers: mode 2 fills `words` and mode 4
     * fills `image`, and modes 5/6/7/8 read `image`.  Running a stage without
     * it answers 946 or 800, which is the entry refusing a damaged image and
     * is NOT the pipeline's verdict on the body. */
    if (STAGES[s].pre)
      run(image, body, len, STAGES[s].pre, &r);
    v->code[s] = run(image, body, len, STAGES[s].mode, &r);
    if (STAGES[s].mode == 0)
      for (unsigned k = 0; k < 4; k++)
        v->report[k] = r.report[k];
    /* The bytes are captured HERE and nowhere else, and the reason is a bug
     * this file shipped once: `text` is ONE buffer that every emitting stage
     * writes, so `build_object` leaves the NXO container in it and `serialize`
     * leaves the IR dump.  Copying on every stage therefore compared the
     * EXPECTED `90 c3` against the OBJECT's `4e 58` -- the NXO magic -- and the
     * gate was red on three of its eight cases for a reason that had nothing
     * to do with the checker.  Captured at the one stage whose output is the
     * program's text, and never re-read afterwards. */
    if (STAGES[s].mode == 1) {
      v->text_len = r.length[0];
      if (v->text_len > 0 && v->text_len < TEXT)
        memcpy(v->text, r.text, (size_t)v->text_len);
    }
  }
  run_free(&r);
}

static const char *stage_label(unsigned s) { return STAGES[s].label; }

int main(void) {
  size_t sizes[PATHS_N] = {0};
  char *sources[PATHS_N] = {0};
  NtFInput inputs[PATHS_N];
  int all = 1;
  for (unsigned i = 0; i < PATHS_N; i++) {
    sources[i] = loadf(PATHS[i], &sizes[i]);
    if (!sources[i])
      all = 0;
    inputs[i] = (NtFInput){PATHS[i], sources[i], sizes[i]};
  }
  CHECK(all, "the fourteen Nova sources load");
  if (!all) {
    printf(BANNER "\n", checks, failures, cases);
    return 1;
  }

  /* TWO INDEPENDENTLY COMPILED IMAGES of the same bytes, and every case is
   * measured on both.  One image is a single sample; two is the project's
   * standing answer to "a module interpreted into a host image", and a
   * disagreement between them is reported by name. */
  NtArtifact first = {0}, second = {0};
  int c1 = nova_compile_many_v2(inputs, PATHS_N, &first);
  int c2 = nova_compile_many_v2(inputs, PATHS_N, &second);
  CHECK(c1, "the Nova sources compile");
  CHECK(c2, "the Nova sources compile a second time");
  if (!c1 || !c2) {
    if (!c1)
      fprintf(stderr, "E%u %zu:%zu %s\n", first.error.code, first.error.line,
              first.error.column, first.error.message);
    if (!c2)
      fprintf(stderr, "E%u %zu:%zu %s\n", second.error.code, second.error.line,
              second.error.column, second.error.message);
    printf(BANNER "\n", checks, failures, cases);
    return 1;
  }
  NovaHostImage ia = {0}, ib = {0};
  CHECK(nova_host_map(&first, &ia), "the first image maps");
  CHECK(nova_host_map(&second, &ib), "the second image maps");
  if (!ia.memory || !ib.memory) {
    for (unsigned i = 0; i < PATHS_N; i++)
      free(sources[i]);
    printf(BANNER "\n", checks, failures, cases);
    return 1;
  }

  /* The expectation table is keyed BY NAME against the corpus, not by index.
   * Two arrays walked in step read identically whether they agree, and the
   * failure mode of a row that has drifted is a case measured against another
   * case's verdict -- which is the "one body per process" artefact in a slower
   * form.  A name is checkable by reading it. */
  CHECK(EXPECT_N == BODIES_N, "one expectation per corpus body");
  if (EXPECT_N == BODIES_N) {
    for (unsigned i = 0; i < BODIES_N; i++)
      CHECK(strcmp(BODIES[i].name, EXPECT[i].name) == 0,
            "the expectation table and the corpus are in the same order");
  }

  for (unsigned i = 0; i < BODIES_N && i < EXPECT_N; i++) {
    const Body *b = &BODIES[i];
    const Expectation *e = &EXPECT[i];
    Verdict v1, v2;
    memset(&v1, 0, sizeof v1);
    memset(&v2, 0, sizeof v2);
    /* BOTH PASSES, ON BOTH IMAGES.  A sweep that has produced a wrong answer
     * once is not trusted to produce a right one silently. */
    measure(&ia, b->body, &v1);
    measure(&ib, b->body, &v2);
    cases++;
    printf("CASE %-16s", b->name);
    for (unsigned s = 0; s < STAGES_N; s++)
      printf(" %s=%llu", stage_label(s), (unsigned long long)v1.code[s]);
    printf(" report=[%llu %llu %llu %llu] text=%llu\n",
           (unsigned long long)v1.report[0], (unsigned long long)v1.report[1],
           (unsigned long long)v1.report[2], (unsigned long long)v1.report[3],
           (unsigned long long)v1.text_len);

    for (unsigned s = 0; s < STAGES_N; s++) {
      /* The buffer is sized so `-Werror=format-truncation` can PROVE the
       * message fits rather than warn and be silenced.  A FAIL line a reader
       * cannot see whole is a failure reported for the wrong reason. */
      char msg[256];
      snprintf(msg, sizeof msg,
               "%s: %s answers %llu and this gate expects %llu -- the stage "
               "moved, or the checker stopped refusing",
               b->name, stage_label(s), (unsigned long long)v1.code[s],
               (unsigned long long)e->code[s]);
      CHECK(v1.code[s] == e->code[s], msg);
    }
    for (unsigned k = 0; k < 4; k++) {
      char msg[320];
      snprintf(msg, sizeof msg,
               "%s: report[%u] is %llu and this gate expects %llu -- report[0] "
               "is the record id on a refusal and the record count on an "
               "acceptance, and the other three words are place()'s",
               b->name, k, (unsigned long long)v1.report[k],
               (unsigned long long)e->report[k]);
      CHECK(v1.report[k] == e->report[k], msg);
    }
    /* The bytes, where the pipeline is green.  A length AND the content: a
     * length alone would pass on a producer that emitted the right NUMBER of
     * wrong bytes, which is the failure this gate is for. */
    if (e->text) {
      CHECK(v1.text_len == e->text_len,
            "the emitted length is the one this gate pins");
      if (v1.text_len == e->text_len && e->text_len > 0) {
        int same = memcmp(v1.text, e->text, (size_t)e->text_len) == 0;
        if (!same) {
          fprintf(stderr, "  emitted:");
          for (unsigned k = 0; k < (unsigned)e->text_len; k++)
            fprintf(stderr, " %02x", v1.text[k]);
          fprintf(stderr, "\n  expected:");
          for (unsigned k = 0; k < (unsigned)e->text_len; k++)
            fprintf(stderr, " %02x", e->text[k]);
          fprintf(stderr, "\n");
        }
        CHECK(same, "the emitted bytes are the ones this gate pins");
      }
    } else {
      /* A refused body must emit NOTHING.  `length` is re-guarded on every
       * call, so this distinguishes "wrote no length" from "wrote zero", and
       * a producer that emitted bytes and THEN refused would be caught. */
      CHECK(v1.text_len == 0,
            "a refused body emits no text: the refusal is before the byte, "
            "which is the whole claim");
    }

    /* The two images must agree, and so must the two passes of one body. */
    for (unsigned s = 0; s < STAGES_N; s++) {
      char msg[160];
      snprintf(msg, sizeof msg,
               "%s: %s answers %llu on the first image and %llu on the second, "
               "so the verdict is a property of the compiler and not of the "
               "image", b->name, stage_label(s), (unsigned long long)v1.code[s],
               (unsigned long long)v2.code[s]);
      CHECK(v1.code[s] == v2.code[s], msg);
    }
    for (unsigned k = 0; k < 4; k++) {
      char msg[160];
      snprintf(msg, sizeof msg,
               "%s: report[%u] is %llu on the first image and %llu on the "
               "second", b->name, k, (unsigned long long)v1.report[k],
               (unsigned long long)v2.report[k]);
      CHECK(v1.report[k] == v2.report[k], msg);
    }
    CHECK(v1.text_len == v2.text_len,
          "the emitted length is the same on both images");
    if (v1.text_len == v2.text_len && v1.text_len > 0 && v1.text_len < TEXT)
      CHECK(memcmp(v1.text, v2.text, (size_t)v1.text_len) == 0,
            "the emitted bytes are the same on both images");
  }

  /* Each new metadata word is rejected before every emission face, even
   * when the old opcode-only subset would accept this nop/return image. */
  {
    Run r; run_init(&r); const char *src=BODIES[0].body;
    CHECK(run(&ia,src,strlen(src),2,&r)==0,"legacy mutation NTIR builds");
    CHECK(run(&ia,src,strlen(src),4,&r)==0,"legacy mutation MIR lowers");
    const uint64_t hw=10,nw=r.image[5]; uint64_t record=0;
    for(uint64_t id=1;id<=r.image[3];id++) if(r.image[hw+(id-1)*nw]==2065){record=id;break;}
    CHECK(record!=0&&nw==24,"real legacy-accepted image has an asm record and stride24");
    const uint64_t modes[]={5,6,8};
    for(unsigned field=20;field<24;field++) {
      if(!record)continue;
      const uint64_t at=hw+(record-1)*nw+field,old=r.image[at]; r.image[at]=1;
      for(unsigned m=0;m<3;m++) {
        const uint64_t code=run(&ia,src,strlen(src),modes[m],&r);
        CHECK(code==962&&r.runtime==0&&r.report[0]==record,"legacy rejects explicit MIR1.0 metadata before emission");
        CHECK(r.length[0]==0,"legacy metadata refusal delivers no bytes");
      }
      r.image[at]=old;
    }
    CHECK(run(&ia,src,strlen(src),5,&r)==0,"restored metadata-free subset is accepted");
    run_free(&r);
  }
  /* Keep the former opcode/register distinction as a constraint-level test
   * with all runtime metadata explicitly erased. These damaged images must
   * still refuse, never emit guessed operands. The source-facing cases above
   * instead demand the earlier MIR1.0 E_FORM refusal. */
  {
    const unsigned ids[]={4,6,7}; const uint64_t expected[]={963,961,961};
    for(unsigned n=0;n<3;n++) {
      Run r;run_init(&r);const char *src=BODIES[ids[n]].body;
      CHECK(run(&ia,src,strlen(src),2,&r)==0,"legacy opcode probe NTIR builds");
      CHECK(run(&ia,src,strlen(src),4,&r)==0,"legacy opcode probe MIR lowers");
      for(uint64_t id=1;id<=r.image[3];id++)for(unsigned f=20;f<24;f++)r.image[10+(id-1)*r.image[5]+f]=0;
      const uint64_t code=run(&ia,src,strlen(src),5,&r);
      CHECK(code==expected[n]&&r.runtime==0,"metadata-free legacy opcode/register refusal remains distinct");
      run_free(&r);
    }
  }

  for (unsigned i = 0; i < PATHS_N; i++)
    free(sources[i]);
  nova_host_unmap(&ia);
  nova_host_unmap(&ib);
  nt_artifact_free(&first);
  nt_artifact_free(&second);
  printf(BANNER "\n", checks, failures, cases);
  return failures ? 1 : 0;
}
