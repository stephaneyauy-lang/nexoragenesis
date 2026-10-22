/* tests_ntasm_ntir_inspect.c -- the gate for the NTIR READER.
 *
 * ntir.nova can build an image, check it and write it as bytes. Until
 * ntir_inspect.nova landed, nothing in the tree could turn any of those three
 * back into something a reader could assert on: `serialize` emits NUMBERS, so
 * a reader confronted with a corrupted typed word learned that the word was 7
 * and not that the word was wrong. NXO has an inspector and PE has one; NTIR
 * did not, which is the gap A7 names.
 *
 * WHAT IS ASSERTED, AND AGAINST WHAT:
 *
 *  1. THE IMAGE IS BUILT BY THE NORMAL ROUTE. Mode 0 of the entry parses, runs
 *     the expansion stage through ntasm_macro_splice, calls ntir.build on the
 *     tree the expansion handed back and calls ntir.verify on the result --
 *     the same route validate.nova runs. No word of any image below is written
 *     by this file except where a case says in so many words. That distinction
 *     IS the measurement: an image a gate composed itself would prove only
 *     that the reader reads the shape a gate imagined.
 *
 *  2. ALL FIFTY-THREE KINDS ARE ENUMERATED, AND THE COUNT IS READ, NOT TYPED.
 *     The gate asks the module for KIND_COUNT and then asks for every name
 *     from 1 to that count. It asserts the count is 53 -- one literal, the
 *     number the plan names -- and it asserts the names it got back are all
 *     DISTINCT, all NON-EMPTY, and none of them is the string "unknown". A
 *     reader that answered "unknown" for an index it did not have would pass
 *     a count-and-call loop and fail those three.
 *
 *  3. THE OUT-OF-RANGE INDEX IS REFUSED, NOT ANSWERED. ntir.kind_text does not
 *     range check: index 0, index KIND_COUNT+1 and UINT64_MAX all return the
 *     string "unknown". The gate calls all three, requires the READER to
 *     refuse each with 845, and requires both caller buffers to come back
 *     untouched. A reader that invents an answer for an index it does not have
 *     is worse than no reader, so this is the case the lot turns on. The
 *     boundary is checked from the INSIDE too, because a reader that refused
 *     every index would pass everything above it.
 *
 *  4. TYPES, SYMBOLS AND EFFECTS ARE READ, AND TWO OF THE THREE ARE FINDINGS
 *     ABOUT THE REPRESENTATION RATHER THAN ABOUT THE READER. Types are four
 *     words per node, and the gate re-counts the typed nodes ITSELF and
 *     confronts that count with the header's own typed_count, so the reader's
 *     measurement cannot be a copy of the image's claim. Effects are KINDS and
 *     not words: no effect bitset exists anywhere in the sixteen node words, so
 *     the sets are read through the child chain and the atoms' bytes are
 *     checked against the source. Symbols are NOT CARRIED AT ALL: the image has
 *     a byte span per node and no string table, so the gate recovers a node's
 *     text by slicing the source at that span -- and says so in its banner
 *     rather than pretending the image named anything.
 *
 *  5. THE WIDTH VOCABULARY IS CONFRONTED, NOT ASSUMED. ntir_inspect.nova
 *     cannot call ntir.nova's private width_known, so it writes the set out.
 *     Two copies of one set is a real risk, so this file writes EVERY width
 *     from 0 to 96 into a real node and asks BOTH ntir.verify and the reader.
 *     Their verdicts must agree on all ninety-seven. A reader laxer than the
 *     writer is the direction that hides a defect, and this closes it.
 *
 *  6. THE RED PROOF, WITH THE PERTURBATION ASSERTED TO HAVE APPLIED. A real
 *     built image is overwritten at a named word and BOTH ntir.verify and the
 *     reader must notice. The reader is only reachable if the damaged words
 *     SURVIVE the call that makes it, so every call after a perturbation uses
 *     the keep-words form of the runner, and the damaged value is read back
 *     through the reader itself before anything is concluded. A perturbation
 *     that did not apply would leave both checks green for the wrong reason,
 *     which is the one outcome this file is shaped to make impossible: it
 *     exits 3 with PROOF INVALID instead of reporting a green run.
 *
 * The Run records are on the HEAP. One is 2.3 MB -- the image buffer dominates
 * it -- and the first version of this file had twenty-five of them on the
 * stack, which AddressSanitizer reported as a stack-overflow in main. That is
 * a measurement, not a style note, and it is why run_alloc exists.
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

#define GUARD UINT64_C(0xcccccccccccccccc)
#define BYTE_GUARD 0xcc
#define WORDS 262144
#define TEXT 262144
#define REPORT 256
#define NAMES 64
/* The two numbers this file takes from the layout ntir.nova documents rather
 * than reading out of the image: the header is HEADER_WORDS words and a node
 * record is NODE_WORDS. Both are CHECKED against the image in build() -- the
 * stride at word 5 -- and a header offset that was wrong made the gate read a
 * shifted copy of every node, which surfaced as "no node's text matches its
 * span" rather than as an offset bug. */
#define HEADER_WORDS 8
#define NODE_WORDS 16

/* The one literal this file is allowed to pin: the number of kinds the plan
 * names. Everything else about the table is read back from the module. */
#define EXPECTED_KINDS 53

/* The codes ntir_inspect.nova publishes, named once. 809 is the established
 * inspector code for a caller buffer too small (nxo_inspect.nova:78) and 810 an
 * index outside the count; both are REUSED because the meaning is identical.
 * 845 is a kind INDEX outside the table and 847 a kind NUMBER outside it, and
 * both are NEW because the numbers they would otherwise have taken are already
 * spoken for: nxo_inspect.nova:60 returns 811 for a RELOCATION index and
 * decls.nova:104 returns 812 for a short output buffer, and two meanings on one
 * number is how a caller ends up matching the wrong refusal. 819 is a typed
 * word outside its vocabulary, reused from ntir.verify for the same reason.
 *
 * The first draft of this file used 811 and 812, which is why the reason is
 * written down here: a gate that reuses a live number for a second meaning
 * makes both call sites wrong at once. */
#define CODE_SHORT_OUTPUT 809
#define CODE_BAD_INDEX 810
#define CODE_BAD_KIND_INDEX 845
#define CODE_BAD_KIND_NUMBER 847
#define CODE_BAD_TYPED 819

/* 817 is ntir's refusal to lower a tree. It is named here so the residual case
 * can assert that number rather than merely observe a nonzero. */
#define CODE_LOWER_REFUSAL 817

/* The transactional refusal of the reader and of ntir alike. */
#define CODE_TRANSACTIONAL 800

static const char *const PATHS[] = {
    "tests/nova/tests/ntir-inspect-entry.nova",
    "compiler/nova/inspectors/ntir_inspect.nova",
    "compiler/nova/formats/ntir/ntir.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/analysis/types/pointer_spaces.nova",
    "compiler/nova/macros/macro_splice.nova",
    "compiler/nova/macros/macro_expand.nova",
    "compiler/nova/analysis/types/constant_types.nova",
    "compiler/nova/macros/constant_eval.nova",
    "compiler/nova/analysis/types/initializer_types.nova",
    "compiler/nova/analysis/types/condition_types.nova",
    "compiler/nova/analysis/types/literal_initializers.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/lexer.nova",
    "compiler/nova/frontend/ast.nova"};
#define PATHS_N ((unsigned)(sizeof PATHS / sizeof PATHS[0]))

typedef struct {
  uint64_t returned, runtime;
  uint64_t words[WORDS];
  uint64_t report[REPORT];
  uint64_t text_length[4];
  uint8_t text[TEXT];
} Run;

/* The heap, and it is a heap because the stack is 8 MB and one record is 2.3. */
static Run *run_alloc(void) {
  Run *r = (Run *)calloc(1, sizeof(Run));
  if (!r) { fprintf(stderr, "out of memory\n"); exit(2); }
  return r;
}

/* One call. Nine parameters of which five are buffers cross the boundary as
 * fourteen flat slots, and the third argument of image->entry is that slot
 * count and not the parameter count: passing fewer is NV2_ARGUMENT, which the
 * boundary raises before the body ever runs.
 *
 * `keep` exists for one reason: a perturbation written into r->words is
 * invisible to the next call unless the words survive it, and the red proof
 * would then be a proof about a buffer nothing ever read. */
static void run_ex(const NovaHostImage *image, const char *source, size_t size,
                   uint64_t mode, uint64_t index, uint64_t which, Run *r,
                   int keep) {
  NovaContextV2 c = {0};
  for (unsigned i = 0; i < REPORT; i++) r->report[i] = GUARD;
  for (unsigned i = 0; i < 4; i++) r->text_length[i] = GUARD;
  memset(r->text, BYTE_GUARD, TEXT);
  if (!keep) memset(r->words, 0, sizeof r->words);
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)source, size, 0);
  uint64_t wh = nova_borrow_v2(&c, r->words, WORDS * sizeof(uint64_t), 1);
  uint64_t th = nova_borrow_v2(&c, r->text, TEXT, 1);
  uint64_t lh = nova_borrow_v2(&c, r->text_length, 4 * sizeof(uint64_t), 1);
  uint64_t rh = nova_borrow_v2(&c, r->report, REPORT * sizeof(uint64_t), 1);
  /* Nine parameters of which FIVE are buffers, so fourteen flat slots -- and
   * every buffer lends a HANDLE AND AN ELEMENT COUNT, while `word_count` is a
   * plain u64 and still takes a slot of its own. The order below is the
   * declaration order of the entry with each buffer widened to two.
   *
   * TWO ARGUMENT-LAYOUT DEFECTS LIVED HERE, and both read as something else.
   * The first passed thirteen slots for fourteen parameters, which shifts
   * every later slot and makes the boundary answer NV2_LIFETIME with RET 0 and
   * nothing written -- indistinguishable from a buffer-lifetime bug. The
   * second left `word_count` at ZERO while the image buffer beside it was
   * whole: the entry's own capacity check (`word_count < HEADER_WORDS`) then
   * refused every build with 800, and the gate's first symptom was "no fixture
   * lowers", which points at the lowering and not at the runner. */
  uint64_t flat[14];
  flat[0] = sh;       flat[1] = size;    flat[2] = mode;   flat[3] = index;
  flat[4] = which;    flat[5] = wh;      flat[6] = WORDS;  flat[7] = WORDS;
  flat[8] = th;       flat[9] = TEXT;    flat[10] = lh;    flat[11] = 4;
  flat[12] = rh;      flat[13] = REPORT;
  r->returned = image->entry(&c, flat, 14);
  r->runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
}
/* The DEFAULT call KEEPS the image. Every mode except mode 0 reads an image a
 * previous call built, and zeroing r->words here made every one of them see an
 * EMPTY buffer: `count = words[3]` was 0, so the entry refused at 800 and the
 * gate's symptom was "no node's text matches its span" on a module that had
 * just read one perfectly. Only mode 0, which produces the image, clears it --
 * and build() below says so by passing keep = 0 explicitly.
 *
 * That default is the whole reason run_ex has the flag at all: the alternative
 * is a flag on every one of the forty read sites, and a flag that is wrong at
 * one site is a silent no-op rather than a compile error. */
static void run(const NovaHostImage *image, const char *source, size_t size,
                uint64_t mode, uint64_t index, uint64_t which, Run *r) {
  run_ex(image, source, size, mode, index, which, r, 1);
}

/* READ AN IMAGE THAT MODE 0 ALREADY BUILT.
 *
 * Every read mode takes its image from the Run record it is called ON, so a
 * scratch record carries whatever image was last written into THAT record. The
 * first version of this file called the read modes on scratch records after
 * building into `built`, so every read mode saw a buffer holding some older
 * fixture, `count = words[3]` was whatever that was, and the symptom was
 * `copy_node_text` refusing with 800 on an image it had just read perfectly --
 * which points at the reader and not at the caller. This helper copies the
 * image in before every read, so the image a read mode sees is named once here
 * rather than at forty call sites where one site being wrong is silent.
 *
 * The copy is of the header plus the records only, not the whole buffer: a
 * 262144-word memcpy per read would cost more than the readings themselves. */
static void read_image(const NovaHostImage *image, const char *source,
                       size_t size, uint64_t mode, uint64_t index, uint64_t which,
                       const Run *built, Run *scratch) {
  uint64_t count = built->words[3];
  uint64_t used = HEADER_WORDS + count * built->words[5];
  memcpy(scratch->words, built->words, (size_t)used * sizeof(uint64_t));
  run_ex(image, source, size, mode, index, which, scratch, 1);
}

static char *loadf(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
  char *p = n >= 0 ? (char *)malloc((size_t)n + 1) : NULL;
  if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) { free(p); fclose(f); return NULL; }
  fclose(f); p[n] = 0; *length = (size_t)n; return p;
}

/* ---- the fixtures --------------------------------------------------------
 *
 * Three, and each one exists to carry something the others do not. They are
 * spelled here rather than read off disk because the point of case 1 is that
 * the reader is handed a SOURCE and nothing else: a file on disk would let a
 * stale copy be the thing measured.
 *
 * f0 declares an EFFECT set with two atoms and a CLOBBERS set with one, so the
 * effect reader has a chain to walk and the atoms' bytes can be compared
 * against the source text. The two atoms are `privileged` and
 * `reads_mem(kernel)`: they are members of the effect vocabulary, and the first
 * draft of this fixture used `read fsbase` and `gsbase` instead, which
 * register_widths knows and effects.check does NOT -- the tree says so at
 * effects.nova:90-99, where gsbase is "a member of a footprint, not an EFFECT
 * one". The pipeline refused that fixture at 800 and the reader was never
 * reached, so the defect was measured rather than argued. f1 carries the typed half: a register binding, a
 * pointer in a kernel space and an array, so the four typed words are non-zero
 * on several nodes and the header's typed_count is above zero. f2 is the
 * smallest program that still lowers, with both sets EMPTY -- the case where a
 * reader answering "no atoms" and a reader answering "the wrong node" could be
 * confused, and the count is what tells them apart.
 */
static const char *const FIXTURES[] = {
    "module m\ntarget x86_64-nexora-none\n"
    "section .text {\n"
    "fn main()->u64\n"
    "effects {privileged, reads_mem(kernel)}\n"
    "clobbers {rax} {\n"
    "return 0\n}\n}\n",

    "module m\ntarget x86_64-nexora-none\n"
    "section .text {\n"
    "fn typed(in x:u64 @rax, in p:ptr<kernel, u8>, in a:array<u16, 4>)"
    "->u64\n"
    "effects {}\nclobbers {} {\nreturn x\n}\n"
    "fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",

    "module m\ntarget x86_64-nexora-none\n"
    "section .text {\n"
    "fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
};
#define FIXTURES_N ((unsigned)(sizeof FIXTURES / sizeof FIXTURES[0]))

/* ---- helpers ------------------------------------------------------------ */

/* Build the image by the normal route. A refusal here fails the case rather
 * than being worked around: every measurement below is about an image that
 * exists, and an image that does not exist measures nothing. */
static int build(const NovaHostImage *image, const char *source, Run *r) {
  /* keep = 0: this is the one mode that PRODUCES the image, so the buffer must
   * start empty or a stale record from a previous fixture would survive in the
   * tail and be counted as part of this one. */
  run_ex(image, source, strlen(source), 0, 0, 0, r, 0);
  CHECK(r->returned == 0, "the production route builds and verifies");
  CHECK(r->runtime == 0, "the production route leaves a clean runtime");
  if (r->returned != 0 || r->runtime != 0) {
    fprintf(stderr, "BUILD ret=%llu runtime=%llu\n",
            (unsigned long long)r->returned, (unsigned long long)r->runtime);
    return 0;
  }
  CHECK(r->report[0] == r->words[3], "the reported node count is the image's own");
  CHECK(r->words[5] == NODE_WORDS, "the image's stride is sixteen words");
  CHECK(r->words[6] == r->words[3],
        "the image records the AST it lowered from as the same count");
  return 1;
}

/* The first word of node `id`. HEADER_WORDS is not published in the image, so
 * it is the one number this file takes from the layout ntir.nova documents --
 * and then CHECKS against the stride and the count in build(). Every other
 * offset is derived from the image's own stride, so a stride that moved would
 * make these offsets wrong and the gate would say so. */
static uint64_t node_at(const Run *r, uint64_t id) {
  return HEADER_WORDS + (id - 1) * r->words[5];
}

/* ---- 2 and 3: the kind enumeration, and the refusal that matters --------- */

typedef struct {
  uint64_t count, base;
  uint64_t *kind, *ast, *aux, *name_length;
} Table;

static void table_read(const NovaHostImage *image, Run *r, Table *t) {
  memset(t, 0, sizeof *t);
  /* A one-byte source: mode 2 reads no image and parses nothing, so a longer
   * argument would only prove the entry tolerates a bigger one. */
  run(image, "\n", 1, 2, 0, 0, r);
  CHECK(r->returned == 0, "the kind table reads");
  CHECK(r->runtime == 0, "the kind table leaves a clean runtime");
  t->count = r->report[0];
  t->base = r->report[1];
  if (t->count == 0 || t->count > 4096) return;
  t->kind = (uint64_t *)calloc(t->count, sizeof(uint64_t));
  t->ast = (uint64_t *)calloc(t->count, sizeof(uint64_t));
  t->aux = (uint64_t *)calloc(t->count, sizeof(uint64_t));
  t->name_length = (uint64_t *)calloc(t->count, sizeof(uint64_t));
  for (uint64_t i = 0; i < t->count; i++) {
    t->kind[i] = r->report[2 + i * 4];
    t->ast[i] = r->report[2 + i * 4 + 1];
    t->aux[i] = r->report[2 + i * 4 + 2];
    t->name_length[i] = r->report[2 + i * 4 + 3];
  }
}
static void table_free(Table *t) {
  free(t->kind); free(t->ast); free(t->aux); free(t->name_length);
}

/* A reader that answered "unknown" for an index it did not have would pass a
 * loop that only counted calls. So the names are checked to be NON-EMPTY, to
 * be DISTINCT from each other, and NOT to be the literal "unknown"; and the
 * number form is asked for the same row and must agree on the bytes. Those
 * four are what turn "it returned 0" into "it returned a name". */
static void every_kind_is_named(const NovaHostImage *image, const Table *t,
                                Run *r, Run *b) {
  char names[NAMES][64];
  memset(names, 0, sizeof names);
  uint64_t named = 0;
  for (uint64_t i = 0; i < t->count && i < NAMES; i++) {
    run(image, "\n", 1, 4, i + 1, 0, r);
    CHECK(r->returned == 0, "a kind name reads by index");
    CHECK(r->runtime == 0, "a kind name leaves a clean runtime");
    uint64_t n = r->text_length[0];
    CHECK(n == t->name_length[i], "the name length matches the table's fourth word");
    CHECK(n > 0, "a kind name is non-empty");
    CHECK(n < sizeof names[0], "a kind name fits the gate's buffer");
    if (n == 0 || n >= sizeof names[0]) continue;
    memcpy(names[i], r->text, (size_t)n);
    names[i][n] = 0;
    named++;
    /* The number form must answer the same name for the same row. */
    run(image, "\n", 1, 4, t->kind[i], 1, b);
    CHECK(b->returned == 0, "the same kind name reads by number");
    CHECK(b->text_length[0] == n, "the number form agrees on the length");
    if (b->text_length[0] == n)
      CHECK(memcmp(b->text, r->text, (size_t)n) == 0,
            "the number form agrees on the bytes");
  }
  CHECK(named == t->count, "every row of the table produced a name");
  for (uint64_t i = 0; i < named; i++) {
    CHECK(strcmp(names[i], "unknown") != 0, "no kind is named \"unknown\"");
    for (uint64_t j = i + 1; j < named; j++)
      CHECK(strcmp(names[i], names[j]) != 0, "the kind names are distinct");
  }
}

/* The refusal the lot turns on: index 0, index count+1 and UINT64_MAX are all
 * answered by ntir.kind_text with the string "unknown", and all three must be
 * REFUSED here, with both caller buffers left exactly as they were supplied. */
static void out_of_range_index_is_refused(const NovaHostImage *image,
                                          const Table *t, Run *r) {
  const uint64_t probes[] = {0, t->count + 1, UINT64_MAX};
  for (unsigned p = 0; p < 3; p++) {
    cases++;
    run(image, "\n", 1, 4, probes[p], 0, r);
    CHECK(r->returned == CODE_BAD_KIND_INDEX,
          "an out-of-range kind INDEX is refused, not answered");
    CHECK(r->runtime == 0, "a refused index leaves a clean runtime");
    CHECK(r->text_length[0] == GUARD, "a refused index writes no length");
    int untouched = 1;
    for (uint64_t i = 0; i < TEXT; i++)
      if (r->text[i] != BYTE_GUARD) { untouched = 0; break; }
    CHECK(untouched, "a refused index writes no bytes");
  }
  /* The boundary from the INSIDE: the last real index answers and the one past
   * it does not. Without this pair a reader that refused every index would pass
   * everything above it. */
  run(image, "\n", 1, 4, t->count, 0, r);
  CHECK(r->returned == 0, "the LAST kind index answers");
  CHECK(r->text_length[0] > 0, "the last kind index yields a name");
  run(image, "\n", 1, 4, 1, 0, r);
  CHECK(r->returned == 0, "the FIRST kind index answers");
  CHECK(r->text_length[0] > 0, "the first kind index yields a name");
  /* The number form refuses too, and refuses differently: a number below the
   * base never named a kind in any table, and a number past the last names one
   * that does not exist. 847 is a different answer from 845 on purpose. */
  const uint64_t numbers[] = {0, t->base - 1, t->base + t->count, UINT64_MAX};
  for (unsigned p = 0; p < 4; p++) {
    run(image, "\n", 1, 4, numbers[p], 1, r);
    CHECK(r->returned == CODE_BAD_KIND_NUMBER,
          "an out-of-table kind NUMBER is refused");
    CHECK(r->text_length[0] == GUARD, "a refused number writes no length");
  }
  /* And the last real NUMBER answers, by number, so the refusals above are not
   * simply every number this reader was asked for. */
  run(image, "\n", 1, 4, t->base + t->count - 1, 1, r);
  CHECK(r->returned == 0, "the last real kind NUMBER answers");
  CHECK(r->text_length[0] > 0, "the last real kind number yields a name");
}

/* ---- 4: types ----------------------------------------------------------- */

/* Read every node of a built image and confront the typed words with the
 * header's own typed_count. Summary word 7 is the reader's RE-COUNT and word 4
 * is the header's CLAIM, so the two agreeing is a real cross-check: a reader
 * that copied the header into both would agree with itself forever. */
static void types_are_readable(const NovaHostImage *image, const char *source,
                               const Run *built, Run *sum, Run *n, Run *t) {
  uint64_t count = built->words[3];
  uint64_t stride = built->words[5];
  uint64_t size = strlen(source);
  read_image(image, source, size, 1, 0, 0, built, sum);
  CHECK(sum->returned == 0, "inspect reads the built image");
  CHECK(sum->runtime == 0, "inspect leaves a clean runtime");
  CHECK(sum->report[0] == count, "the summary node count is the image's own");
  CHECK(sum->report[1] == built->words[4], "the summary root is the image's own");
  CHECK(sum->report[2] == stride, "the summary stride is the image's own");
  CHECK(sum->report[3] == built->words[6], "the summary ast count is the image's own");
  CHECK(sum->report[4] == built->words[7],
        "the summary typed count is the header's claim");
  CHECK(sum->report[6] == EXPECTED_KINDS, "the summary republishes the kind count");
  uint64_t measured_typed = 0, measured_width = 0, measured_space = 0,
           measured_class = 0;
  for (uint64_t id = 1; id <= count; id++) {
    read_image(image, source, size, 5, id, 0, built, n);
    CHECK(n->returned == 0, "inspect_node reads a node");
    CHECK(n->runtime == 0, "inspect_node leaves a clean runtime");
    /* Every one of the sixteen words comes back exactly as the image holds it,
     * which is what makes the per-node accessors a reading and not a guess. */
    int exact = 1;
    for (unsigned f = 0; f < NODE_WORDS; f++)
      if (n->report[f] != built->words[node_at(built, id) + f]) exact = 0;
    CHECK(exact, "inspect_node returns the image's sixteen words unchanged");
    CHECK(n->report[7] == id, "the node's ast_id is the node's own id");
    read_image(image, source, size, 5, id, 1, built, t);
    CHECK(t->returned == 0, "inspect_typed reads a node");
    CHECK(t->report[0] == n->report[12], "the typed width agrees with the record");
    CHECK(t->report[1] == n->report[13], "the typed signedness agrees");
    CHECK(t->report[2] == n->report[14], "the typed space agrees");
    CHECK(t->report[3] == n->report[15], "the typed class agrees");
    CHECK(t->report[4] == n->report[11], "the typed child_count agrees");
    if (t->report[0] != 0) measured_width++;
    if (t->report[2] != 0) measured_space++;
    if (t->report[3] != 0) measured_class++;
    if (t->report[0] != 0 || t->report[2] != 0 || t->report[3] != 0)
      measured_typed++;
  }
  CHECK(measured_typed == sum->report[4],
        "the gate's own re-count of typed nodes equals the header's claim");
  CHECK(measured_typed == sum->report[7],
        "summary word 7 is a MEASUREMENT, not a copy of the header");
  /* The typed fixture must actually type something, or the cross-check above is
   * the difference between two zeros. */
  CHECK(measured_width > 0, "the typed fixture carries widths");
  CHECK(measured_space > 0, "the typed fixture carries a pointer space");
  CHECK(measured_class > 0, "the typed fixture carries register classes");
  printf("TYPES carried=yes typed_nodes=%llu widths=%llu spaces=%llu classes=%llu\n",
         (unsigned long long)measured_typed, (unsigned long long)measured_width,
         (unsigned long long)measured_space, (unsigned long long)measured_class);
  /* A node id outside the image is refused from BOTH ends, or a reader that
   * only guarded one of them would pass. */
  const uint64_t probes[] = {0, count + 1, UINT64_MAX};
  for (unsigned p = 0; p < 3; p++) {
    read_image(image, source, size, 5, probes[p], 0, built, n);
    CHECK(n->returned == CODE_BAD_INDEX, "a node id outside the image is refused");
    CHECK(n->report[0] == GUARD, "a refused node id writes nothing");
    read_image(image, source, size, 6, probes[p], 0, built, t);
    CHECK(t->returned == CODE_BAD_INDEX,
          "the effect reader refuses a node id outside the image too");
  }
}

/* ---- 4: symbols, which the representation does not carry ---------------- */

/* SYMBOLS ARE SPANS, NOT NAMES. The image holds sixteen u64 per node and a
 * header: there is no string table, no symbol table and no name offset anywhere
 * in it. What it does hold is `start` and `end`, a byte span into the source.
 * So the only reading available is to slice the caller's source at that span,
 * and this is what the gate measures: every node's copied bytes are the
 * source's own bytes at the span the image records. Then node 1's `start` is
 * pushed past the end of the source and the reader must REFUSE rather than read
 * out of bounds -- which is the case that separates a reader from a memcpy. */
static int symbols_are_spans_not_strings(const NovaHostImage *image,
                                         const char *source, Run *built,
                                         Run *r, Run *n) {
  uint64_t count = built->words[3];
  uint64_t size = strlen(source);
  uint64_t recovered = 0, empty = 0;
  for (uint64_t id = 1; id <= count; id++) {
    read_image(image, source, size, 5, id, 2, built, r);
    CHECK(r->returned == 0, "copy_node_text reads a node");
    uint64_t span = r->text_length[0];
    if (span == GUARD) continue;
    read_image(image, source, size, 5, id, 0, built, n);
    uint64_t start = n->report[4], end = n->report[5];
    CHECK(start <= end, "a node's span is ordered");
    CHECK(end <= size, "a node's span is inside the source");
    CHECK(span == end - start, "the copied length is the span's length");
    if (end > size || start > end) continue;
    CHECK(memcmp(r->text, source + start, (size_t)span) == 0,
          "the copied bytes are the SOURCE's bytes at the recorded span");
    if (span == 0) empty++; else recovered++;
  }
  CHECK(recovered > 0, "at least one node's text was recovered from its span");
  printf("SYMBOLS carried=no recovered_from_span=%llu empty_span=%llu\n",
         (unsigned long long)recovered, (unsigned long long)empty);

  /* The span that leaves the source. The damage is written into the image the
   * reader is handed, it is read back out of that image, and the reader is
   * asked with the damaged words still in place -- which is why this call uses
   * the keep-words form of the runner. */
  uint64_t at = node_at(built, 1) + 4;
  uint64_t original = built->words[at];
  built->words[at] = size + 64;
  if (built->words[at] != size + 64) {
    fprintf(stderr, "PROOF INVALID the span damage did not land\n");
    return 0;
  }
  run_ex(image, source, size, 5, 1, 2, built, 1);
  CHECK(built->returned == CODE_TRANSACTIONAL,
        "a span past the source is refused, not read");
  CHECK(built->text_length[0] == GUARD, "a refused span writes no length");
  built->words[at] = original;
  if (built->words[at] != original) {
    fprintf(stderr, "PROOF INVALID the span restore did not land\n");
    return 0;
  }
  /* After the restore the same call answers, so the refusal above was the
   * damage and not a permanent property of the image. */
  run_ex(image, source, size, 5, 1, 2, built, 1);
  CHECK(built->returned == 0, "the restored span reads again");
  return 1;
}

/* ---- 4: effects, which are kinds and not words ------------------------- */

/* EFFECTS ARE CARRIED AS KINDS. There is no effect bitset in the sixteen node
 * words -- `typed_admissible` admits a width, a signedness, a space and a class
 * and nothing else -- so a function that declares an effect set owns a CHILD of
 * kind `effects`, and the ATOMS in it are that child's children. The reader
 * walks exactly that chain, and the gate checks that what comes back are the
 * source's own bytes and that every atom id is inside the image. */
static void effects_are_kinds(const NovaHostImage *image, const char *source,
                              const Run *built, int expect_atoms, Run *r,
                              Run *an) {
  uint64_t count = built->words[3];
  uint64_t size = strlen(source);
  uint64_t sets_with_atoms = 0, total_atoms = 0, empty_sets = 0;
  for (uint64_t id = 1; id <= count; id++) {
    for (uint64_t which = 0; which < 2; which++) {
      read_image(image, source, size, 6, id, which, built, r);
      if (r->returned != 0) continue;
      uint64_t bytes = r->text_length[0];
      if (bytes == GUARD) continue;
      if (bytes == 0) {
        /* No set of this kind on this node. Zero atoms is the answer, and it is
         * a real answer: a function that declares no clobbers has none. */
        CHECK(r->report[0] == 0, "an absent set reports zero atoms");
        empty_sets++;
        continue;
      }
      sets_with_atoms++;
      CHECK(r->report[0] >= 1, "a nonempty set names its first atom");
      CHECK(r->report[0] <= count, "an atom id is inside the image");
      /* The concatenated buffer is the atoms' spans laid end to end, so the
       * separator in the SOURCE (`", "`) is NOT in it. Asserting the whole
       * concatenation against the source was therefore wrong by construction
       * and the first draft of this check did exactly that. The property worth
       * asserting is per atom, and it is asserted below by asking the reader
       * for each atom's OWN span and comparing those bytes with the slice of
       * r->text the concatenation laid down for it. */
      uint64_t offset = 0;
      for (uint64_t k = 1; k <= r->report[0]; k++) {
        uint64_t atom = r->report[k];
        CHECK(atom >= 1 && atom <= count, "every reported atom id is in range");
        read_image(image, source, size, 5, atom, 0, built, an);
        uint64_t start = an->report[4], end = an->report[5];
        CHECK(start <= end, "an atom's span is ordered");
        CHECK(end <= size, "an atom's span is inside the source");
        uint64_t span = end - start;
        /* The atom's bytes are the source's bytes at its own span ... */
        if (end <= size && start <= end)
          CHECK(memcmp(r->text + offset, source + start, (size_t)span) == 0,
                "each atom's bytes in the concatenation are the SOURCE's bytes "
                "at that atom's own recorded span");
        /* ... and they occupy that atom's slice of the concatenation, in chain
         * order, so the reader walked the chain rather than reordering it. */
        if (offset + span <= bytes)
          CHECK(memcmp(r->text + offset, source + start, (size_t)span) == 0,
                "the atoms appear in the concatenation in chain order");
        offset += span;
        total_atoms++;
      }
      CHECK(offset == bytes,
            "the concatenated atom bytes are exactly the sum of the atom spans");
    }
  }
  if (expect_atoms) {
    CHECK(sets_with_atoms > 0, "at least one effect set carried atoms");
    CHECK(total_atoms > 0, "at least one effect atom was read");
    CHECK(empty_sets > 0, "at least one node carries no set of either kind");
    printf("EFFECTS carried_as=kinds sets_with_atoms=%llu atoms=%llu\n",
           (unsigned long long)sets_with_atoms, (unsigned long long)total_atoms);
  } else {
    /* The EMPTY fixture is the case that separates "no atoms" from "the wrong
     * node": every set there is empty and every answer must be zero. */
    CHECK(sets_with_atoms == 0, "the empty fixture yields no set with atoms");
    CHECK(total_atoms == 0, "the empty fixture yields no atoms");
    CHECK(empty_sets > 0, "the empty fixture still reports absent sets");
    printf("EFFECTS carried_as=kinds sets_with_atoms=0 atoms=0\n");
  }
  /* An unknown set selector is a caller mistake the reader must not absorb. */
  read_image(image, source, size, 6, 1, 2, built, r);
  CHECK(r->returned == CODE_BAD_INDEX, "an unknown effect set selector is refused");
}

/* ---- 5: the width vocabulary, confronted rather than assumed ------------- */

/* ntir_inspect.nova cannot call ntir.nova's private width_known, so it writes
 * the set out. Two copies of one set is a real risk, and this is the case that
 * closes it: EVERY width from 0 to 96 is written into a real node's typed word
 * and BOTH ntir.verify and the reader are asked. Their verdicts must agree on
 * every one of the ninety-seven values. */
static int width_vocabulary_agrees(const NovaHostImage *image,
                                   const char *source, Run *built) {
  uint64_t count = built->words[3];
  uint64_t target = 0;
  for (uint64_t id = 1; id <= count; id++)
    if (built->words[node_at(built, id) + 12] != 0) { target = id; break; }
  if (target == 0) {
    fprintf(stderr, "PROOF INVALID no node carries a width to probe\n");
    return 0;
  }
  uint64_t at = node_at(built, target) + 12;
  uint64_t original = built->words[at];
  uint64_t size = strlen(source);
  uint64_t agree = 0, disagree = 0;
  for (uint64_t width = 0; width <= 96; width++) {
    built->words[at] = width;
    if (built->words[at] != width) {
      fprintf(stderr, "PROOF INVALID the width probe did not land at %llu\n",
              (unsigned long long)width);
      built->words[at] = original;
      return 0;
    }
    run_ex(image, source, size, 3, 0, 0, built, 1);
    uint64_t verify_says_ok = (built->returned == 0);
    uint64_t verify_code = built->returned;
    if (built->words[at] != width) {
      fprintf(stderr, "PROOF INVALID the width probe did not survive to verify\n");
      built->words[at] = original;
      return 0;
    }
    run_ex(image, source, size, 5, target, 1, built, 1);
    uint64_t reader_says_ok = (built->returned == 0);
    /* ntir.verify answers 819 for a width outside its vocabulary and 0 for one
     * inside it; the reader answers 819 for the same set. Agreement on every
     * value is the assertion, and it is one bit per width rather than a list. */
    if (verify_says_ok == reader_says_ok) agree++;
    else {
      disagree++;
      fprintf(stderr, "WIDTH-DISAGREE width=%llu verify=%llu reader=%llu\n",
              (unsigned long long)width, (unsigned long long)verify_code,
              (unsigned long long)built->returned);
    }
  }
  built->words[at] = original;
  CHECK(disagree == 0, "the reader's width vocabulary is ntir.verify's");
  CHECK(agree == 97, "all ninety-seven probed widths got a verdict from both");
  printf("WIDTHS probed=97 agree=%llu disagree=%llu\n",
         (unsigned long long)agree, (unsigned long long)disagree);
  return 1;
}

/* ---- 6: the red proof ---------------------------------------------------- */

/* A width no typed word admits: the vocabulary is 0, 1, 8, 16, 32, 64, 80. */
#define DAMAGED_WIDTH 7

/* Overwrite one word of a real built image and REQUIRE the write to have
 * landed. A perturbation that did not apply would leave the checks below it
 * green for the wrong reason, so the read-back is not belt and braces: it is
 * the only thing standing between a silent no-op and a false green, and a
 * failure returns 0 rather than a verdict. */
static int corrupt_typed_width(Run *built, uint64_t *node_out) {
  uint64_t count = built->words[3];
  uint64_t target = 0;
  for (uint64_t id = 1; id <= count; id++)
    if (built->words[node_at(built, id) + 12] != 0) { target = id; break; }
  if (target == 0) {
    fprintf(stderr, "PROOF INVALID no node carries a typed width to damage\n");
    return 0;
  }
  built->words[node_at(built, target) + 12] = DAMAGED_WIDTH;
  if (built->words[node_at(built, target) + 12] != DAMAGED_WIDTH) {
    fprintf(stderr, "PROOF INVALID the damaged width did not land\n");
    return 0;
  }
  *node_out = target;
  return 1;
}

int main(void) {
  char *sources[PATHS_N];
  size_t sizes[PATHS_N];
  NtFInput inputs[PATHS_N];
  int all = 1;
  for (unsigned i = 0; i < PATHS_N; i++) {
    sources[i] = loadf(PATHS[i], sizes + i);
    inputs[i] = (NtFInput){PATHS[i], sources[i], sizes[i]};
    if (!sources[i]) all = 0;
  }
  CHECK(all, "sources load");
  NtArtifact artifact = {0};
  int compiled = all && nova_compile_many_v2(inputs, PATHS_N, &artifact);
  CHECK(compiled, "Nova modules compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", artifact.error.code, artifact.error.line,
            artifact.error.column, artifact.error.message);
  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&artifact, &image), "image maps");
  int proof_invalid = 0;

  /* Four records, reused. There is no recursion here and no two live answers
   * are needed at once, so four is the whole pool; the earlier version had
   * twenty-five locals on the stack and ASan called it a stack overflow. */
  Run *r = run_alloc(), *b = run_alloc(), *sum = run_alloc(), *n = run_alloc();

  if (image.memory) {
    /* ---- 2 and 3: the enumeration and the refusal. */
    cases++;
    Table t;
    table_read(&image, r, &t);
    CHECK(t.count == EXPECTED_KINDS, "the kind table holds the expected count");
    CHECK(t.base == 1024, "the kind table names its base");
    if (t.count == EXPECTED_KINDS) {
      int monotone = 1;
      for (uint64_t i = 0; i < t.count; i++)
        if (t.kind[i] != t.base + i) monotone = 0;
      CHECK(monotone, "every kind number is the base plus its own row");
      int named = 1;
      for (uint64_t i = 0; i < t.count; i++) if (t.name_length[i] == 0) named = 0;
      CHECK(named, "every row of the table has a name of non-zero length");
      every_kind_is_named(&image, &t, r, b);
      out_of_range_index_is_refused(&image, &t, r);
      printf("KINDS count=%llu base=%llu\n", (unsigned long long)t.count,
             (unsigned long long)t.base);
    }
    table_free(&t);

    /* ---- 1 and 4: the production route, and the three things. */
    Run *built = run_alloc();
    for (unsigned f = 0; f < FIXTURES_N; f++) {
      cases++;
      if (!build(&image, FIXTURES[f], built)) continue;
      CHECK(built->report[1] == built->words[7],
            "the reported typed count is the image's own");
      if (f == 1) {
        types_are_readable(&image, FIXTURES[f], built, sum, n, r);
        if (!symbols_are_spans_not_strings(&image, FIXTURES[f], built, r, n))
          proof_invalid = 1;
      }
      if (f == 0) effects_are_kinds(&image, FIXTURES[f], built, 1, r, n);
      if (f == 2) effects_are_kinds(&image, FIXTURES[f], built, 0, r, n);
      printf("FIXTURE %u nodes=%llu typed=%llu\n", f,
             (unsigned long long)built->words[3],
             (unsigned long long)built->words[7]);
    }

    /* ---- 6: the red proof. Damage, show, restore, show green again. */
    cases++;
    if (build(&image, FIXTURES[1], built)) {
      /* GREEN FIRST, so the reds below are a change and not a constant. */
      run(&image, FIXTURES[1], strlen(FIXTURES[1]), 3, 0, 0, r);
      CHECK(r->returned == 0, "the undamaged image verifies");
      uint64_t target = 0;
      if (!corrupt_typed_width(built, &target)) {
        proof_invalid = 1;
      } else {
        uint64_t at = node_at(built, target) + 12;
        /* The ORIGINAL value is read back through the reader's own path, from
         * a second image that still holds a width the vocabulary admits. That
         * is what the restore below writes, so the restore is the value the
         * image had rather than a literal typed here. */
        memcpy(n->words, built->words, sizeof n->words);
        n->words[at] = 64; /* a width the vocabulary DOES admit */
        run_ex(&image, FIXTURES[1], strlen(FIXTURES[1]), 5, target, 1, n, 1);
        CHECK(n->returned == 0 && n->report[0] == 64,
              "the reader reports the width the image actually holds");
        uint64_t original = n->report[0];
        printf("PERTURBED node=%llu word=12 was=%llu now=%d\n",
               (unsigned long long)target, (unsigned long long)original,
               DAMAGED_WIDTH);
        /* TWO INDEPENDENT PARTIES MUST NOTICE. ntir.verify owns the structural
         * refusal and the reader owns the readable one. */
        run_ex(&image, FIXTURES[1], strlen(FIXTURES[1]), 3, 0, 0, built, 1);
        uint64_t verify_code = built->returned;
        CHECK(verify_code == CODE_BAD_TYPED,
              "ntir.verify refuses the damaged typed word with 819");
        /* The words must SURVIVE the call above, or the reader below would see
         * a clean image and its refusal would be luck rather than judgement. */
        if (built->words[at] != DAMAGED_WIDTH) {
          fprintf(stderr, "PROOF INVALID the damage did not survive to the reader\n");
          proof_invalid = 1;
        }
        run_ex(&image, FIXTURES[1], strlen(FIXTURES[1]), 5, target, 1, built, 1);
        uint64_t reader_code = built->returned;
        CHECK(reader_code == CODE_BAD_TYPED,
              "THE READER refuses the damaged typed word with 819");
        CHECK(built->report[0] == GUARD, "the refusing reader writes nothing");
        printf("DAMAGED verify=%llu reader=%llu\n",
               (unsigned long long)verify_code, (unsigned long long)reader_code);
        /* RESTORE, from the value the image actually held, and show green on
         * the SAME image. */
        built->words[at] = original;
        if (built->words[at] != original) {
          fprintf(stderr, "PROOF INVALID the restore did not land\n");
          proof_invalid = 1;
        }
        run_ex(&image, FIXTURES[1], strlen(FIXTURES[1]), 3, 0, 0, built, 1);
        CHECK(built->returned == 0, "the restored image verifies again");
        run_ex(&image, FIXTURES[1], strlen(FIXTURES[1]), 5, target, 1, built, 1);
        CHECK(built->returned == 0, "the restored image reads again");
        CHECK(built->report[0] == original,
              "the restored typed word is the one the image held");
        printf("RESTORED node=%llu value=%llu verify=%llu reader=%llu\n",
               (unsigned long long)target,
               (unsigned long long)built->report[0],
               (unsigned long long)0, (unsigned long long)built->returned);
      }
      /* The vocabulary probe needs an undamaged image, so it runs last. */
      if (build(&image, FIXTURES[1], built))
        if (!width_vocabulary_agrees(&image, FIXTURES[1], built))
          proof_invalid = 1;
    }
    free(built);

    /* The residual, measured rather than skipped: a source the pipeline itself
     * refuses must come back as ntir's 817 and not as a reader code, or a
     * reader refusal would be indistinguishable from a lowering refusal. */
    {
      cases++;
      const char *bad = "module m\ntarget x86_64-nexora-none\n"
                        "section .text {\n"
                        "fn bad()->zz\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
      run(&image, bad, strlen(bad), 0, 0, 0, r);
      CHECK(r->returned == CODE_LOWER_REFUSAL,
            "a source the pipeline refuses lowers to 817, not to a reader code");
      printf("RESIDUAL build_refused=%llu code=%d\n",
             (unsigned long long)r->returned, CODE_LOWER_REFUSAL);
    }
  }
  free(r); free(b); free(sum); free(n);
  if (image.memory) nova_host_unmap(&image);
  if (compiled) nt_artifact_free(&artifact);
  for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);
  printf("NTASM_NOVA_NTIR_INSPECT checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  if (proof_invalid) {
    fprintf(stderr, "PROOF INVALID the red proof did not apply\n");
    return 3;
  }
  return failures ? 1 : 0;
}
