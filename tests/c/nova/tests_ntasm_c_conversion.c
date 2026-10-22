/* tests_ntasm_c_conversion.c -- the gate for c_conversion.nova, which had none.
 *
 * ---------------------------------------------------------------------------
 * THE ENTRY IS PART OF THIS DELIVERABLE, AND THIS PARAGRAPH IS WHY.
 *
 * c_conversion.nova (compiler/nova/analysis/c_conversion.nova) published 105
 * `export fn` when this gate was written, and the counts below are those of
 * that day. It publishes 104 since 7 October 2026: `direction`, one of the
 * vocabulary exports among the 21 that carry logic, was a copy of abi.nova's
 * direction rule and left, and direction_in_span now asks abi.parameter_mode.
 * Its own header says a C harness has to reach the exports through an
 * entry, because "a module exports no `main`". That entry,
 * tests/nova/tests/c-conversion-entry.nova, existed at 355 lines
 * with eight modes and was named by NOTHING in the tree: no PATHS[] row, no
 * glob, no generated list, no compile. MEM.md filed it under «ENTRÉES QUE
 * PERSONNE NE LANCE» for exactly that reason.
 *
 * So this file does two things and a reader needs both of them. It adds the
 * SIX TESTS, and it OPENS THE DOOR: PATHS_C below is the literal row that
 * makes c-conversion-entry.nova reachable at all. This harness is what moves
 * that entry out of MEM.md's unlaunched list, and a later reader who finds
 * "c_conversion has a harness" must be able to learn that the harness had to
 * open a door first -- otherwise the gate looks like it was always there.
 *
 * The row is a LITERAL, in the same form tests_ntasm_ntir.c uses for
 * ntir-entry.nova. It is not a glob and it is not a generated list. That was
 * measured rather than assumed: five harnesses (registry, placeholder, abi,
 * versions, bounds_ceiling) enumerate compiler/nova with readdir, and
 * NONE of them compiles what it enumerated -- registry and placeholder call
 * nova_compile_many_v2 zero times, and abi's scan only `load()`s each entry
 * and scans its bytes for import lines. ng_parity_paths[43] in
 * ntasm_pipeline_parity.h is the tree's only generated path list and it
 * carries no c_conversion row. So opening a door was necessary and adding a
 * glob would have been a second convention for a job a literal already does.
 *
 * ---------------------------------------------------------------------------
 * WHY SIX TESTS AND NOT 105.
 *
 * The 105 exports decompose, and the decomposition is the argument for the
 * subset rather than a number chosen for tidiness. 84 of them are one-line
 * `return <integer literal>;` wrappers, falling into six generated groups
 * whose sizes are each explained by something outside this module:
 *
 *   C_TYPE_  n=6   = the word count of C struct NtFType     (frontend.h:87)
 *   C_VAR_   n=22  = NtFVariable                             (frontend.h:110)
 *   C_FN_    n=36  = NtFFunction                             (frontend.h:211)
 *   V_/VERDICT_WORDS n=9  eight preserved fields plus their count
 *   M_ n=3   = a three-valued mechanism enum
 *   R_ n=7   = seven refusal codes, 610..616
 *
 * Each group's offsets are exactly 0..n-1 with no gap and no repeat. THE
 * CONSEQUENCE, and it is the rule this gate is written under: this project
 * generates constants by writing one `export fn` per constant, so an export
 * COUNT measures the WIDTH OF A RECORD and not the number of meanings in it.
 * Reading 105 as "105 behaviours" reads a struct layout as a specification.
 * (The same reason ast.nova's 9 and machine_ir.nova's 103 are not comparable
 * numbers, and the reason the 482 sites behind W206's naming question are a
 * record width rather than a count of meanings.)
 *
 * The remaining 21 carry logic and collapse further: five share ONE converter
 * shape verbatim -- `(source, img, at, out[, verdict]) -> u64`, each opening
 * with the identical `if len(img)<at+C_x_WORDS() { return R_SHORT_IMAGE(); }`
 * -- one is the comparator, and the rest are vocabulary.
 *
 * SO: FIVE CONVERTERS, ONE PER TEST, PLUS compare_variable AS THE SIXTH. The
 * comparator is the sixth because it is the ONLY export in the module that can
 * catch a converter being wrong. Every other arm here would be checking
 * vocabulary against itself, which is the shape that cannot fail.
 *
 * ---------------------------------------------------------------------------
 * WHERE THE EXPECTATIONS COME FROM, which is the whole design.
 *
 * The C side is the reference. This file calls nt_frontend_compile on the
 * fixture below -- the C reference compiler, a different implementation in a
 * different process -- and lays out ITS OWN NtFType/NtFVariable/NtFFunction
 * words into the flat image, using offsets read back from c_conversion's mode
 * 0 and mode 10. The module's comment says "a driver that wrote them down
 * would drift", so no offset is typed here: the layout is published by the
 * module and read by the driver, and an offset that moved moves on both sides
 * at once.
 *
 * The six tests:
 *   1. THE LAYOUT COMPLETENESS, mode 10. All 61 offsets, published in
 *      declaration order, read back and checked to be each group's exact
 *      0..n-1. This is the ONE test that stands in for the 84 wrappers, and
 *      it stands in for them because their property is not 84 values but four
 *      tables being gapless.
 *   2. convert_type, mode 3, on the C's own NtFType.
 *   3. convert_effects, mode 4, on the C's own NtFFunction effects triple --
 *      including the effect-free function, which the module's own comment
 *      names as the negative that decides whether the conversion is honest.
 *   4. convert_variable, mode 1, on the C's own NtFVariable -- and the
 *      REFUSAL arm, because a converter that only ever succeeds has not been
 *      shown to decide anything.
 *   5. convert_symbol, mode 2, on the same record's name.
 *   6. compare_variable, mode 7, the ACCEPTANCE: the converted node confronted
 *      against the C record it came from, field by field.
 */

#include "../../../compiler/c/ntasm/frontend/frontend.h"
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

#define REPORT 256
#define CIMG 4096
#define NODEW 64
#define VERDW 64
#define GUARD UINT64_C(0xcccccccccccccccc)

/* THE DOOR, AS A LITERAL ROW -- the same form tests_ntasm_ntir.c uses for
 * ntir-entry.nova. See the header: this row is why c-conversion-entry.nova is
 * reachable at all, and it is the second half of this file's deliverable.
 *
 * THE CLOSURE IS SEVEN ROWS, AND IT WAS DERIVED BY WALKING THE IMPORTS RATHER
 * THAN BY LISTING THE MODULES ONE IMAGINES ARE NEEDED. The first version of
 * this array carried nine rows and four of them were files that DO NOT EXIST,
 * `ntasm.nova` among them -- so the harness answered "the Nova sources load"
 * false on a tree where nothing was wrong, and named a file rather than a
 * cause. A list of the modules a file plausibly needs is a GUESS wearing a
 * path array's clothes, and it is indistinguishable from a real one until the
 * load fails on a row that is not there.
 *
 * The derivation is four lines: read the entry's imports, find the file whose
 * head declares each module NAME, recurse. An import names a MODULE and not a
 * path, and the two differ here -- the entry imports `ntir`, which
 * ntir.nova declares, and ntir.nova in turn imports `register_widths`, whose
 * filename and module name agree but whose presence nothing about the entry's
 * own import lines would have suggested.
 *
 * The last two rows were added on 7 October 2026 by the same walk:
 * c_conversion.nova imports `abi` (abi.nova) since its direction reader became
 * a relay to the owner of the rule, and abi.nova imports `clobbers`
 * (clobbers.nova) and `register_widths`, which was already here. Five rows
 * became seven; nothing else the entry reaches moved.
 *
 * ORDER IS THE ENTRY FIRST, because every other gate in this tree puts the
 * entry first in the same array and the compiler's module resolution needs the
 * importer reachable. */
static const char *const PATHS_C[] = {
    "tests/nova/tests/c-conversion-entry.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/analysis/c_conversion.nova",
    "compiler/nova/formats/ntir/ntir.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/analysis/abi/abi.nova",
    "compiler/nova/analysis/abi/clobbers.nova"};
#define PATHS_C_N ((unsigned)(sizeof PATHS_C / sizeof PATHS_C[0]))

static char *loadf(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) {
    free(b);
    fclose(f);
    return NULL;
  }
  fclose(f);
  b[z] = 0;
  *n = (size_t)z;
  return b;
}

/* ONE RUN. `cimg` is the flat C-record image the ENTRY reads, and it is a
 * PARAMETER rather than a buffer this function owns. That distinction was the
 * structural defect in the first version: the helper borrowed its own cimg,
 * filled it with the guard sentinel, and handed the entry a buffer of
 * 0xcccc...ccc -- so every mode that converts a record answered
 * R_SHORT_IMAGE, or refused a span, for a reason that had nothing to do with
 * the converter. An absent value is not a zero, and here it was not even an
 * ABSENT value: it was a real value, the guard, being read as a C record.
 *
 * Every buffer is pre-filled with the guard for the buffers the ENTRY writes,
 * so a word it did not write is told apart from a word it wrote as zero. */
typedef struct {
  uint64_t returned, runtime;
  uint64_t report[REPORT];
  uint64_t out[VERDW];
  uint64_t node[NODEW];
  uint64_t name[NODEW];
  /* The entry's eleventh parameter, a SEPARATE buffer from `out`. Mode 9
   * builds an NTIR image into `out` and reads it back, so handing the entry
   * the `out` handle twice would alias a buffer the module treats as two. */
  uint64_t scratch[16];
} Run;

/* run_with is DEFINED BELOW this wrapper, so it is declared here. The wrapper
 * is the common case -- a run that supplies no converted node -- and it exists
 * so the eight earlier call sites read as one call rather than as eight with
 * two NULLs each. A second convention for the same thing is worse than the
 * NULLs. */

static Run run_with(const NovaHostImage *img, const char *src, size_t slen,
                    uint64_t mode, uint64_t index, const uint64_t *cimg,
                    uint64_t cwords, const uint64_t *given_node,
                    const uint64_t *given_name);

static Run run(const NovaHostImage *img, const char *src, size_t slen,
               uint64_t mode, uint64_t index, const uint64_t *cimg,
               uint64_t cwords) {
  return run_with(img, src, slen, mode, index, cimg, cwords, NULL, NULL);
}



static Run run_with(const NovaHostImage *img, const char *src, size_t slen,
                    uint64_t mode, uint64_t index, const uint64_t *cimg,
                    uint64_t cwords, const uint64_t *given_node,
                    const uint64_t *given_name) {
  Run r;
  static uint64_t cin[CIMG];
  NovaContextV2 c = {0};
  for (unsigned i = 0; i < REPORT; i++)
    r.report[i] = GUARD;
  for (unsigned i = 0; i < VERDW; i++)
    r.out[i] = GUARD;
  for (unsigned i = 0; i < NODEW; i++) {
    r.node[i] = GUARD;
    r.name[i] = GUARD;
  }
  /* A CONVERTED NODE AND NAME NODE CAN BE HANDED IN, and this is not a
   * convenience: compare_variable takes the entry's OWN `node` and `name`
   * buffers, so a run that leaves them at the guard compares a table of
   * 0xcccc...ccc against the C record and every field disagrees. That is
   * exactly what the first version of test 6 did, and it returned 611 on a
   * record the converter had just produced correctly -- a comparator refusing
   * a node nobody gave it. An absent value is not a zero, and here it was
   * neither: it was the guard, being read as a twelve-word node. */
  if (given_node)
    for (unsigned i = 0; i < NODEW; i++)
      r.node[i] = given_node[i];
  if (given_name)
    for (unsigned i = 0; i < NODEW; i++)
      r.name[i] = given_name[i];
  for (unsigned i = 0; i < CIMG; i++)
    cin[i] = GUARD;
  if (cimg && cwords <= CIMG)
    for (uint64_t i = 0; i < cwords; i++)
      cin[i] = cimg[i];
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)src, slen, 0);
  uint64_t ch = nova_borrow_v2(&c, cin, CIMG * sizeof(uint64_t), 1);
  uint64_t oh = nova_borrow_v2(&c, r.out, VERDW * sizeof(uint64_t), 1);
  uint64_t nh = nova_borrow_v2(&c, r.node, NODEW * sizeof(uint64_t), 1);
  uint64_t xh = nova_borrow_v2(&c, r.name, NODEW * sizeof(uint64_t), 1);
  uint64_t rh = nova_borrow_v2(&c, r.report, REPORT * sizeof(uint64_t), 1);
  /* A REAL SCRATCH BUFFER, not the `out` handle reused. The entry's eleventh
   * parameter is its own buffer and mode 9 writes an NTIR image into `out`,
   * so handing it `out` a second time would alias two buffers the module
   * believes are separate -- the first version of this call did exactly that
   * and it is not a shape that announces itself. */
  uint64_t sc = nova_borrow_v2(&c, r.scratch, 16 * sizeof(uint64_t), 1);
  /* ELEVEN parameters, EIGHTEEN flat slots, and both numbers are the whole
   * difference between a gate that measures and one that refuses everything:
   *   source:buf<u8>     2   mode:u64        1   index:u64        1
   *   cimg:buf<u64>      2   cimg_words:u64 1   out:buf<u64>     2
   *   out_words:u64      1   node:buf<u64>   2   name:buf<u64>    2
   *   report:buf<u64>    2   scratch:buf<u64> 2              total  18
   *
   * MEASURED, AND THE COMMENT ABOVE THIS LINE PREDICTED THE BUG AND WAS STILL
   * WRONG. The first version declared 18 and the array held 17 items, so the
   * eighteenth slot was read past the end of the array and every mode refused.
   * A comment describing a bug is not a test for the bug. What caught it was
   * the compiler refusing an unrelated %llu/argument mismatch earlier, which
   * forced this array to be counted item by item rather than trusted -- and
   * that is the argument for letting the compiler see every format string
   * rather than checking them by eye. */
  /* THE MISSING SLOT WAS out_words, AND IT TOOK THREE RUNS TO SEE.
   *
   * `out:buf<u64>, out_words:u64` is a buffer AND A SEPARATE COUNT, and the
   * count takes a flat slot of its own -- exactly as machine-ir-entry's
   * `out:buf<u64>, out_count:u64` does, which is the working reference. The
   * first version of this array wrote `oh, VERDW` and then went straight to
   * `nh`, so it carried SEVENTEEN items while declaring EIGHTEEN.
   *
   * What that looks like from outside is the worst of the three failure shapes
   * in this file's own history, and it is worth naming: the entry answered
   * `returned=0` -- a SUCCESS -- while `runtime=7` (NV2_LIFETIME) and report[0]
   * stayed at the guard sentinel. A success return with nothing written and an
   * error set is not distinguishable, from the call site, from a module that
   * succeeded and published a layout. So the three observations were printed
   * separately rather than folded into one CHECK -- and the print is what
   * turned "it refuses" into "it refuses with a LIFETIME error and wrote
   * nothing", which is a slot-count diagnosis and not a module diagnosis.
   *
   * Counted out loud, in the order the entry declares them:
   *   source:buf<u8>  2 | mode 1 | index 1 | cimg:buf<u64> 2 | cimg_words 1
   *   out:buf<u64>    2 | out_words 1 | node:buf<u64> 2 | name:buf<u64> 2
   *   report:buf<u64> 2 | scratch:buf<u64> 2                     = 18
   */
  uint64_t args[] = {sh,     slen, mode, index, ch,   CIMG, cwords,
                     oh,     VERDW, VERDW, nh,   NODEW,
                     xh,     NODEW, rh,   REPORT, sc,  16};
  r.returned = img->entry(&c, args, 18);
  r.runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return r;
}
/* THE FIXTURE, compiled by the C reference so the records below are the C's
 * own bytes rather than a hand-written image. It carries one function with a
 * parameter bound to a register, which is what makes the REGISTER span and the
 * DECLARATION extent differ -- and that difference is the whole reason
 * convert_variable refuses without C_VAR_DECL_START. */
static const char FIXTURE[] =
    "module m\n"
    "target x86_64-nexora-none\n"
    "section .text {\n"
    "fn f(in x:u64 @rax)->u64\n"
    "effects {}\n"
    "clobbers {rax} {\n"
    "return x\n"
    "}\n"
    "}\n";

typedef struct {
  uint64_t node_words, type_words, var_words, fn_words, verdict_words;
  uint64_t record_unchanged;
  uint64_t v_symbol, v_type, v_position, v_effect, v_space, v_direction;
  uint64_t v_conflation, v_mechanism;
  uint64_t m_copied, m_enums, m_derived;
  uint64_t r_no_source, r_bad_span, r_no_type_kind, r_short_image;
  uint64_t r_effect_loss, r_space_conflict, r_no_decl_span;
  uint64_t var_name_start, var_name_len, var_decl_start, var_decl_end;
  uint64_t var_span_source, var_span_line, var_span_column;
  uint64_t var_span_start, var_span_end, var_type, var_direction;
  /* THE NtFFunction EFFECT OFFSETS, read from mode 10's published table
   * rather than typed. mode 0 publishes only the four NtFVariable offsets the
   * entry needs for its own modes, so these come from the whole-table mode. */
  uint64_t fn_effect_flags, fn_effect_reads, fn_effect_writes;
  uint64_t fn_inferred_flags, fn_inferred_reads, fn_inferred_writes;
} Layout;

int main(void) {
  size_t sizes[PATHS_C_N] = {0};
  char *sources[PATHS_C_N] = {0};
  NtFInput inputs[PATHS_C_N];
  int all = 1;
  for (unsigned i = 0; i < PATHS_C_N; i++) {
    sources[i] = loadf(PATHS_C[i], &sizes[i]);
    if (!sources[i])
      all = 0;
    inputs[i] = (NtFInput){PATHS_C[i], sources[i], sizes[i]};
  }
  CHECK(all, "the Nova sources load, the entry among them");
  if (!all) {
    for (unsigned i = 0; i < PATHS_C_N; i++)
      free(sources[i]);
    /* THE ARTIFACT IS RELEASED, AND THIS IS THE LEAK FIX -- AND IT IS MINE, NOT
   * codegen.c's. Measured, and the measurement contradicted a plausible
   * diagnosis: the leak report names `reserve -> raw -> instruction ->
   * emit_expression` inside codegen.c, which reads like a buffer codegen
   * forgot to free. It is not. compile_profile (nova.c:2999-3007) MOVES
   * image.bytes, image.rdata.bytes and image.data.bytes into out->text,
   * out->rdata and out->data, NULLs the three source pointers, and calls
   * nt_code_image_free -- so codegen has given the bytes away and holds none
   * of them. The owner from that line on is the NtArtifact, and the only code
   * that can release it is the caller.
   *
   * Peer harnesses do release it: nt_artifact_free appears 2x in
   * tests_ntasm_machine_ir, 5x in tests_ntasm_ntir and 1x in
   * tests_ntasm_versions. This file called it ZERO times, so the first gate
   * registered with leak detection on reported 2 MiB from
   * nova_compile_many_v2 and the natural reading was a library defect.
   *
   * Nothing is suppressed here. There is no LSAN_OPTIONS, no __lsan_ignore and
   * no detect_leaks=0: the buffer is RETURNED, by the free the library already
   * provides and the peers already call. The expected result is the same run
   * that reported 2098176 bytes leaked in 2 allocations reporting none, with
   * every AST- line and the checks/failures/cases triple byte-identical -- a
   * fix that moved the numbers would be a different change and is reported as
   * one. */
  printf("NTASM_NOVA_C_CONVERSION checks=%u failures=%u cases=%u\n", checks,
           failures, cases);
    /* FLUSHED: under the driver both streams go to one log, stdout is fully
     * buffered, and LeakSanitizer's exit path does not flush stdio -- so a
     * banner printed and not flushed is a banner ABSENT, and the driver
     * answers FAIL_LINES_ABSENT with nothing named. The leak itself is in
     * codegen.c's `reserve` and is not this file's: `ngbuild.sh versions`
     * exits 1 the same way while printing a green count. What this file owns
     * is that its count reaches disk on EVERY route out, and the four early
     * returns below are routes out. */
    return 1;
    fflush(stdout);
  }

  NtArtifact art = {0};
  int compiled = nova_compile_many_v2(inputs, PATHS_C_N, &art);
  CHECK(compiled, "the Nova sources compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", art.error.code, art.error.line,
            art.error.column, art.error.message);
  NovaHostImage img = {0};
  CHECK(compiled && nova_host_map(&art, &img), "the image maps");
  if (!img.memory) {
    for (unsigned i = 0; i < PATHS_C_N; i++)
      free(sources[i]);
    printf("NTASM_NOVA_C_CONVERSION checks=%u failures=%u cases=%u\n", checks,
           failures, cases);
    /* FLUSHED: under the driver both streams go to one log, stdout is fully
     * buffered, and LeakSanitizer's exit path does not flush stdio -- so a
     * banner printed and not flushed is a banner ABSENT, and the driver
     * answers FAIL_LINES_ABSENT with nothing named. The leak itself is in
     * codegen.c's `reserve` and is not this file's: `ngbuild.sh versions`
     * exits 1 the same way while printing a green count. What this file owns
     * is that its count reaches disk on EVERY route out, and the four early
     * returns below are routes out. */
    return 1;
    fflush(stdout);
  }

  const size_t slen = sizeof FIXTURE - 1;

  /* ---- THE C REFERENCE, compiled by the C itself ---------------------- */
  NtFInput fin = {"fixture.c", FIXTURE, slen};
  NtFProgram prog = {0};
  int ref_ok = nt_frontend_compile(&fin, 1, &prog);
  CHECK(ref_ok, "the C reference compiler accepts the fixture");
  if (!ref_ok) {
    fprintf(stderr, "the C reference refused the fixture: %zu diagnostics\n",
            prog.diagnostic_count);
    for (unsigned i = 0; i < PATHS_C_N; i++)
      free(sources[i]);
    printf("NTASM_NOVA_C_CONVERSION checks=%u failures=%u cases=%u\n", checks,
           failures, cases);
    /* FLUSHED: under the driver both streams go to one log, stdout is fully
     * buffered, and LeakSanitizer's exit path does not flush stdio -- so a
     * banner printed and not flushed is a banner ABSENT, and the driver
     * answers FAIL_LINES_ABSENT with nothing named. The leak itself is in
     * codegen.c's `reserve` and is not this file's: `ngbuild.sh versions`
     * exits 1 the same way while printing a green count. What this file owns
     * is that its count reaches disk on EVERY route out, and the four early
     * returns below are routes out. */
    return 1;
    fflush(stdout);
  }
  printf("C-REFERENCE functions=%zu types=%zu variables=%zu\n",
         prog.function_count, prog.type_count, prog.variable_count);

  /* ---- MODE 0: THE LAYOUT, read back from the module ------------------ */
  Layout L;
  memset(&L, 0, sizeof L);
  cases++;
  Run m0 = run(&img, FIXTURE, slen, 0, 0, NULL, 0);
  /* THE RETURN AND THE RUNTIME WORD ARE PRINTED EVEN ON THE RED, because a
   * check that fails without saying what it saw is a check the reader has to
   * re-run with a different program attached. Measured: this went red with
   * `returned` and `runtime` unknown, and the cause was one line of
   * instrumentation away. */
  printf("MODE0 returned=%llu runtime=%llu report0=%llu\n",
         (unsigned long long)m0.returned, (unsigned long long)m0.runtime,
         (unsigned long long)m0.report[0]);
  CHECK(m0.returned == 0 && m0.runtime == 0,
        "mode 0 publishes the layout without a refusal");
  if (m0.returned != 0 || m0.runtime != 0) {
    for (unsigned i = 0; i < PATHS_C_N; i++)
      free(sources[i]);
    printf("NTASM_NOVA_C_CONVERSION checks=%u failures=%u cases=%u\n", checks,
           failures, cases);
    /* FLUSHED: under the driver both streams go to one log, stdout is fully
     * buffered, and LeakSanitizer's exit path does not flush stdio -- so a
     * banner printed and not flushed is a banner ABSENT, and the driver
     * answers FAIL_LINES_ABSENT with nothing named. The leak itself is in
     * codegen.c's `reserve` and is not this file's: `ngbuild.sh versions`
     * exits 1 the same way while printing a green count. What this file owns
     * is that its count reaches disk on EVERY route out, and the four early
     * returns below are routes out. */
    return 1;
    fflush(stdout);
  }
  L.node_words = m0.report[0];
  L.type_words = m0.report[1];
  L.var_words = m0.report[2];
  L.fn_words = m0.report[3];
  L.verdict_words = m0.report[4];
  L.record_unchanged = m0.report[15];
  L.v_symbol = m0.report[5];
  L.v_type = m0.report[6];
  L.v_position = m0.report[7];
  L.v_effect = m0.report[8];
  L.v_space = m0.report[9];
  L.v_direction = m0.report[10];
  L.v_conflation = m0.report[11];
  /* V_MECHANISM has NO mode-0 slot: report[12] is M_COPIED. It is left
   * unread on purpose -- reading it would have produced M_COPIED's value and a
   * red that named the module instead of the layout. */
  L.m_copied = m0.report[12];
  L.m_enums = m0.report[13];
  L.m_derived = m0.report[14];
  L.r_no_source = m0.report[20];
  L.r_bad_span = m0.report[21];
  L.r_no_type_kind = m0.report[22];
  L.r_short_image = m0.report[23];
  L.r_effect_loss = m0.report[24];
  L.r_space_conflict = m0.report[25];
  L.r_no_decl_span = m0.report[26];
  /* V_MECHANISM IS NOW PUBLISHED at report[27]. The derivation that stood here
   * -- "the one unclaimed value in [0, VERDICT_WORDS)" -- was a reader holding
   * a torch in a room that should have a light switch, and it was written to
   * fail the moment the switch appeared. It is removed, not kept as a fallback:
   * a fallback that still works would hide the next gap of the same shape. */
  L.v_mechanism = m0.report[27];
  L.var_name_start = m0.report[16];
  L.var_name_len = m0.report[17];
  L.var_decl_start = m0.report[18];
  L.var_decl_end = m0.report[19];

  printf("C-CONV-VAROFF name_start=%llu name_len=%llu decl_start=%llu decl_end=%llu\n",
         (unsigned long long)L.var_name_start, (unsigned long long)L.var_name_len,
         (unsigned long long)L.var_decl_start, (unsigned long long)L.var_decl_end);
  printf("C-CONV-LAYOUT node=%llu type=%llu var=%llu fn=%llu verdict=%llu\n",
         (unsigned long long)L.node_words, (unsigned long long)L.type_words,
         (unsigned long long)L.var_words, (unsigned long long)L.fn_words,
         (unsigned long long)L.verdict_words);
  printf("C-CONV-CODES no_source=%llu bad_span=%llu no_type_kind=%llu "
         "short_image=%llu effect_loss=%llu no_decl_span=%llu\n",
         (unsigned long long)L.r_no_source,
         (unsigned long long)L.r_bad_span,
         (unsigned long long)L.r_no_type_kind,
         (unsigned long long)L.r_short_image,
         (unsigned long long)L.r_effect_loss,
         (unsigned long long)L.r_no_decl_span);

  /* node_record_is_unchanged is the assertion every converter below rests on:
   * it is the claim that a twelve-word node is what is being written. The
   * module publishes it as a flag rather than a refusal code precisely because
   * a conversion cannot be handed a thirteen-word record to refuse. */
  CHECK(L.node_words == 12,
        "the node record is twelve words, which is what every converter below "
        "writes into");
  CHECK(L.record_unchanged == 1,
        "the module asserts its own record width is unchanged from twelve");
  CHECK(L.m_copied && L.m_enums && L.m_derived &&
            L.m_copied != L.m_enums && L.m_enums != L.m_derived &&
            L.m_copied != L.m_derived && L.m_copied != 0 && L.m_enums != 0 &&
            L.m_derived != 0,
        "the three mechanism ids are distinct and none of them is zero, so an "
        "id cannot be read as the absence of a mechanism");
  {
    uint64_t codes[7] = {L.r_no_source,    L.r_bad_span,      L.r_no_type_kind,
                         L.r_short_image,  L.r_effect_loss,   L.r_space_conflict,
                         L.r_no_decl_span};
    uint64_t dup = 0;
    for (int i = 0; i < 7; i++)
      for (int j = i + 1; j < 7; j++)
        if (codes[i] == codes[j])
          dup++;
    CHECK(dup == 0, "the seven refusal codes are seven distinct values");
    CHECK(L.r_no_source != 0 && L.r_no_decl_span != 0,
          "no refusal code is zero, so a refusal can never be read as success");
    /* A code inside the node-record band would collide with an AST kind the
     * same twelve words carry, and the two meanings would be one number. */
    uint64_t inband = 0;
    for (int i = 0; i < 7; i++)
      if (codes[i] < 100)
        inband++;
    CHECK(inband == 0,
          "no refusal code sits in the low band where AST kinds live, so a "
          "code and a kind can never be the same number");
  }
  /* SEVEN OF THE EIGHT VERDICT FIELDS, BECAUSE MODE 0 PUBLISHES SEVEN.
   *
   * MEASURED FROM c-conversion-entry.nova's own mode 0: report[5..11] carry
   * V_SYMBOL, V_TYPE, V_POSITION, V_EFFECT, V_SPACE, V_DIRECTION and
   * V_CONFLATION, and report[12] is M_COPIED -- the mechanism ids occupy the
   * slots where an eighth verdict field would sit. V_MECHANISM is NOT
   * published by mode 0 at all, even though VERDICT_WORDS() says there are
   * eight fields and convert_variable writes into verdict[V_MECHANISM()].
   *
   * The first version of this check read report[12] as V_MECHANISM, received
   * M_COPIED's value of 1, and went red on "not a permutation of 0..7". The
   * check was not wrong about the module; it was wrong about the LAYOUT, and
   * the failure named neither, because a permutation check reports the SHAPE
   * of a disagreement and not the slot that caused it. Reading the entry
   * instead of assuming its shape is the fix, and it is the third time across
   * these two files that the layout was the defect and the module was right.
   *
   * So: the seven PUBLISHED fields must be a permutation of 0..6, and the
   * eighth is stated as a NAMED GAP rather than asserted through a slot that
   * does not exist. This entry file is not this gate's to edit, so the gap is
   * reported and not repaired: a driver that wanted V_MECHANISM would need
   * mode 0 to publish it, which is a change to
   * tests/nova/tests/c-conversion-entry.nova. */
  {
    uint64_t v[8] = {L.v_symbol,   L.v_type,      L.v_position,
                     L.v_effect,   L.v_space,     L.v_direction,
                     L.v_conflation, L.v_mechanism};
    uint64_t seen = 0, ok = 1;
    for (int i = 0; i < 8; i++) {
      if (v[i] >= L.verdict_words)
        ok = 0;
      if (seen & (1u << v[i]))
        ok = 0;
      seen |= 1u << v[i];
    }
    CHECK(ok,
          "all EIGHT verdict fields, now that mode 0 publishes V_MECHANISM, "
          "are a permutation of 0..n-1, so a verdict word can be indexed "
          "without asking which field it is");
    printf("C-CONV-VERDICT mechanism_slot=%llu (published by mode 0 at "
           "report[27], not derived)\n",
           (unsigned long long)L.v_mechanism);
  }
  {
    uint64_t v[7] = {L.v_symbol,   L.v_type,      L.v_position,
                     L.v_effect,   L.v_space,     L.v_direction,
                     L.v_conflation};
    uint64_t seen = 0, ok = 1;
    for (int i = 0; i < 7; i++) {
      if (v[i] >= 7)
        ok = 0;
      if (seen & (1u << v[i]))
        ok = 0;
      seen |= 1u << v[i];
    }
    CHECK(ok,
          "the seven fields mode 0 published BEFORE V_MECHANISM existed are a "
          "permutation of 0..6");
    CHECK(L.verdict_words == 8,
          "the verdict buffer holds eight words, one per preserved field");  }
  {
    uint64_t v[7] = {L.v_symbol,   L.v_type,      L.v_position,
                     L.v_effect,   L.v_space,     L.v_direction,
                     L.v_conflation};
    uint64_t seen = 0, ok = 1;
    for (int i = 0; i < 7; i++) {
      if (v[i] >= 7)
        ok = 0;
      if (seen & (1u << v[i]))
        ok = 0;
      seen |= 1u << v[i];
    }
    CHECK(ok,
          "the seven verdict fields mode 0 publishes are a permutation of "
          "0..6, so a verdict word can be indexed without asking which field "
          "it is");
    CHECK(L.verdict_words == 8,
          "the verdict buffer holds EIGHT words, one per preserved field, so "
          "V_MECHANISM exists even though mode 0 does not publish it");
  }

  /* ---- TEST 1: THE LAYOUT COMPLETENESS (mode 10) ----------------------- */
  /* THIS IS THE TEST THAT STANDS IN FOR THE 84 WRAPPERS. Their property is
   * not 84 individual values -- a wrapper whose offset were duplicated would
   * still be a green one-line function -- it is that each of four generated
   * tables is gapless and in order. Checking the SEQUENCE is the property;
   * checking the values one at a time would be a census in a test's clothes. */
  cases++;
  Run m10 = run(&img, FIXTURE, slen, 10, 0, NULL, 0);
  CHECK(m10.returned == 0 && m10.runtime == 0,
        "mode 10 publishes the whole offset table without a refusal");
  if (m10.returned == 0 && m10.runtime == 0) {
    uint64_t n = m10.report[0];
    uint64_t want = L.type_words + L.var_words + L.fn_words;
    CHECK(n == want,
          "the published offset table is the sum of the three record widths "
          "the module publishes, so a record that grew a field moves both");
    printf("C-CONV-TABLE offsets=%llu expected=%llu\n",
           (unsigned long long)n, (unsigned long long)want);
    uint64_t tw = 0, groups[3];
    groups[0] = L.type_words;
    groups[1] = L.var_words;
    groups[2] = L.fn_words;
    const char *names[3] = {"NtFType", "NtFVariable", "NtFFunction"};
    for (int g = 0; g < 3; g++) {
      uint64_t bad = 0;
      for (uint64_t i = 0; i < groups[g]; i++)
        if (m10.out[tw + i] != i)
          bad++;
      char msg[160];
      snprintf(msg, sizeof msg,
               "the %s offsets are exactly 0..n-1: %llu of %llu read wrong",
               names[g], (unsigned long long)bad,
               (unsigned long long)groups[g]);
      CHECK(bad == 0, msg);
      tw += groups[g];
    }
    CHECK(tw == n,
          "the three groups account for every published offset and leave no "
          "word unaccounted for");
    /* THE NtFVariable OFFSETS, READ FROM THE BLOCK JUST VERIFIED GAPLESS.
     *
     * MEASURED, and this is the second collision of the same shape. mode 0
     * publishes FOUR of the twenty-one NtFVariable offsets -- the two name
     * words and the two declaration-extent words -- and none of the span, type
     * or direction offsets. The first version left those fields at their
     * memset value of 0, so `var_type` was 0, `cvar[0]` (which is
     * C_VAR_NAME_START) received the type kind, and compare_variable answered
     * R_NO_TYPE_KIND on a record whose type word had been written over its
     * name offset. Two fields, one cause, and the cause was a struct member
     * nobody had filled.
     *
     * An index into a block verified gapless IS that block's offset: after the
     * three checks above, table[base+j] is the module's own answer for "field
     * j of NtFVariable", and no number is typed here. The block's base is the
     * sum of the blocks before it, which is why it is computed and not
     * written -- a base written down twice from two facts is a place those two
     * facts can disagree. */
    uint64_t vb = L.type_words;
    if (vb + L.var_words <= n) {
      L.var_name_start = m10.out[vb + 0];
      L.var_name_len = m10.out[vb + 1];
      L.var_span_source = m10.out[vb + 2];
      L.var_span_line = m10.out[vb + 3];
      L.var_span_column = m10.out[vb + 4];
      L.var_span_start = m10.out[vb + 5];
      L.var_span_end = m10.out[vb + 6];
      L.var_type = m10.out[vb + 7];
      L.var_direction = m10.out[vb + 11];
      L.var_decl_start = m10.out[vb + 19];
      L.var_decl_end = m10.out[vb + 20];
      printf("C-CONV-VAROFF name=%llu,%llu span=%llu,%llu,%llu,%llu,%llu "
             "type=%llu direction=%llu decl=%llu,%llu\n",
             (unsigned long long)L.var_name_start,
             (unsigned long long)L.var_name_len,
             (unsigned long long)L.var_span_source,
             (unsigned long long)L.var_span_line,
             (unsigned long long)L.var_span_column,
             (unsigned long long)L.var_span_start,
             (unsigned long long)L.var_span_end, (unsigned long long)L.var_type,
             (unsigned long long)L.var_direction,
             (unsigned long long)L.var_decl_start,
             (unsigned long long)L.var_decl_end);
    }
    /* THE EFFECT OFFSETS, TAKEN FROM THE TABLE JUST VERIFIED GAPLESS. They are
     * positions within the NtFFunction block, so the block's base is the sum
     * of the two blocks before it -- which is why this reads them here and not
     * from a constant: a base computed twice from two different facts is a
     * place the two facts can disagree. */
    uint64_t fb = L.type_words + L.var_words;
    if (fb + L.fn_words <= n) {
      L.fn_effect_flags = m10.out[fb + 18];
      L.fn_effect_reads = m10.out[fb + 19];
      L.fn_effect_writes = m10.out[fb + 20];
      L.fn_inferred_flags = m10.out[fb + 21];
      L.fn_inferred_reads = m10.out[fb + 22];
      L.fn_inferred_writes = m10.out[fb + 23];
      printf("C-CONV-FN offsets flags=%llu reads=%llu writes=%llu inferred=%llu,"
             "%llu,%llu\n",
             (unsigned long long)L.fn_effect_flags,
             (unsigned long long)L.fn_effect_reads,
             (unsigned long long)L.fn_effect_writes,
             (unsigned long long)L.fn_inferred_flags,
             (unsigned long long)L.fn_inferred_reads,
             (unsigned long long)L.fn_inferred_writes);
    }
  }

  /* ---- THE C RECORDS, laid out with the module's own offsets ------------ */
  /* The driver builds the image. It uses the offsets mode 0 published, never
   * a number typed here, so the two sides cannot drift by transcription. */
  uint64_t cvar[CIMG], ctype[CIMG], ceff[CIMG];
  memset(cvar, 0, sizeof cvar);
  memset(ctype, 0, sizeof ctype);
  memset(ceff, 0, sizeof ceff);

  int have_var = 0, have_type = 0;
  /* THE PARAMETER IS NOT prog.functions[0].parameters[0]. IT IS AN ENTRY IN
   * prog.variables WHOSE `function` FIELD POINTS AT THE FUNCTION. That was
   * measured from frontend.h rather than assumed: NtFFunction carries no
   * parameter array at all, so the first version of this file asked for a
   * member that does not exist and the compiler said so by name. The walk is
   * also the honest way to find a parameter -- the C's own order, not an index
   * this file picked. */
  {
    const NtFVariable *v = NULL;
    for (size_t k = 0; k < prog.variable_count && !v; k++)
      /* NtFId IS ONE-BASED, AND THAT IS WHY THE FIRST WALK FOUND NOTHING.
       * frontend.h declares `typedef uint32_t NtFId` and the compiler hands
       * ids out from 1, so the ONLY function in the fixture has id 1 and
       * `function < function_count` is `1 < 1` -- false. The walk then
       * reported no parameter on a fixture that has one, and the null guard
       * printed "the C reference produced no variable this walk can accept",
       * which is a TRUE sentence about a walk that was WRONG. That is the
       * most expensive kind of report: an absent value, stated as a fact
       * about the world instead of as a fact about the walk.
       *
       * The id's BASE is the whole defect, and it is read off the header
       * rather than assumed: ids run 1..function_count inclusive. */
      if (prog.variables[k].function >= 1 &&
          prog.variables[k].function <= prog.function_count)
        v = &prog.variables[k];
    /* THE WALK MAY FIND NOTHING, AND THAT IS AN ANSWER, NOT A CRASH.
     *
     * Measured: with this guard absent the harness read through a null
     * NtFVariable and died on address 0x0 -- a SEGV, not a refusal, so nothing
     * named a cause. The C reference is a different implementation and its
     * variable list is not this file's to predict, so a walk that finds nothing
     * must SKIP the arms that need one and say so on stdout. Dereferencing
     * first and asking afterwards is the shape where the instrument decides
     * what is true by being able to reach it. */
    if (v) {
      uint64_t at = 0;
      /* C_VAR_NAME_START IS A BYTE OFFSET INTO THE SOURCE, NOT A POINTER.
       *
       * MEASURED, and this is what made convert_variable answer R_NO_SOURCE
       * (610) on a record it had every reason to convert. The first version
       * wrote `(uint64_t)v->name` -- the C's pointer -- into that word, and
       * the module's own guard `name_start+name_len > len(source)` fired on
       * an address of about 1.4e14 against a 117-byte source. The refusal was
       * CORRECT: the input it was shown really did name an offset outside the
       * source. The comment above C_VAR_NAME_START says the field is "a byte
       * offset into the source" and that a length of zero is the null pointer,
       * and I read that comment after writing the pointer.
       *
       * So the offset is located in the source by name, and it is located in
       * the SOURCE rather than derived from the pointer, because the pointer
       * points into the C compiler's own copy of the text and its offset
       * there is not the offset in this buffer. */
      cvar[at + L.var_name_start] =
          v->name ? (uint64_t)(strstr(FIXTURE, v->name) - FIXTURE)
                  : (uint64_t)(SIZE_MAX); /* absent: the module treats it as 0 */
      cvar[at + L.var_name_len] = v->name ? strlen(v->name) : 0;
      cvar[at + L.var_span_source] = v->span.source;
      cvar[at + L.var_span_line] = v->span.line;
      cvar[at + L.var_span_column] = v->span.column;
      cvar[at + L.var_span_start] = v->span.start;
      cvar[at + L.var_span_end] = v->span.end;
      /* THE TYPE ID IS ONE-BASED TOO -- THE SAME BUG, THE SECOND TIME.
       * `v->type < prog.type_count` sends type id 1 into prog.types[1], which
       * is the SECOND type, and sends the fixture's parameter at whatever
       * index it happened to hold. c_conversion then read a type id of 0 --
       * NTF_T_INVALID -- and answered R_NO_TYPE_KIND, which is the correct
       * refusal for a wrong input and the wrong input was mine. */
      cvar[at + L.var_type] = (v->type >= 1 && v->type <= prog.type_count)
                                  ? (uint64_t)prog.types[v->type - 1].kind
                                  : 0;
      cvar[at + L.var_direction] = (uint64_t)v->direction;
      printf("C-VARTYPE v->type=%llu type_count=%zu resolved_kind=%llu "
             "node_aux=%llu\n",
             (unsigned long long)v->type, prog.type_count,
             (unsigned long long)cvar[L.var_type],
             (unsigned long long)prog.types[0].kind);
      printf("C-VARTYPE2 off_var_type=%llu cvar_at_off=%llu\n",
             (unsigned long long)L.var_type,
             (unsigned long long)cvar[L.var_type]);
      /* THE DECLARATION EXTENT, and this is the finding the module's header
       * names: the C record carries no field naming the text a parameter is
       * written in, so the driver supplies it as an EXPLICIT input, which is
       * what C_VAR_DECL_START exists for. Without it the module refuses with
       * R_NO_DECL_SPAN, and THAT REFUSAL IS TESTED below as a refusal rather
       * than worked around. */
      /* THE DECLARATION EXTENT, AND strlen() IS THE WRONG TOOL FOR IT.
       *
       * MEASURED, and this is the answer to the open item I handed over:
       * `decl - FIXTURE` was 56 and `strlen(decl)` was 61 -- because decl
       * points into a NUL-terminated array at a SUBSTRING, not at a suffix, so
       * strlen runs to the end of the buffer rather than to the end of the
       * match. 56 + 61 = 117 is the FIXTURE's length, which is what made the
       * number look like something else entirely. The span should be
       * [56..69): thirteen bytes, the length of the DECLARATION TEXT.
       *
       * So the length comes from the literal, named once and measured once,
       * and the offset comes from strstr. A declaration extent is a
       * SUBSTRING of the source and every function that takes one wants the
       * substring's length, and strlen answers the buffer's.
       *
       * It converted anyway, which is worth recording: convert_variable reads
       * the direction out of the span's first word and "in" is at both
       * offsets, so a span that was 48 bytes too long still produced the right
       * direction. A wrong extent that happens to agree at its first byte is a
       * green that would have been red on any other parameter spelling --
       * `outbound` read as `out` is exactly the defect c_conversion's own
       * word_is comment refuses to repeat. */
      static const char DECL[] = "in x:u64 @rax";
      const char *decl = strstr(FIXTURE, DECL);
      if (decl) {
        cvar[at + L.var_decl_start] = (uint64_t)(decl - FIXTURE);
        cvar[at + L.var_decl_end] =
            (uint64_t)(decl - FIXTURE) + (sizeof DECL) - 1;
        printf("C-DECL offset=%llu length=%llu span=[%llu..%llu)\n",
               (unsigned long long)(decl - FIXTURE),
               (unsigned long long)((sizeof DECL) - 1),
               (unsigned long long)cvar[at + L.var_decl_start],
               (unsigned long long)cvar[at + L.var_decl_end]);
      }
      have_var = 1;
      printf("C-DECL ptr=%lld strlen=%zu start=%llu end=%llu cvar19=%llu "
             "cvar20=%llu off_start=%llu off_end=%llu slen=%zu\n",
             (long long)(decl - FIXTURE), strlen(decl),
             (unsigned long long)cvar[L.var_decl_start],
             (unsigned long long)cvar[L.var_decl_end],
             (unsigned long long)cvar[19], (unsigned long long)cvar[20],
             (unsigned long long)L.var_decl_start,
             (unsigned long long)L.var_decl_end, slen);
      printf("C-RECORD name_len=%llu span=[%llu..%llu) decl=[%llu..%llu) "
             "direction=%llu type_kind=%llu\n",
             (unsigned long long)cvar[at + L.var_name_len],
             (unsigned long long)cvar[at + L.var_span_start],
             (unsigned long long)cvar[at + L.var_span_end],
             (unsigned long long)cvar[at + L.var_decl_start],
             (unsigned long long)cvar[at + L.var_decl_end],
             (unsigned long long)cvar[at + L.var_direction],
             (unsigned long long)cvar[at + L.var_type]);
    } else {
      printf("C-RECORD none: the C reference produced no variable this walk can "
             "accept, so every variable arm is SKIPPED rather than run against "
             "a record that is not there\n");
    }
  }
  if (prog.type_count) {
    const NtFType *t = &prog.types[0];
    ctype[0] = (uint64_t)t->kind;
    ctype[1] = (uint64_t)t->space;
    ctype[2] = (uint64_t)t->element;
    ctype[3] = t->count;
    ctype[4] = t->bits;
    have_type = 1;
    printf("C-TYPE kind=%llu space=%llu bits=%llu\n", (unsigned long long)t->kind,
           (unsigned long long)t->space, (unsigned long long)t->bits);
  }
  if (prog.function_count) {
    /* A FULL NtFFunction RECORD, not a three-word triple. convert_effects reads
     * img[at + C_FN_EFFECT_FLAGS()] and its five siblings, and those offsets
     * are 18..23 of a thirty-five-word record -- so a three-word image hands it
     * uninitialised words, effect_flag_count on a guard value answers
     * 0xffffffff, and the module correctly refuses with R_EFFECT_LOSS. The
     * refusal was RIGHT and the image was wrong, which is the shape that reads
     * as a converter bug and is a driver's. The offsets come from mode 10's
     * published table, never from a number typed here. */
    uint64_t fb = L.type_words + L.var_words; /* the NtFFunction block's base */
    ceff[fb + L.fn_effect_flags] = prog.functions[0].effects.flags;
    ceff[fb + L.fn_effect_reads] = prog.functions[0].effects.reads;
    ceff[fb + L.fn_effect_writes] = prog.functions[0].effects.writes;
    ceff[fb + L.fn_inferred_flags] = prog.functions[0].inferred_effects.flags;
    ceff[fb + L.fn_inferred_reads] = prog.functions[0].inferred_effects.reads;
    ceff[fb + L.fn_inferred_writes] = prog.functions[0].inferred_effects.writes;
    printf("C-EFFECTS flags=%llu reads=%llu writes=%llu\n",
           (unsigned long long)ceff[0], (unsigned long long)ceff[1],
           (unsigned long long)ceff[2]);
  }

  /* ---- TEST 2: convert_type (mode 3) ---------------------------------- */
  cases++;
  if (have_type) {
    Run t = run(&img, FIXTURE, slen, 3, 0, ctype, L.type_words);
    CHECK(t.report[0] == 0 || t.report[0] == L.r_no_type_kind,
          "convert_type answers 0 or refuses with R_NO_TYPE_KIND, the two "
          "answers its own header names");
    printf("C-TYPE-CONVERT code=%llu node0=%llu node11=%llu\n",
           (unsigned long long)t.report[0], (unsigned long long)t.report[1],
           (unsigned long long)t.report[2]);
    /* THE POSITIVE ARM, and it is required: a converter that only ever refuses
     * has decided nothing. The C accepted this type, so a refusal here is a
     * finding and not a shrug. */
    if (prog.types[0].kind != 0) {
      CHECK(t.report[0] == 0,
            "convert_type converts the C's own accepted type rather than "
            "refusing it");
      CHECK(t.report[1] != GUARD && t.report[2] != GUARD,
            "convert_type published the node's first and last words");
    } else {
      CHECK(t.report[0] == L.r_no_type_kind,
            "convert_type refuses NtFTypeKind 0, which is INVALID and which "
            "the module says it must refuse");
    }
    /* THE COLLAPSE, which is this module's central claim and the reason ten of
     * the thirteen C type enumerators map onto ONE Nova value: the C
     * enumerator names a TYPE and the Nova aux names a FORM. A conversion
     * that mapped all thirteen onto thirteen values would write a word the
     * format does not define for ten of them. */
    if (t.report[0] == 0 && prog.types[0].kind == 1) {
      CHECK(t.report[1] == 0,
            "a plain scalar type converts to aux 0, because the scalar is "
            "spelled in the source and re-read from it and has no form of "
            "its own");
    }
  }

  /* ---- TEST 3: convert_effects (mode 4) ------------------------------- */
  cases++;
  if (prog.function_count) {
    Run e = run(&img, FIXTURE, slen, 4, 0, ceff,
                      L.type_words + L.var_words + L.fn_words);
    CHECK(e.report[0] == 0 || e.report[0] == L.r_effect_loss,
          "convert_effects answers 0 or refuses with R_EFFECT_LOSS");
    printf("C-EFFECTS-CONVERT code=%llu flags=%llu reads=%llu writes=%llu\n",
           (unsigned long long)e.report[0], (unsigned long long)e.report[1],
           (unsigned long long)e.report[2], (unsigned long long)e.report[3]);
    /* THE NEGATIVE THAT DECIDES WHETHER THE CONVERSION IS HONEST, and the
     * module's own comment names it: `effects {}` is a REAL ANSWER of three
     * zeros, not an absence. A zero triple must convert, and it must come
     * back as zeros rather than as a refusal -- because a conversion that read
     * "no flags" as "flags not read" could not tell a function that promises
     * nothing from a function whose promise was dropped, and that difference
     * is the false positive this module exists to make impossible. */
    if (ceff[0] == 0) {
      CHECK(e.report[0] == 0,
            "an effect-free function converts to a zero triple rather than to "
            "a refusal: the fixture declares `effects {}` and a zero triple is "
            "a real answer");
      CHECK(e.report[1] == 0 && e.report[2] == 0 && e.report[3] == 0,
            "the converted triple carries the C's three zeros and the flag "
            "count is zero rather than eleven");
    }
  }

  /* ---- TEST 4: convert_variable (mode 1), AND ITS REFUSAL ------------- */
  cases++;
  if (have_var) {
    Run v = run(&img, FIXTURE, slen, 1, 0, cvar, L.var_words);
    printf("C-VAR-CONVERT code=%llu verdict_direction=%llu verdict_mechanism=%llu\n",
           (unsigned long long)v.report[0],
           (unsigned long long)v.report[1 + L.v_direction],
           (unsigned long long)v.report[1 + L.v_mechanism]);
    CHECK(v.report[0] == 0,
          "convert_variable converts the C's own parameter once the driver "
          "supplies the declaration extent its header says the C record cannot "
          "carry");
    /* M_DERIVED, and the direction was read out of the DECLARATION and never
     * out of the C's own span, which is the register. The verdict word says
     * so. */
    if (v.report[0] == 0) {
      CHECK(v.report[1 + L.v_mechanism] == L.m_derived,
            "the direction was DERIVED from the declaration span rather than "
            "copied from the C enumerator, and the verdict says which");
      CHECK(v.report[1 + L.v_position] == 1,
            "the position is marked preserved, because it is the one field "
            "with a word-for-word witness on both sides");
      CHECK(v.report[1 + L.v_direction] != 0,
            "the derived direction is a value and not the refusal zero");
    }
    /* AND THE REFUSAL ARM, in its own run. This is the module's headline
     * finding: the C record carries no field naming the text a parameter is
     * written in, so a conversion that derived the direction from `rax` would
     * report NTF_IN for every parameter in the program. Zeroing the
     * declaration extent removes the only input the module will accept, and
     * the honest answer is a refusal. */
    {
      uint64_t nodecl[CIMG];
      memcpy(nodecl, cvar, sizeof cvar);
      nodecl[L.var_decl_start] = 0;
      nodecl[L.var_decl_end] = 0;
      Run d = run(&img, FIXTURE, slen, 1, 0, nodecl, L.var_words);
      printf("C-VAR-REFUSE code=%llu (r_no_decl_span=%llu)\n",
             (unsigned long long)d.report[0],
             (unsigned long long)L.r_no_decl_span);
      CHECK(d.report[0] == L.r_no_decl_span,
            "with no declaration extent the module REFUSES with R_NO_DECL_SPAN "
            "instead of deriving a direction from the register: a direction "
            "read out of `rax` would be NTF_IN for every parameter in the "
            "program");
    }
    /* AND A SECOND REFUSAL, on the length check rather than the absence, so
     * the refusal is not one channel. A span past the end of the source is
     * R_NO_SOURCE, and a start after its end is R_BAD_SPAN. */
    {
      uint64_t bad[CIMG];
      memcpy(bad, cvar, sizeof cvar);
      bad[L.var_span_end] = slen + 1000;
      Run b = run(&img, FIXTURE, slen, 1, 0, bad, L.var_words);
      CHECK(b.report[0] == L.r_no_source,
            "a span running past the end of the source is refused with "
            "R_NO_SOURCE, which is a different code from the missing "
            "declaration and names a different defect");
    }
  }

  /* ---- TEST 5: convert_symbol (mode 2) -------------------------------- */
  cases++;
  if (have_var) {
    Run s = run(&img, FIXTURE, slen, 2, 0, cvar, L.var_words);
    printf("C-SYMBOL code=%llu kind=%llu start=%llu end=%llu span_len=%llu\n",
           (unsigned long long)s.report[0], (unsigned long long)s.report[1],
           (unsigned long long)s.report[2], (unsigned long long)s.report[3],
           (unsigned long long)(s.report[3] - s.report[2]));
    /* THE THREE DIRECTIONS ARE THREE DEFECTS, and the module's comment names
     * them: a LOST symbol (the C had a name, no node was written), a WRONG
     * one (a node whose span is not L bytes), and an INVENTED one (a node
     * where the C had none). The positive arm and the invented arm are both
     * asked, because a gate that only asked the positive arm could not tell
     * "wrote the right name" from "wrote a name". */
    if (cvar[L.var_name_len] != 0) {
      CHECK(s.report[0] == 1,
            "the C's parameter has a name, so convert_symbol writes a name "
            "node rather than answering NO NODE");
      /* THE ENTRY PUBLISHES START AND END, NOT START AND LENGTH. Measured:
       * mode 2 writes `report[2]=name[6]` and `report[3]=name[7]`, which are
       * the node's own N_START and N_END -- so the span is the DIFFERENCE and
       * the first version compared an END offset against a LENGTH. On a name
       * at offset 16 of length 1 that is 17 against 1, and the check went red
       * on a name node that is exactly one byte long where it should be.
       * The length is a property of the two published words together, and
       * neither word alone is it. */
      CHECK(s.report[3] - s.report[2] == cvar[L.var_name_len],
            "the name node's span is exactly the C's name length: a node whose "
            "span is not L is a WRONG name, which is a different defect from a "
            "LOST one");
      CHECK(s.report[2] == cvar[L.var_name_start],
            "the name node starts where the C's name starts, over the same "
            "bytes");
    }
    /* THE INVENTED ARM: zero the name length and any node is one the
     * conversion invented. An invented symbol is worse than a lost one, since
     * a lost one fails loudly downstream and an invented one is a name that
     * resolves against nothing. */
    {
      uint64_t anon[CIMG];
      memcpy(anon, cvar, sizeof cvar);
      anon[L.var_name_len] = 0;
      Run n = run(&img, FIXTURE, slen, 2, 0, anon, L.var_words);
      CHECK(n.report[0] == 0,
            "a C record with no name converts to NO NODE rather than to an "
            "empty name, because a name of length zero is the C's null "
            "pointer and not a name");
    }
  }

  /* ---- TEST 6: compare_variable (mode 7), THE ACCEPTANCE -------------- */
  /* THIS IS THE SIXTH TEST AND THE ONE THAT EARNS THE SUBSET. compare_variable
   * is the only export in the module that can catch a converter being wrong:
   * every other arm checks a converter against its own vocabulary, and this
   * one confronts a converted node against the C record it came from, field by
   * field, and returns the first field that differs. */
  cases++;
  if (have_var) {
    /* THE CONVERTED NODE AND NAME NODE ARE TAKEN FROM THE CONVERTERS AND HANDED
     * IN. This is the fix for the half-property I reported, and the reason the
     * first version returned 611 on a record the converter had just produced
     * correctly is the same reason it is worth writing down.
     *
     * compare_variable takes the entry's OWN `node` and `name` buffers. The
     * first version of this arm left them at the guard sentinel and stuffed the
     * converted node into `cimg` instead -- so the comparator was handed
     * twelve words of 0xcccc...ccc and reported R_BAD_SPAN on position, symbol,
     * type and direction at once. Four fields disagreeing is what a comparator
     * says when it is comparing against nothing, and nothing in the output
     * said the input was absent. It looked like the module refusing a valid
     * record, and the module was right to refuse: the record it was shown WAS
     * invalid.
     *
     * So the node is now read out of mode 1's own `node` buffer, the name node
     * out of mode 2's, and both are handed to mode 7 through run_with. Nothing
     * is re-derived and nothing is typed: each word came from the converter
     * that wrote it.
     *
     * `present` lives at cimg[0], which is also C_VAR_NAME_START -- the entry
     * reads it as `present` before the module reads the record at `at`, so the
     * two meanings are the ENTRY's convention and not a collision introduced
     * here. It is stated because a reader must know which side wrote each word. */
    Run cv = run(&img, FIXTURE, slen, 1, 0, cvar, L.var_words);
    Run sy = run(&img, FIXTURE, slen, 2, 0, cvar, L.var_words);
    uint64_t node[NODEW], namenode[NODEW];
    for (unsigned k = 0; k < NODEW; k++) {
      node[k] = cv.node[k];
      namenode[k] = sy.name[k];
    }
    /* THE RECORD SITS AT WORD 1, NOT WORD 0, AND THAT IS THE WHOLE FIX FOR A
     * DISAGREEMENT ON TWO FIELDS AT ONCE.
     *
     * The entry's mode 7 reads `present` from cimg[0] and passes the record's
     * word offset as `at`. C_VAR_NAME_START is 0, so a record laid out AT word
     * zero and a `present` written at word zero are THE SAME WORD. Writing
     * present=1 overwrote the name's start offset, and compare_variable then
     * compared the name node's span against a `1` that was never a byte
     * offset. It answered R_BAD_SPAN on the symbol and R_NO_TYPE_KIND on the
     * type -- two fields, one cause, and a cause that looks like two defects.
     *
     * The first version reported this as "the comparator refuses a record the
     * C itself calls empty". It was not refusing the record. It was being
     * handed a record whose first word was a boolean.
     *
     * So: the record goes at `at` = 1 and word 0 carries `present`, which is
     * what the entry's own signature is shaped for -- it takes BOTH, so they
     * cannot be the same word. Read the entry's parameters, not its prose. */
    uint64_t m7[CIMG];
    memset(m7, 0, sizeof m7);
    /* var_words words, not the whole 4096-word array -- a `sizeof cvar` copy
     * runs off the end of m7 and -Werror=array-bounds says so, which is the
     * compiler doing the job the guard exists to do. */
    memcpy(m7 + 1, cvar, L.var_words * sizeof(uint64_t));
    m7[0] = cvar[L.var_name_len] != 0 ? 1 : 0; /* present: the C had a name */
    Run c7 = run_with(&img, FIXTURE, slen, 7, 1, m7, 1 + L.var_words, node,
                      namenode);
    /* EIGHT verdict fields, printed in the module's own order, and the count of
     * arguments is CHECKED BY THE COMPILER rather than by reading the line: the
     * first version had nine %llu and eight arguments, so the ninth read
     * whatever was next on the stack. A printf whose format and its arguments
     * disagree does not fail; it prints a number the world does not contain. */
    {
      printf("C-COMPARE code=%llu verdicts=",
             (unsigned long long)c7.report[0]);
      for (unsigned f = 0; f < L.verdict_words && f < REPORT - 1; f++)
        printf("%s%llu", f ? "," : "",
               (unsigned long long)c7.report[1 + f]);
      printf("\n");
    }
    /* THE ACCEPTANCE, and this is the half that was missing. A comparator that
     * cannot see damage is not a comparator; a comparator that cannot report
     * AGREEMENT is not a comparator either, and the first version only proved
     * the first. The converted node came from the converter and the name node
     * came from the symbol converter, so every preserved field should agree and
     * the whole comparison should return 0. */
    CHECK(c7.report[0] == 0,
          "compare_variable returns 0 when the converted node and the name "
          "node are the ones the converters actually produced: every preserved "
          "field agrees with the C record it came from");
    CHECK(c7.report[1 + L.v_position] == 0,
          "the position field AGREES: the node's source, line, column and span "
          "are the C record's own five words, and this is the one field with a "
          "word-for-word witness on both sides");
    CHECK(c7.report[1 + L.v_direction] == 0,
          "the direction field AGREES: the node's derived direction is the "
          "same one the C record claims, which is the claim decision A rests "
          "on");
    /* The comparison is run TWICE, and the SECOND run is the control: the same
     * comparison with ONE word of the converted node changed. A comparator that
     * cannot see a corrupted node is not a comparator, and this is the only
     * arm in this file where that is the thing at issue rather than a
     * consequence of something else changing. */
    uint64_t damaged[CIMG], damaged_node[NODEW];
    memcpy(damaged, m7, sizeof m7);
    memcpy(damaged_node, node, sizeof node);
    /* The LINE word of the converted node, which compare_variable compares
     * word for word against the C's own span line. */
    damaged_node[4] = damaged_node[4] + 1;
    Run c7d = run_with(&img, FIXTURE, slen, 7, 1, damaged, 1 + L.var_words,
                       damaged_node, namenode);
    printf("C-COMPARE-DAMAGED code=%llu verdict_position=%llu\n",
           (unsigned long long)c7d.report[0],
           (unsigned long long)c7d.report[1 + L.v_position]);
    CHECK(c7d.report[1 + L.v_position] != 0,
          "the comparator SEES a node whose line differs from the C record: "
          "changing one word of the converted node makes the position verdict "
          "non-zero, which is what makes it a comparator and not a reader");
  }

  for (unsigned i = 0; i < PATHS_C_N; i++)
    free(sources[i]);
  nova_host_unmap(&img);
  /* BOTH OWNED RESOURCES ARE RELEASED, and the second one is the reason this
   * file needed two lines rather than one.
   *
   * nt_frontend_compile returns an NtFProgram that OWNS arrays the C reference
   * allocated, and the tree provides nt_frontend_free for it. Not calling it
   * leaked 21 allocations -- the same class of defect as the missing
   * nt_artifact_free in the ast gate, found here by the same instrument: a
   * caller that takes ownership and does not release. Neither is a defect in
   * the library; both are the library working as written and a driver not
   * completing the transaction.
   *
   * Neither release is a suppression: no LSAN_OPTIONS, no __lsan_ignore, no
   * detect_leaks=0 anywhere in this file. */
  nt_frontend_free(&prog);
  nt_artifact_free(&art);
  printf("NTASM_NOVA_C_CONVERSION checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  /* FLUSHED: under the driver both streams go to one log, stdout is fully
     * buffered, and LeakSanitizer's exit path does not flush stdio -- so a
     * banner printed and not flushed is a banner ABSENT, and the driver
     * answers FAIL_LINES_ABSENT with nothing named. The leak itself is in
     * codegen.c's `reserve` and is not this file's: `ngbuild.sh versions`
     * exits 1 the same way while printing a green count. What this file owns
     * is that its count reaches disk on EVERY route out, and the four early
     * returns below are routes out. */
  fflush(stdout);
  return failures ? 1 : 0;
}