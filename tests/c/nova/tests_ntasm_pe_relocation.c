/* tests_ntasm_pe_relocation.c -- OPENS THE THIRD DOOR.
 *
 * The door: tests/nova/tests/pe-relocation-entry.nova, which until
 * now was written and loaded by nobody. It is four lines wide --
 *
 *     fn main(kind,source,target,addend)->ntasm_pe.Value
 *         = ntasm_pe.relocation_value(kind,source,target,addend)
 *
 * -- and it is the ONLY caller-visible route to that function. This file is
 * the harness that runs it and asserts a property on the result.
 *
 * WHAT IT PUBLISHES. ntasm_pe.Value is a two-word record {code, value}
 * (compiler/nova/formats/pe/pe.nova, "export struct Value { code:u64,value:u64 }"),
 * so the result is a pair, not a number. `code` is the diagnostic (0 accept,
 * 1 the i64 guard, 2 the arithmetic range guard, 3 the displacement does not
 * fit an int32, 4 a kind outside {1,2}) and `value` is the patched field on
 * acceptance.
 *
 * THE PROPERTY IS THE OTHER HALF'S, NOT MINE. nt_relocation_value in
 * pe_layout.h is the C implementation of the same contract, and it is not a
 * table written for this gate: it is the function object_materialize.c calls
 * for every relocation it stores, and ntasm.c calls for the ones it emits.
 * pe_oracle.c exposes it as nova_oracle_relocation, and pe_oracle.c is in the
 * driver's own LIBS list, so the oracle this gate compares against is the
 * production one and not a second copy. Three things are asserted per case:
 *
 *   1. REFUSAL SETS AGREE. code == 0 exactly when the oracle returns 1. The
 *      Nova side names FOUR refusals and the C side names one, so this is a
 *      refinement and not an equality: what is asserted is that no input the
 *      C writer would have refused is accepted here, and none it would have
 *      accepted is refused. A gate asserting "the same code" would be
 *      asserting a form the C side does not publish.
 *   2. ON ACCEPTANCE, value EQUALS the oracle's value. This is the load
 *      bearing half and the reason the door is worth opening.
 *   3. ON REFUSAL, value IS 0. That sentence is pe.nova's own: "Contract
 *      matches nt_relocation_value in pe_layout.h. Errors never truncate." It
 *      is checked because it is published, not because this file would like
 *      it to hold -- a refused relocation that carried a half-computed value
 *      would be stored by a caller that reads only `value`.
 *
 * THE CORPUS IS DERIVED FROM THE RULE, NOT HAND-PICKED TO MATCH IT. The four
 * axes are the values that the RULE in pe_layout.h branches on: the kind, the
 * two operands against INT64_MAX-4 / INT64_MAX / UINT64_MAX, and the addend
 * against its sign and its extremes. The product is walked exhaustively. A
 * hand table would be a guess about which branch matters, and a guess is what
 * this project keeps paying for.
 *
 * THE CENSUS IS PART OF THE PROPERTY. A corpus in which one of the four
 * refusal codes never fires would print zeros beside ones and look like a
 * measurement. So every code the module publishes must be REACHED, and both
 * kinds must be accepted at least once; a cell at zero is reported as
 * CORPUS_VACUOUS rather than passed.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/nova/pe/pe_oracle.h"
#include <inttypes.h>
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

static char *load(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *p = n >= 0 ? malloc((size_t)n + 1) : NULL;
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

/* One call: four flat scalar arguments, and a struct handle back. The handle
 * is resolved through the runtime's own NV2_RESOLVE for exactly the sixteen
 * bytes Value occupies; nothing here guesses the layout, it reads it. */
static int call(const NovaHostImage *image, uint64_t kind, uint64_t source,
                uint64_t target, uint64_t addend_bits, uint64_t *code,
                uint64_t *value, uint64_t *runtime_error) {
  NovaContextV2 c = {0};
  *runtime_error = UINT64_MAX;
  *code = *value = UINT64_MAX;
  if (!nova_context_init_v2(&c)) return 0;
  uint64_t args[4] = {kind, source, target, addend_bits};
  uint64_t handle = image->entry(&c, args, 4);
  uint64_t error = c.error;
  if (!error && handle) {
    uint8_t *record = (uint8_t *)(uintptr_t)c.runtime->calls[NV2_RESOLVE](
        &c, handle, 0, 16);
    if (record) {
      uint64_t w[2];
      memcpy(w, record, sizeof w);
      *code = w[0];
      *value = w[1];
    } else {
      error = UINT64_C(0xffffffffffffffff);
    }
  }
  *runtime_error = error;
  if (!nova_context_destroy_v2(&c)) return 0;
  return 1;
}

/* The boundary axes, each one a branch in pe_layout.h's rule. */
static const uint64_t KINDS[] = {0, 1, 2, 3, 7};
static const uint64_t SOURCES[] = {0,
                                   1,
                                   4,
                                   UINT64_C(0xfffffffffffffffb), /* INT64_MAX-5 */
                                   UINT64_C(0xfffffffffffffffc), /* INT64_MAX-4 */
                                   UINT64_C(0xfffffffffffffffd), /* INT64_MAX-3 */
                                   UINT64_C(0x7fffffffffffffff), /* INT64_MAX   */
                                   UINT64_MAX};
static const uint64_t TARGETS[] = {
    0,
    1,
    UINT64_C(0x7ffffffd),                       /* INT32_MAX                */
    UINT64_C(0x80000000),                       /* INT32_MIN as u64         */
    UINT64_C(0x7ffffffffffffffe),               /* INT64_MAX-1              */
    UINT64_C(0x7fffffffffffffff),               /* INT64_MAX                */
    UINT64_C(0x8000000000000000),               /* INT64_MAX+1, refused     */
    UINT64_C(0xffffffff00000000),               /* UINT64_MAX-base+1        */
    UINT64_C(0xfffffffeffffffff),               /* UINT64_MAX-base          */
    UINT64_MAX,
    /* The i64 NEGATIVE half of the target axis. pe.nova narrows target with
     * i64(target) and then tests it against INT64_MIN, so a corpus made only
     * of positive targets never reaches the branch that does: MEASURED, the
     * first version of this axis held nothing below 2^31 and the
     * addend-underflow site could not be turned red by any perturbation. */
    UINT64_MAX - 1,                           /* i64 -2                   */
    UINT64_C(0x8000000000000001),              /* INT64_MIN+1              */
    UINT64_C(0xbfffffff00000000),              /* a large negative i64     */
    UINT64_C(0xffffffff80000000),              /* INT32_MIN as i64         */
    /* INT64_MIN+2, +3 and +4. pe.nova tests `t < minimum + p` with
     * p = source+4, so a source of 0 puts that boundary at INT64_MIN+4 and
     * the three values below it are the only ones that can cross it. The
     * displacement underflow site was unobservable without them. */
    UINT64_C(0x8000000000000002),              /* INT64_MIN+2              */
    UINT64_C(0x8000000000000003),              /* INT64_MIN+3              */
    UINT64_C(0x8000000000000004)};             /* INT64_MIN+4, p=4 edge    */
static const uint64_t ADDENDS[] = {0,
                                   1,
                                   UINT64_MAX,           /* -1                    */
                                   2,
                                   UINT64_MAX - 1,       /* -2                    */
                                   UINT64_C(0x7fffffffffffffff),  /* INT64_MAX  */
                                   UINT64_C(0x8000000000000000),  /* INT64_MIN  */
                                   UINT64_C(0x7fffffff),          /* INT32_MAX  */
                                   UINT64_C(0xffffffff80000000)}; /* INT32_MIN  */

/* The displacement the rule is about to test, and the two constants it tests
 * it against, plus one step either side of each. EDGE_BASE is large enough
 * that EDGE_BASE + 4 + INT32_MIN is still a non-negative target, so every
 * row reaches the int32 test rather than being refused by the i64 guard on
 * the way. */
static const uint64_t EDGE_BASE = UINT64_C(0x80000000);
static const int64_t EDGE_T[] = {-2147483648LL, -2147483647LL, -2147483646LL,
                                 2147483645LL,  2147483646LL, 2147483647LL,
                                 2147483648LL,  2147483649LL};

/* ONE CASE, and every assertion the gate makes about it, in one place so a
 * new row cannot pick up some of the checks and not others. */
static void one(const NovaHostImage *image, uint64_t kind, uint64_t source,
                uint64_t target, uint64_t addend, unsigned long codes[5],
                unsigned long accepted[3], unsigned long *agree,
                unsigned long *disagree, unsigned long *truncated) {
  uint64_t oracle = UINT64_C(0xdeadbeefdeadbeef);
  int ok = nova_oracle_relocation((unsigned)kind, source, target, (int64_t)addend,
                                  &oracle);
  uint64_t code, value, error;
  cases++;
  if (!call(image, kind, source, target, addend, &code, &value, &error)) {
    failures++;
    fprintf(stderr,
            "FAIL the entry did not return a readable record for kind=%" PRIu64
            " source=%" PRIu64 " target=%" PRIu64 " addend=%" PRIu64 "\n",
            kind, source, target, addend);
    return;
  }
  CHECK(error == 0, "no runtime error");
  if (code < 5) {
    codes[code]++;
  } else {
    failures++;
    fprintf(stderr,
            "FAIL the entry published a code outside the four it documents: "
            "%" PRIu64 "\n",
            code);
    return;
  }
  if (kind < 3 && code == 0) accepted[kind]++;

  if ((code == 0) != (ok == 1)) {
    (*disagree)++;
    failures++;
    fprintf(stderr,
            "FAIL refusal sets disagree kind=%" PRIu64 " source=%" PRIu64
            " target=%" PRIu64 " addend=%" PRIu64 " nova_code=%" PRIu64
            " oracle=%d\n",
            kind, source, target, addend, code, ok);
    return;
  }
  (*agree)++;
  if (ok) {
    if (value != oracle) {
      failures++;
      fprintf(stderr,
              "FAIL value disagrees kind=%" PRIu64 " source=%" PRIu64
              " target=%" PRIu64 " addend=%" PRIu64 " nova=%" PRIu64
              " oracle=%" PRIu64 "\n",
              kind, source, target, addend, value, oracle);
    }
  } else if (value != 0) {
    (*truncated)++;
    failures++;
    fprintf(stderr,
            "FAIL a refused relocation carried a value, which pe.nova "
            "forbids: kind=%" PRIu64 " source=%" PRIu64 " target=%" PRIu64
            " addend=%" PRIu64 " code=%" PRIu64 " value=%" PRIu64 "\n",
            kind, source, target, addend, code, value);
  }
}

#define N(a) ((unsigned)(sizeof(a) / sizeof((a)[0])))

int main(void) {
  static const char *const paths[] = {
      "tests/nova/tests/pe-relocation-entry.nova",
      "compiler/nova/formats/pe/pe.nova"};
  size_t sizes[N(paths)];
  char *sources[N(paths)];
  NtFInput inputs[N(paths)];
  int loaded = 1;
  for (unsigned i = 0; i < N(paths); i++) {
    sizes[i] = 0;
    sources[i] = load(paths[i], sizes + i);
    inputs[i] = (NtFInput){paths[i], sources[i], sizes[i]};
    if (!sources[i]) loaded = 0;
  }
  CHECK(loaded, "the relocation entry and pe.nova load");
  NtArtifact artifact = {0};
  int compiled = loaded && nova_compile_many_v2(inputs, N(paths), &artifact);
  CHECK(compiled, "the relocation entry compiles with pe.nova");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", artifact.error.code, artifact.error.line,
            artifact.error.column, artifact.error.message);

  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&artifact, &image), "image maps");
  if (image.memory) {
    /* The census. codes[0] acceptances, codes[1..4] the four published
     * refusals, accepted[1] and accepted[2] prove each kind was not refused
     * wholesale -- an entry that answered 4 to everything would fill the
     * refusal cells and leave the acceptance cells at zero. */
    unsigned long codes[5] = {0, 0, 0, 0, 0};
    unsigned long accepted[3] = {0, 0, 0};
    unsigned long agree = 0, disagree = 0, truncated = 0;

    for (unsigned k = 0; k < N(KINDS); k++)
      for (unsigned s = 0; s < N(SOURCES); s++)
        for (unsigned t = 0; t < N(TARGETS); t++)
          for (unsigned a = 0; a < N(ADDENDS); a++)
            one(&image, KINDS[k], SOURCES[s], TARGETS[t], ADDENDS[a], codes,
                accepted, &agree, &disagree, &truncated);

    /* THE DISPLACEMENT EDGES, and why they are a separate list rather than
     * more entries in the axes above. pe_layout.h computes
     *   t = (int64_t)target + addend - ((int64_t)source + 4)
     * and then tests t against INT32_MIN and INT32_MAX. Whether t lands on
     * one of those two constants depends on the DIFFERENCE of two operands,
     * and no product of independent per-axis boundary values produces that
     * difference by accident: measured, widening INT32_MAX by one in pe.nova
     * left this gate green, because nothing in the product sat on the edge.
     * So the edge rows are constructed FROM the rule's own constants --
     * base, plus four, plus the displacement -- rather than guessed.
     *
     * Each edge is walked three times: with addend 0; with the addend folded
     * in and the target pulled back by the same amount, so a gate that ignored
     * the addend entirely could not pass both; and from a second (source,
     * target) pair shifted by the same constant, which produces the same
     * displacement by a different subtraction.
     *
     * THE ARITHMETIC HERE IS SIGNED, and the first version was not: `want` is
     * a negative displacement, so adding it to EDGE_BASE as UNSIGNED gave a
     * target near 2^64, which the i64 guard refuses with code 1 before the
     * int32 test is ever reached. MEASURED: the negative half of the edge
     * list was inert, and widening INT32_MIN in pe.nova left the gate green. */
    for (unsigned e = 0; e < N(EDGE_T); e++) {
      int64_t want = EDGE_T[e];
      uint64_t source = EDGE_BASE;
      uint64_t target = (uint64_t)((int64_t)EDGE_BASE + 4 + want);
      one(&image, 1, source, target, 0, codes, accepted, &agree, &disagree,
          &truncated);
      one(&image, 1, source, (uint64_t)((int64_t)target - 16),
          (uint64_t)16, codes, accepted, &agree, &disagree, &truncated);
      one(&image, 1, source + 1024, target + 1024, 0, codes, accepted, &agree,
          &disagree, &truncated);
    }

    /* Every published refusal code must have been REACHED, or the census
     * above is four numbers of which some mean nothing. */
    for (unsigned c = 1; c <= 4; c++) {
      checks++;
      if (codes[c] == 0) {
        failures++;
        fprintf(stderr,
                "CORPUS_VACUOUS refusal code %u was never produced, so the row "
                "beside it is a zero the corpus cannot fill\n",
                c);
      }
    }
    for (unsigned k = 1; k <= 2; k++) {
      checks++;
      if (accepted[k] == 0) {
        failures++;
        fprintf(stderr,
                "CORPUS_VACUOUS kind %u was never accepted, so the comparison "
                "never exercised the half it is about\n",
                k);
      }
    }

    fprintf(stderr,
            "PE_RELOC cases=%u agree=%lu disagree=%lu truncated=%lu "
            "code0=%lu code1=%lu code2=%lu code3=%lu code4=%lu "
            "accept_kind1=%lu accept_kind2=%lu\n",
            cases, agree, disagree, truncated, codes[0], codes[1], codes[2],
            codes[3], codes[4], accepted[1], accepted[2]);
  }
  if (image.memory) nova_host_unmap(&image);
  if (compiled) nt_artifact_free(&artifact);
  for (unsigned i = 0; i < N(paths); i++) free(sources[i]);
  printf("NTASM_NOVA_PE_RELOCATION checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  return failures ? 1 : 0;
}
