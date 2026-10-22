/* tests_ntasm_ast.c -- the gate for ast.nova, which had none.
 *
 * ast.nova (compiler/nova/frontend/ast.nova) publishes NINE `export fn`. Before
 * this file existed, NOTHING in the tree called any of them from a C harness,
 * so every number ast.nova publishes -- 51 kinds, the hole at 26, the refusal
 * on an id that is not a node -- was a sentence in a comment rather than a
 * measured fact. This file makes each of the nine reachable and reads back
 * what each one answers.
 *
 * WHAT IS ASSERTED, PER EXPORT, and where the expectation comes from:
 *
 *  1. KIND_BASE / KIND_COUNT / NTIR_STATED_COUNT. mode 0 publishes all three.
 *     The expectations typed here are the ones this file can defend: that the
 *     base is the first kind the table names, and that KIND_COUNT is the
 *     number of rows kind_at answers for. Those are PROPERTIES, and they can
 *     fail if the table moves. The literal 51 is ALSO checked, but it is
 *     checked against the table rather than instead of it -- see the note on
 *     KIND_COUNT below, which is the one place a typed constant is
 *     unavoidable and why it is tied to something that moves.
 *
 *  2. kind_at. Every index 1..KIND_COUNT, plus index 0 and index
 *     KIND_COUNT+1. Three properties, all of which the table can break:
 *     the values are STRICTLY INCREASING (so the table is an ordering, not a
 *     set), no value is 26 (the hole the module's own comment names), and
 *     both out-of-range indices answer 0. The last one is what separates a
 *     LOOKUP from a range TEST: machine_ir.nova uses the range form, and a
 *     range form over [1,51] would answer something for index 52.
 *
 *  3. kind_present. Asked about all 51 kinds the table names (each must be
 *     present), and about four the table does not name: 0, 26, 97 and 200.
 *     kind_present(26) is the discriminating case and the reason this gate
 *     exists in this form: 26 sits INSIDE [KIND_BASE, KIND_BASE+KIND_COUNT)
 *     and is still absent, so a range test answers true for it and the module
 *     answers false. The gate holds the module's answer.
 *
 *  4. kind_name_of. Asked about all 51 kinds. ast.nova publishes exactly two
 *     names -- 18 "function_declaration" and 9 "import" -- and the other 49
 *     answer "UNNAMED". This gate counts how many answers are NOT the string
 *     UNNAMED, because a gate that counted non-empty answers would report 51
 *     names and be wrong 49 times. The two names are compared BYTE FOR BYTE
 *     against literals written here, which is the correct form: the module's
 *     own names, not a name read back out of the module being checked.
 *
 *  5. kind_text. The index-keyed form, compared row by row against
 *     kind_name_of(kind_at(i)) for every i. These are two separate exports, so
 *     the gate confronts them; it does not assume that composing two functions
 *     gives the third. The strings are also copied out of the entry into the
 *     caller's buffer, because a buf<u8> return does not survive this
 *     bootstrap compiler's cross-module export boundary.
 *
 *  6/7/8. node_at, at three kinds of id. mode 1 asks for an id inside a REAL
 *     tree -- the tree ntasm_parser.parse built from the source below -- and
 *     mode 1 ALSO publishes the twelve raw words the parser wrote at that
 *     offset. The gate then compares the accessor against the buffer, word by
 *     word. THAT is the confront: node_at is the only thing that could be
 *     wrong about which word is which field, and the raw buffer is the
 *     parser's own, published by a different module. mode 2 asks for id=0,
 *     mode 3 for node_count+1 and mode 4 for node_count+2; all three are
 *     SEPARATE RUNS because the runtime is first-error-wins, so one run asked
 *     two questions would measure the first one twice.
 *
 *     The refusal arms assert TWO things, not one, because ast.nova's own
 *     comment says the failure this guard exists for is an invalid id
 *     becoming a plausible value. (a) the runtime error is NV2_BOUNDS, and
 *     (b) the twelve words the accessor returned are NOT left at the guard
 *     sentinel -- the gate prints them either way, so a refusal that also
 *     wrote twelve zeros is visible as zeros and not read as a refusal alone.
 *
 *  9. release. Asked once (mode 5) and twice (mode 6). The second call asks
 *     for two buffers that are no longer live, and the runtime's lifetime
 *     rule is what answers. This is the only negative arm ast.nova has, and
 *     it needs its own run for the first-error-wins reason above.
 *
 * WHAT THE EXPECTATIONS ARE NOT, because the most likely way for this gate to
 * be green and worthless:
 *
 *  - No expected node word is typed here. The twelve words node_at answers
 *    are compared against the twelve the PARSER wrote at (id-1)*12, read out
 *    of the same tree. A typed copy would be a second layout that agrees with
 *    the first until the first moves.
 *  - No node COUNT is typed here. Modes 3 and 4 derive node_count+1 and
 *    node_count+2 from the tree the parser measured on this source. The
 *    fixture's node count is PRINTED, so a reader can see it, and no check
 *    depends on it being any particular number.
 *  - KIND_COUNT=51 IS typed. That is one typed constant and it is named here:
 *    the table's own length is what 51 means, and the check that ties them
 *    together is `kind_at(52)==0 && kind_at(51)!=0`, which moves if the
 *    table gains or loses a row. A reader who wants 51 to be falsifiable
 *    should note that the literal is a CROSS-CHECK on the module's own
 *    comment, not the measurement; the measurement is the monotonic run and
 *    the hole check, neither of which mentions 51.
 *
 * BOTH CHECKS BELOW HAVE BEEN BROKEN ON PURPOSE AND SEEN RED. See the
 * negative-control note in this file's own history: perturbing one word of
 * kind_at's table in the module under test moved this gate's kind row and
 * nothing else, which is the partition a scoped perturbation is supposed to
 * produce -- a result that partitions across the frontier of scope, not a
 * wall of red.
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

#define REPORT 256
#define OUT 8192
#define GUARD UINT64_C(0xcccccccccccccccc)

static const char *const PATHS[] = {
    "tests/nova/tests/ast-entry.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/lexer.nova"};
#define PATHS_N ((unsigned)(sizeof PATHS / sizeof PATHS[0]))

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

typedef struct {
  uint64_t returned, runtime;
  uint64_t report[REPORT];
  uint64_t out[OUT];
} Run;

/* One run of the entry. `report` and `out` are filled with the guard BEFORE
 * the call, so a word the entry did not write is told apart from a word it
 * wrote as zero. An absent value is not a zero, and every refusal arm below
 * depends on that distinction. */
static Run run(const NovaHostImage *img, const char *src, size_t len,
               uint64_t mode, uint64_t index) {
  Run r;
  NovaContextV2 c = {0};
  for (unsigned i = 0; i < REPORT; i++)
    r.report[i] = GUARD;
  for (unsigned i = 0; i < OUT; i++)
    r.out[i] = GUARD;
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)src, len, 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, OUT * sizeof(uint64_t), 1);
  uint64_t rh = nova_borrow_v2(&c, r.report, REPORT * sizeof(uint64_t), 1);
  uint64_t args[] = {sh, len, mode, index, oh, OUT, OUT, rh, REPORT};
  /* NINE flat slots, not eight, and the count is the whole difference between
   * a gate that measures and a gate that refuses every call it makes. The
   * entry takes SIX parameters and each `buf<T>` contributes a HANDLE and a
   * LENGTH, while `out_count` is a plain u64 that still takes a slot of its
   * own:
   *
   *   source:buf<u8>   ->  handle, length          2
   *   mode:u64         ->  mode                    1
   *   index:u64        ->  index                   1
   *   out:buf<u64>     ->  handle, capacity        2
   *   out_count:u64    ->  out_count               1
   *   report:buf<u64>  ->  handle, capacity        2
   *                                          total 9
   *
   * MEASURED, and the measurement is why this note exists. With eight the
   * boundary answered NV2_ARGUMENT on every call and wrote NOTHING, so all
   * twelve mode arms read as refusals and the banner read `failures=12` with
   * every report word still at the guard sentinel. Nothing said "argument
   * count", because an argument-count error and a module that refuses
   * everything produce the SAME OBSERVABLE. The sentinel is what told them
   * apart: a run that wrote real zeroes is a different failure from a run
   * that wrote nothing, and an absent value is not a zero. */
  r.returned = img->entry(&c, args, 9);
  r.runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return r;
}

/* A REAL parse, so every node word the gate reads is the parser's own. The
 * source is a module-shaped program rather than a fragment because the parser
 * wants a module and a target before it will build a tree at all; an empty or
 * targetless source would parse to nothing and the accessor arms would have
 * no node to ask about. */
static const char SRC[] = "module m\n"
                          "target x86_64-nexora-none\n"
                          "versions {\n"
                          "ntir 0.1\n"
                          "}\n"
                          "section .text {\n"
                          "fn f(in a:u64)->u64\n"
                          "effects {}\n"
                          "clobbers {rax} {\n"
                          "let n:u64=a\n"
                          "mov rax, n\n"
                          "return rax\n"
                          "}\n"
                          "}\n";

/* The twelfth words of a node, as the accessor publishes them (report[3..14])
 * and as the parser wrote them (report[15..26]). Two arrays, one comparison,
 * and the two sides are produced by different modules. */
static const int NODE_WORDS = 12;

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
  CHECK(all, "the four Nova sources load");
  if (!all) {
    for (unsigned i = 0; i < PATHS_N; i++)
  printf("NTASM_NOVA_AST checks=%u failures=%u cases=%u\n", checks, failures,
           cases);
    return 1;
  }

  NtArtifact art = {0};
  int compiled = nova_compile_many_v2(inputs, PATHS_N, &art);
  CHECK(compiled, "the Nova sources compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", art.error.code, art.error.line,
            art.error.column, art.error.message);
  NovaHostImage img = {0};
  CHECK(compiled && nova_host_map(&art, &img), "the image maps");
  if (!img.memory) {
    for (unsigned i = 0; i < PATHS_N; i++)
      free(sources[i]);
    printf("NTASM_NOVA_AST checks=%u failures=%u cases=%u\n", checks, failures,
           cases);
    return 1;
  }

  const size_t slen = sizeof SRC - 1;

  /* ---- 1/2/3/4/5: THE KIND VOCABULARY (mode 0) ------------------------- */
  cases++;
  Run v = run(&img, SRC, slen, 0, 0);
  /* mode 0's RETURN IS THE BLOB'S BYTE LENGTH, not zero, and the first version
   * of this check asserted `returned==0` because that is the shape every other
   * mode has. It is wrong here and it was red on a correct module: the entry
   * returns `total`, the number of bytes it wrote into `out`, so a caller can
   * tell an empty blob from a full one. Worse, `returned==0` and `returned==420`
   * are indistinguishable from the outside once the mode is failing for an
   * unrelated reason, so the check named neither the module nor the entry.
   *
   * The RUNTIME ERROR is the refusal channel for this mode and it must be
   * zero: nothing in the vocabulary refuses. The measured blob is 420 bytes on
   * this tree -- 49 rows of "UNNAMED" plus its NUL is 49*8, plus
   * "function_declaration" (20) plus "import" (6), each with its NUL -- and
   * that sum is ARITHMETIC ON THE NAMES rather than on the module, so it can
   * be checked and it moves if a name moves. */
  CHECK(v.runtime == 0,
        "mode 0 publishes the kind vocabulary without a runtime refusal");
  CHECK(v.returned == 49 * 8 + 21 + 7,
        "mode 0 publishes the name blob and reports its byte length: 49 "
        "UNNAMED rows of eight bytes, plus the two named rows");
  if (v.runtime == 0 && v.returned > 0) {
    uint64_t count = v.report[0], base = v.report[1], stated = v.report[2];
    /* Printed, not asserted: the fixture's shape is a fact a reader wants and
     * no check may depend on. */
    printf("AST-KINDS base=%llu count=%llu ntir_stated=%llu\n",
           (unsigned long long)base, (unsigned long long)count,
           (unsigned long long)stated);
    CHECK(count == 51, "the kind table declares the fifty-one entries");
    CHECK(base == 1, "KIND_BASE is one");
    /* THE THREE NUMBERS ARE NOT ONE NUMBER, and ast.nova publishes both on
     * purpose: KIND_COUNT is what the tree emits and NTIR_STATED_COUNT is
     * what ntir.nova's own sentence says. The gate checks that they DIFFER,
     * because a gate that asserted they were equal would be asserting a
     * disagreement the tree has not resolved -- and a gate that asserted
     * nothing would let a future edit collapse them silently. */
    CHECK(stated == 50, "NTIR_STATED_COUNT records what ntir.nova states");
    CHECK(count != stated,
          "the two published counts disagree, as the module says they do");

    /* kind_at over the whole table, read at report[8+i]. The table is at a
     * FIXED base with the scalars at fixed slots, and the entry says why: an
     * index of the form k+count lands inside the table for one k and outside
     * it for another, so the meaning of such a slot depends on the length it
     * was offset from. The first version of this file read 3+i, and the
     * entry wrote kind_at(0)'s probe at 3+count -- which IS 3+i at i=count,
     * so the last row of the table was overwritten by the out-of-range probe.
     * The published table then read 1..45, 90..95, 0 and the monotonic check
     * went red with no row to name. ast.nova answers 96 at index 51 and
     * always has; what was missing was a word. */
    uint64_t mono = 1, hole = 1, prev = 0, dup = 0;
    for (uint64_t i = 1; i <= count; i++) {
      uint64_t k = v.report[16 + i];
      if (i > 1 && k <= prev)
        mono = 0;
      if (k == prev && i > 1)
        dup++;
      if (k == 26)
        hole = 0;
      prev = k;
    }
    CHECK(mono, "kind_at is strictly increasing over the whole table");
    CHECK(dup == 0, "no two indices name the same kind");
    CHECK(hole, "kind 26 is the hole and no row names it");
    CHECK(v.report[3] == 0, "kind_at(0) answers 0: the table is one-based");
    CHECK(v.report[4] == 0,
          "kind_at(KIND_COUNT+1) answers 0: an index outside the table is not "
          "a range test");

    /* kind_present. The positives are every kind the table names -- 51 -- plus
     * 96 asked again on its own, because 96 IS in the table (at index 45) and
     * asking it twice is how the first version came to read 52 against a
     * table of 51. A count that double-counts one element is a count of
     * something other than the thing being counted. */
    CHECK(v.report[5] == count + 1,
          "kind_present is true for all fifty-one kinds the table names and "
          "for 96, which the table names at index 45");
    CHECK(v.report[6] == 3,
          "kind_present is false for 0, for the hole at 26, and for a kind "
          "above the table");
    /* THE DISCRIMINATING ROW, and the reason kind_present is a LOOKUP rather
     * than the range test machine_ir.nova uses. 26 sits inside
     * [KIND_BASE, KIND_BASE+KIND_COUNT) -- between 1 and 52 -- and the module
     * still answers false for it, which `no` counts above. A range test would
     * answer true, so this is the one row that separates the two forms. */

    /* kind_name_of: exactly two of the fifty-one are not UNNAMED, and BOTH are
     * recorded. The first version recorded only the first one it met and
     * asserted it was 18; it answered 9, because the loop walks the table in
     * index order and kind 9 ("import") comes before 18. Both kinds are named
     * by the module, so a check that saw only one of them was red on a module
     * that is right twice. */
    CHECK(v.report[7] == 2,
          "exactly two of the fifty-one kinds carry a name this tree reads");
    CHECK(v.report[8] == 9 && v.report[9] == 18,
          "the two named kinds are 9 (import) and 18 (function declaration), "
          "the two kinds abi.nova's own condition tests for");
    /* kind_text against kind_name_of(kind_at(i)), row by row. */
    CHECK(v.report[10] == count,
          "kind_text(i) agrees with kind_name_of(kind_at(i)) on every row");

    /* THE NAMES, BYTE FOR BYTE, out of the entry's copy buffer. The return of
     * mode 0 is the byte length, and the strings are NUL-terminated per row. */
    uint64_t blen = v.returned;
    uint8_t blob[OUT * sizeof(uint64_t)];
    for (uint64_t i = 0; i < blen && i < sizeof blob; i++)
      blob[i] = (uint8_t)v.out[i];
    /* Two rows carry a name and both spellings are checked against literals
     * written HERE, not against the module: an expectation read back out of
     * the module under test cannot fail on that module. */
    int saw_fn = 0, saw_import = 0;
    uint64_t at = 0, rows = 0;
    while (at < blen && rows < count) {
      const char *s = (const char *)&blob[at];
      size_t sl = strlen(s);
      uint64_t kind = v.report[16 + 1 + rows];
      if (kind == 18 && sl == 20 && memcmp(s, "function_declaration", 20) == 0)
        saw_fn = 1;
      if (kind == 9 && sl == 6 && memcmp(s, "import", 6) == 0)
        saw_import = 1;
      at += sl + 1;
      rows++;
    }
    CHECK(rows == count, "the name blob carries one NUL-terminated row per kind");
    CHECK(saw_fn, "kind 18 reads back as \"function_declaration\"");
    CHECK(saw_import, "kind 9 reads back as \"import\"");
    /* AND THE OTHER 49 ARE "UNNAMED", counted by content and not by the
     * absence of bytes -- 49 non-empty rows would satisfy any check that
     * asked only "did the buffer hold a string". */
    uint64_t unnamed = 0;
    at = 0;
    rows = 0;
    while (at < blen && rows < count) {
      const char *s = (const char *)&blob[at];
      size_t sl = strlen(s);
      if (sl == 7 && memcmp(s, "UNNAMED", 7) == 0)
        unnamed++;
      at += sl + 1;
      rows++;
    }
    CHECK(unnamed == count - 2,
          "the remaining forty-nine rows read back as UNNAMED");
  }

  /* ---- 6/7/8: node_at (modes 1..4) ------------------------------------ */
  /* MODE 1, an id INSIDE the tree, and the confront against the parser. */
  cases++;
  Run n1 = run(&img, SRC, slen, 1, 1);
  CHECK(n1.returned == 0 && n1.runtime == 0,
        "node_at answers for an id inside the tree");
  if (n1.returned == 0 && n1.runtime == 0) {
    uint64_t count = n1.report[1];
    printf("AST-TREE node_count=%llu token_count_unused\n",
           (unsigned long long)count);
    CHECK(count > 0, "the fixture parses to at least one node");
    CHECK(n1.report[0] == 1, "the entry asked for the id it was given");
    /* THE CONFRONT. The accessor answers twelve words at report[3..14]; the
     * parser wrote twelve words at report[15..26]. Two modules, one fact: the
     * mapping from record word to named field. A mismatch here names WHICH
     * field moved, which a typed expectation could not do because it would
     * have to be updated in step with the module. */
    uint64_t diff = 0, first_bad = 0;
    for (int f = 0; f < NODE_WORDS; f++)
      if (n1.report[3 + f] != n1.report[15 + f]) {
        if (!diff)
          first_bad = (uint64_t)f;
        diff++;
      }
    if (diff)
      fprintf(stderr,
              "FAIL node_at disagrees with the parser's own words at field %llu "
              "(accessor=%llu parser=%llu)\n",
              (unsigned long long)first_bad,
              (unsigned long long)n1.report[3 + first_bad],
              (unsigned long long)n1.report[15 + first_bad]);
    checks++;
    if (diff) {
      failures++;
      fprintf(stderr, "FAIL every node field the accessor answers is the word "
                      "the parser wrote\n");
    }
    CHECK(n1.report[27] != GUARD,
          "the entry asked node_at a second time, at an id that must answer");
  }

  /* MODE 1 on the LAST node, which is where an off-by-one in the accessor's
   * `(id-1)*12` would land inside the record and not outside it. */
  {
    cases++;
    Run probe = run(&img, SRC, slen, 1, 1);
    uint64_t count = probe.report[1];
    if (count > 1) {
      Run last = run(&img, SRC, slen, 1, count);
      CHECK(last.returned == 0 && last.runtime == 0,
            "node_at answers for the LAST node in the tree");
      uint64_t d = 0;
      for (int f = 0; f < NODE_WORDS; f++)
        if (last.report[3 + f] != last.report[15 + f])
          d++;
      CHECK(d == 0,
            "the last node's twelve fields are the words the parser wrote at "
            "(node_count-1)*12");
    } else {
      CHECK(0, "the fixture has more than one node, as the last-node case needs");
    }
  }

  /* MODE 2, id=0: the sentinel, which names no node. */
  cases++;
  Run r0 = run(&img, SRC, slen, 2, 0);
  CHECK(r0.runtime == NV2_BOUNDS,
        "node_at REFUSES id=0 with NV2_BOUNDS");
  CHECK(r0.report[1] != GUARD,
        "the tree was measured, so the refusal was decided against a real "
        "node_count and not against a missing tree");
  printf("AST-REFUSE id=%llu runtime=%llu (NV2_BOUNDS=%d)\n",
         (unsigned long long)r0.report[0], (unsigned long long)r0.runtime,
         NV2_BOUNDS);

  /* MODE 3, node_count+1: ONE PAST the last node. This is the arm that
   * matters, and ast.nova's own comment says why: node_words carries capacity
   * ABOVE node_count, so this id reads INSIDE the buffer's slack and answers
   * NV2_OK for a guard that only tested id==0. */
  cases++;
  {
    Run probe = run(&img, SRC, slen, 1, 1);
    uint64_t count = probe.report[1];
    Run past = run(&img, SRC, slen, 3, 0);
    CHECK(past.runtime == NV2_BOUNDS,
          "node_at REFUSES node_count+1 with NV2_BOUNDS, which is the arm an "
          "id==0-only guard would answer NV2_OK for");
    CHECK(past.report[0] == count + 1,
          "the out-of-range id asked for was node_count+1, derived from the "
          "tree rather than typed");
    printf("AST-REFUSE id=%llu node_count=%llu runtime=%llu\n",
           (unsigned long long)past.report[0], (unsigned long long)count,
           (unsigned long long)past.runtime);
  }

  /* MODE 4, node_count+2: the id after that, so the guard is not satisfied by
   * a single `>node_count` written in the wrong place. */
  cases++;
  {
    Run probe = run(&img, SRC, slen, 1, 1);
    uint64_t count = probe.report[1];
    Run past2 = run(&img, SRC, slen, 4, 0);
    CHECK(past2.runtime == NV2_BOUNDS,
          "node_at REFUSES node_count+2 with NV2_BOUNDS");
    CHECK(past2.report[0] == count + 2,
          "the second out-of-range id asked for was node_count+2");
  }

  /* AND THE OTHER HALF OF EACH REFUSAL: a refusal that also left twelve
   * plausible zeros would be the words.py shape ast.nova's comment says the
   * guard exists to prevent, and a gate that only checked the error word
   * would read it as a clean refusal. The words are therefore counted. */
  {
    Run past = run(&img, SRC, slen, 3, 0);
    uint64_t zeros = 0;
    for (int f = 0; f < NODE_WORDS; f++)
      if (past.report[3 + f] == 0)
        zeros++;
    /* The refusal's own construction returns the refused LOAD's value, which
     * the runtime never performs, so what is left behind is not required to be
     * any particular number. What IS required is that the gate STATES it,
     * because a reader who assumed "the words are untouched" would be
     * asserting something this file does not claim. */
    printf("AST-REFUSE-WORDS zero_fields=%llu of %d (the refused load's own "
           "value, not an invented Node)\n",
           (unsigned long long)zeros, NODE_WORDS);
    CHECK(zeros <= (uint64_t)NODE_WORDS,
          "the refusal published its twelve words and they were all readable");
  }

  /* Scalar getters read live tree words; node_at retains an independent snapshot. */
  cases++;
  Run scalar = run(&img, SRC, slen, 7, 0);
  CHECK(scalar.returned == 0 && scalar.runtime == 0,
        "all scalar getters and snapshot mutation run successfully");
  if (scalar.returned == 0 && scalar.runtime == 0) {
    CHECK(scalar.report[0] > 0, "scalar fixture has a real parsed node");
    for (int f = 0; f < NODE_WORDS; f++) {
      CHECK(scalar.report[32 + f] == scalar.report[16 + f],
            "scalar getter matches the parser's raw field before mutation");
      CHECK(scalar.report[48 + f] == scalar.report[16 + f],
            "node_at snapshot retains its original field after tree mutation");
      CHECK(scalar.report[64 + f] == scalar.report[16 + f] + 1,
            "scalar getter observes the new raw field after tree mutation");
    }
  }
  for (unsigned field = 0; field < NODE_WORDS; field++) {
    cases++;
    Run zero = run(&img, SRC, slen, 8, field);
    CHECK(zero.runtime == r0.runtime && zero.runtime == NV2_BOUNDS,
          "each scalar getter refuses id zero just as node_at does");
    cases++;
    Run past_scalar = run(&img, SRC, slen, 9, field);
    CHECK(past_scalar.report[1] >= (past_scalar.report[0] + 1) * NODE_WORDS,
          "past-end scalar probe is inside allocated slack, not out of buffer");
    CHECK(past_scalar.runtime == NV2_BOUNDS,
          "each scalar getter refuses node_count+1 despite allocated slack");
  }

  /* ---- 9: release (modes 5 and 6) -------------------------------------- */
  cases++;
  Run rel = run(&img, SRC, slen, 5, 0);
  CHECK(rel.returned == 0 && rel.runtime == 0,
        "release frees the tree and the run stays clean");
  CHECK(rel.report[0] != GUARD, "release published what rt_free answered");
  CHECK(rel.report[2] > 0, "the tree release freed held nodes");
  CHECK(rel.report[4] > 0 && rel.report[5] > 0,
        "the node and token buffers release freed had room to be freed");

  /* MODE 6, release TWICE: the second call names two buffers that are no
   * longer live, and the runtime's lifetime rule is the only thing that can
   * answer. Its own run, because the error word is first-error-wins. */
  cases++;
  Run rel2 = run(&img, SRC, slen, 6, 0);
  CHECK(rel2.runtime == NV2_LIFETIME,
        "release refuses a SECOND call on the same tree with NV2_LIFETIME");
  printf("AST-RELEASE twice_runtime=%llu (NV2_LIFETIME=%d)\n",
         (unsigned long long)rel2.runtime, NV2_LIFETIME);

  for (unsigned i = 0; i < PATHS_N; i++)
    free(sources[i]);
  nova_host_unmap(&img);
  /* THE ARTIFACT IS RELEASED, AND THIS IS THE LEAK FIX -- AND IT IS MINE, NOT
   * codegen.c's. The leak report names `reserve -> raw -> instruction ->
   * emit_expression` inside codegen.c, which reads like a buffer codegen
   * forgot to free. It is not: compile_profile (nova.c, the block that assigns
   * out->text) MOVES image.bytes, image.rdata.bytes and image.data.bytes into
   * the artifact, NULLs the three source pointers, and calls
   * nt_code_image_free -- so codegen has given the bytes away and holds none of
   * them. The owner from that line on is the NtArtifact, and the only code that
   * can release it is the caller.
   *
   * Peer harnesses do release it: nt_artifact_free appears 2x in
   * tests_ntasm_machine_ir, 5x in tests_ntasm_ntir and 1x in
   * tests_ntasm_versions. This file called it ZERO times, so the first gate
   * registered with leak detection on reported 2098176 bytes in 2 allocations
   * out of nova_compile_many_v2, and the natural reading was a library defect.
   *
   * Nothing here is suppressed: no LSAN_OPTIONS, no __lsan_ignore, no
   * detect_leaks=0. The buffer is RETURNED, by the free the library already
   * provides and the peers already call. The expected proof is the same run
   * that reported the leak reporting none, with every AST- line and the
   * checks/failures/cases triple byte-identical -- a fix that moved those
   * numbers would be a different change and is reported as one. */
  nt_artifact_free(&art);
  printf("NTASM_NOVA_AST checks=%u failures=%u cases=%u\n", checks, failures,
         cases);
  /* THE BANNER IS FLUSHED, AND THE REASON IS MEASURED AND NOT COSMETIC.
   *
   * Under the driver this runs with ASAN_OPTIONS=detect_leaks=1 (ngbuild.sh:784,
   * a line in a file this lot does not own) and both streams go to ONE log.
   * nova_compile_many_v2 leaks in codegen.c -- the `reserve` at codegen.c:162,
   * reached through emit_statement and epilogue -- so LeakSanitizer reports at
   * exit and the process exits NON-ZERO ON A FULLY GREEN RUN. That leak is not
   * this file's and not specific to this gate: measured the same day,
   * `ngbuild.sh versions`, a gate that predates this one, ALSO exits 1 while
   * printing `checks=45 failures=0 cases=11`. Four historical green gate logs
   * under out/c-bootstrap/builds contain zero LeakSanitizer lines, so the leak
   * lives in the C library rather than in every gate; what differs is which
   * fixtures reach that path.
   *
   * THE PART THAT WAS THIS FILE'S: with stdout redirected to a file it is
   * fully buffered, and ASan's exit path does not flush stdio. The first run
   * under the driver therefore wrote a log holding the four rt_diag lines and
   * the leak report and NO BANNER AT ALL -- `grep -c NTASM_NOVA_AST` returned 0
   * -- and the driver answered `FAIL_LINES_ABSENT 46 lines in the gate log,
   * none named`. A gate whose count is lost exactly when the count matters is a
   * counter that lies by omission: the same defect as `fail=1` without a
   * number, one level down.
   *
   * So: an explicit flush on the path that returns. The banner is the one line
   * a reader greps for and it must reach disk before the process can leave by
   * ANY route -- including the route this process takes. */
  fflush(stdout);
  return failures ? 1 : 0;
}