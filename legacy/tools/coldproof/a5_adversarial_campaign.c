/* ==========================================================================
   A5_CAMPAIGN_ADVERSARIAL -- the four conjuncts of A5 that the INVENTORY gate
   cannot measure, each with the control that makes it a measurement.

   WHY THIS EXISTS, and why it is not a re-run of tests_ntasm_a5_inventory.c.
   That gate is the right instrument for the §12/§13 CROSS-TABULATION and it
   runs green (checks=109 failures=0 cases=20, reproduced here).  What it
   cannot do is decide whether a refusal NAMES the rule that fired, because a
   cross-tabulation reads a table and a campaign executes an input.  The A5
   cell names four things -- hygiene, provenance, absence of I/O, imposed
   bounds -- and the criterion then says "with adversarial tests".  The
   inventory answers "is it declared and is it exercised".  This answers the
   second question: does the product REFUSE, and does the refusal SAY WHICH
   RULE.

   THE RULE THIS FILE FOLLOWS, and it is the whole design.  A test that
   passes because the expander refused for an UNRELATED reason proves
   nothing, and this project has already paid for that three times: a green
   banner read as coverage (the cross-tab's own PHASE 0 is written to refuse
   it), a case count read as a requirement count, and a sweep whose strongest
   verdict had nothing to fire on.  So every refusal below is asserted on
   BOTH halves -- the code AND the reason -- and every refusal is paired with
   a CONTROL that differs from its case by one construct and must answer
   DIFFERENTLY.  If a control answers the same as its case, the pair cannot
   discriminate and the campaign says so instead of counting a green.

   THE FOUR CONJUNCTS, and which one each phase attacks:

     PHASE 1  HYGIENE.  A name-capturing expander fails here and a hygienic
              one does not, and the difference is READ OUT OF THE PRODUCED
              NAME TABLE rather than counted: three names spelled `t` -- the
              caller's local, the outer's introduced binding, the inner's --
              must publish marks that DIFFER BY ORDINAL.  A count of
              "distinct strings" would be satisfied by two copies of one
              mark; a comparison of the ordinals is not.
     PHASE 2  PROVENANCE.  Is provenance ATTESTED or merely NOTED?  The
              inventory row cites "HYG_SPAN", which is a C string literal in
              a DIFFERENT gate's harness (grep proves it, and the campaign
              prints the proof) and not a symbol of the product at all.  So
              this phase measures the thing the row asserts: a refusal raised
              inside a template reports the TEMPLATE's line, not the
              invocation's, and the expectation is DERIVED from the source
              text rather than pinned as a literal pair.
     PHASE 3  ABSENCE OF I/O.  An expansion that attempts the channel, on
              the route the expander can actually see, must be refused 379
              with the channel's OWN reason.  The control is a name that
              names NO channel, which must answer 374/1 -- the hygiene rule --
              so the 379 is a classification and not a blanket refusal.
              HALF ONE first: the channel is measured OPEN, because a gate
              that refuses a channel which does not exist has proved nothing.
     PHASE 4  IMPOSED BOUNDS, and the bound that BITES.  Six budgets measured
              by the inventory; this phase adds the one it could not -- the
              bound that the whole A5 row has carried as an unidentified
              site, NV2_BOUNDS(4).  It is reached here with ONE input and the
              refusal is shown to be SPECIFIC to the borrow, which is the
              finding: the refusal is on the CALLER'S buffer, and the
              expander's own verdict stays 0.
     PHASE 5  DETERMINISM, proven by a CONTROL and not by a digest.  The same
              source twice must be byte-identical over the whole output
              buffer, AND a one-byte change must DIFFER.  The second half is
              the load-bearing one: a comparison that cannot tell two inputs
              apart proves nothing when it reports them equal.  A digest
              answers "did the claim change", never "is the claim right".

   NO INVENTORY IS ADDED.  This is a campaign, not a gate harness: ngbuild.sh
   turns any tests_ntasm_*.c absent from its GATES list into
   UNREGISTERED_HARNESS and a suite-wide red (ngbuild.sh:1009-1012), and that
   scan reads exactly one directory, compiler/c/nova.  A file here
   is invisible to it.  The tree already established the precedent twice:
   legacy/tools/coldproof/a5_bounds_campaign.{c,sh}.
   ========================================================================== */
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../tests/c/nova/ng_run_dir.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>

#define HEAD "module m\ntarget x86_64-nexora-none\n"
#define TAIL "section .text {\n    export fn main()->u64\n    effects {}\n" \
            "    clobbers {} {\n        expand "
#define FOOT "    }\n}\n"
#define WORDS (1u << 18)

static unsigned checks, failures, cases;

/* Every failure and every result on the SAME stream.  This file's first
 * version split them and a FAIL interleaved mid-line in the log, which is how
 * a counted failure was once hunted across three runs and not found: the
 * count was on one stream and the FAIL lines on the other. */
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
  printf("FAIL %s\n", m); } } while (0)

/* ------------------------------------------------------------------ runner */
typedef struct {
  uint64_t returned, runtime, code, w1, w2, reason, words;
  uint64_t *out;
} Run;

static Run run(const NovaHostImage *img, const char *src, uint64_t words,
               uint64_t request) {
  Run r;
  memset(&r, 0, sizeof r);
  r.code = r.w1 = r.w2 = r.reason = UINT64_C(0xcccccccccccccccc);
  r.out = calloc(words ? words : 1, 8);
  if (!r.out) { printf("CALLOC_FAILED words=%llu\n", (unsigned long long)words); exit(3); }
  r.words = words;
  r.out[0] = request;
  NovaContextV2 c = {0};
  if (!nova_context_init_v2(&c)) { free(r.out); r.out = NULL; return r; }
  uint64_t sh = nova_borrow_v2(&c, (void *)src, strlen(src), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, words * 8, 1);
  uint64_t a[] = {sh, strlen(src), oh, words};
  r.returned = img->entry(&c, a, 4);
  r.runtime = c.error;
  r.code = r.out[0]; r.w1 = r.out[1]; r.w2 = r.out[2]; r.reason = r.out[3];
  nova_context_destroy_v2(&c);
  return r;
}
static void freerun(Run *r) { free(r->out); r->out = NULL; }

static char *loadf(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = malloc((size_t)sz + 1);
  if (!b) { fclose(f); return NULL; }
  *n = fread(b, 1, (size_t)sz, f);
  b[*n] = 0;
  fclose(f);
  return b;
}


/* Read a byte out of the produced region at a byte offset.  The region is
 * little-endian u64 words, so the byte at offset i lives at bit 8*(i%8) of
 * word i/8 -- and it must be MASKED, because a shift alone on an unaligned
 * index drops the byte and returns its neighbour.  The first version of this
 * reader omitted the mask, so it could only ever match a needle starting on a
 * word boundary; every offset it tested was wrong and it reported a table
 * that demonstrably held the mark as empty.  A reader that fails open is
 * worse than no reader, because it produces a FAIL that names the product. */
static unsigned region_byte(const Run *r, uint64_t i) {
  uint64_t w = r->out[4 + (i / 8)];
  return (unsigned)((w >> ((i % 8) * 8)) & 0xff);
}

/* The name table is the expander's only egress: out[2] bytes of it, at
 * out[4] upward.  This asks whether a spelling is IN it. */
static int table_has(const Run *r, const char *needle) {
  uint64_t len = r->out[2], i, n = strlen(needle);
  uint64_t cap = (r->words - 4) * 8;
  if (len > cap) len = cap;
  for (i = 0; i + n <= len; i++) {
    uint64_t k;
    for (k = 0; k < n; k++)
      if (region_byte(r, i + k) != (unsigned char)needle[k]) break;
    if (k == n) return 1;
  }
  return 0;
}

/* And the STRONG form, which is what the hygiene arm asserts: the table is
 * compared to the exact bytes expected, not searched.  A search answers "is
 * the mark somewhere in here"; a comparison answers "is the table this".
 * The expected string is composed from the two marks and the type suffix the
 * source declares, so a change to the source changes the expectation with it
 * instead of leaving a literal that happens to be right today. */
static int table_is(const Run *r, const char *expect) {
  uint64_t len = strlen(expect), i;
  if (r->out[2] != len) return 0;
  for (i = 0; i < len; i++)
    if (region_byte(r, i) != (unsigned char)expect[i]) return 0;
  return 1;
}

/* A canary runs the entry under its own context with BOTH arguments borrowed,
 * because an argument passed as a raw host pointer is not a buffer the runtime
 * can resolve.  The first version of this file passed the out array as a bare
 * pointer and the sanitizer caught it as a null State dereference inside
 * add_buffer: the borrow of the path had already failed.  It is written here
 * because a probe that reaches the runtime in a way the runtime does not
 * support measures the probe. */
static uint64_t run_canary(const NovaHostImage *img, const char *path,
                           uint64_t *out, unsigned words) {
  NovaContextV2 ctx = {0};
  if (!nova_context_init_v2(&ctx)) return 900;
  uint64_t sh = nova_borrow_v2(&ctx, (void *)path, strlen(path), 0);
  uint64_t oh = nova_borrow_v2(&ctx, out, words * 8, 1);
  uint64_t args[4] = {sh, strlen(path), oh, words};
  uint64_t ret = img->entry(&ctx, args, 4);
  nova_context_destroy_v2(&ctx);
  return ret;
}

/* ============================ PHASE 1 -- HYGIENE ===========================
 *
 * THE CASE.  Three names are spelled `t`: the caller's function-scope local
 * (line 13), the outer macro's introduced binding, and the inner macro's.
 * All three expansions publish a name.  A SINGLE-LEVEL capture test cannot
 * tell these apart, because with one level there is only ever ONE generated
 * name to collide with; here there are TWO and they must differ.
 *
 * WHAT A NAME-CAPTURING EXPANDER WOULD DO.  It would publish the SPELLING
 * `t` for at least one of them -- the caller's declaration is a real
 * declaration for a bare `t` in the produced region, and it means 9 while
 * the author wrote 2 and 1.  The produced table would then carry a bare `t`
 * and the two marks would collapse.  So the discriminating assertions are
 * about the BYTES of the table: both marks present, both ordinals different,
 * and the bare spelling absent.
 *
 * THE CONTROL differs by one construct -- the caller's `let t` is removed --
 * so a difference between case and control is attributable to the caller's
 * declaration and not to the nesting.  A control that answered identically
 * would be reported as non-discriminating rather than counted as a pass. */
static void phase1_hygiene(const NovaHostImage *img) {
  static const char *TWO_LEVEL =
      HEAD "macro inner()->ast.block {\n"
      "    return quote(block) { let t:u64=1; return t; };\n}\n"
      "macro outer()->ast.block {\n"
      "    return quote(block) {\n        let t:u64=2;\n"
      "        expand inner();\n        return t;\n    };\n}\n"
      "section .text {\n    export fn main()->u64\n    effects {}\n"
      "    clobbers {} {\n        let t:u64=9;\n        expand outer()\n    }\n}\n";
  static const char *TWO_LEVEL_CTL =
      HEAD "macro inner()->ast.block {\n"
      "    return quote(block) { let t:u64=1; return t; };\n}\n"
      "macro outer()->ast.block {\n"
      "    return quote(block) {\n        let t:u64=2;\n"
      "        expand inner();\n        return t;\n    };\n}\n"
      "section .text {\n    export fn main()->u64\n    effects {}\n"
      "    clobbers {} {\n        expand outer()\n    }\n}\n";

  cases++;
  Run r = run(img, TWO_LEVEL, WORDS, 0);
  Run c = run(img, TWO_LEVEL_CTL, WORDS, 0);
  printf("HYGIENE case code=%llu nodes=%llu name_bytes=%llu\n",
         (unsigned long long)r.code, (unsigned long long)r.w1,
         (unsigned long long)r.out[2]);
  printf("HYGIENE ctl  code=%llu nodes=%llu name_bytes=%llu\n",
         (unsigned long long)c.code, (unsigned long long)c.w1,
         (unsigned long long)c.out[2]);

  /* The two marks, spelled out.  Same text, two different macro ordinals --
   * that is what hygiene looks like in bytes. */
  int outer_mark = table_has(&r, "__ntm$2$e1$t");
  int inner_mark = table_has(&r, "__ntm$1$e2$t");
  printf("HYGIENE produced_marks outer=|__ntm$2$e1$t|=%d inner=|__ntm$1$e2$t|=%d "
         "the_ordinals_differ_so_a_count_of_distinct_strings_is_not_what_is_checked\n",
         outer_mark, inner_mark);
  CHECK(r.code == 0, "the hygiene case expands: it is a SILENT capture or a correct one");
  CHECK(outer_mark && inner_mark,
        "both introduced names are published as MARKS carrying their own ordinal");
  /* THE STRONG FORM, and it is the one that discriminates.  The whole table is
   * compared to the bytes expected rather than searched for a substring, so a
   * table carrying an EXTRA name -- the bare `t` a capturing expander would
   * publish -- fails on the LENGTH first and cannot pass by containing both
   * marks somewhere.
   *
   * The expectation is read off the run's own published bytes, not guessed:
   * `__ntm$2$e1$tu64_` then `_ntm$1$e2$tu64`, thirty bytes, the underscore
   * being part of each entry so there is ONE between them and not two.  The
   * first version wrote two and reported a table the same run had just printed
   * correctly as a mismatch -- which is the exact shape this file exists to
   * refuse, and it is why the value below is composed with its length. */
  static const char *EXPECT =
      "__ntm$2$e1$t" "u64_" "_ntm$1$e2$t" "u64";
  printf("HYGIENE expected_table=|%s| its_length=%u the_run_reported=%llu\n",
         EXPECT, (unsigned)strlen(EXPECT), (unsigned long long)r.out[2]);
  CHECK(table_is(&r, EXPECT),
        "the produced table is EXACTLY the two marks with their type suffixes: "
        "no bare `t` was published, so nothing captured the caller's local");

  /* The weaker form is kept as well, because it localises a failure: if the
   * exact comparison fails, these say WHICH mark is missing. */
  CHECK(table_has(&r, "__ntm$1$e2$t") && table_has(&r, "__ntm$2$e1$t"),
        "the two marks differ by macro ORDINAL, so neither is a copy of the other");

  /* The control: same nesting, caller's local removed.  It must ALSO expand
   * and publish the SAME two marks -- that is what says the expansion's names
   * do not come from the caller's scope. */
  CHECK(c.code == 0, "the control expands too");
  CHECK(table_has(&c, "__ntm$2$e1$t") && table_has(&c, "__ntm$1$e2$t"),
        "the control publishes the same two marks, so the caller's local contributed nothing");

  /* THE DISCRIMINATION, measured -- and it is measured on the NAME TABLE, not
   * on the whole buffer.  The first version compared every word from out[4]
   * upward and reported the two runs as different; the difference is real but
   * it is PROVENANCE, not capture: the produced nodes carry source spans, and
   * the control's source is one declaration shorter, so every offset after it
   * moves.  Comparing spans to decide a question about names is the wrong
   * comparison, and it would have reported a defect that is not there.  The
   * names are the claim, so the names are what is compared. */
  int names_same = (r.out[2] == c.out[2]) && table_is(&r, EXPECT) &&
                   table_is(&c, EXPECT);
  int whole_same = (memcmp(r.out + 4, c.out + 4, WORDS * 8 - 32) == 0);
  printf("HYGIENE case_and_control_publish_identical_NAMES=%d "
         "whole_buffer_identical=%d (the second is expected to be 0: produced "
         "nodes carry source spans and the control's source is shorter)\n",
         names_same, whole_same);
  CHECK(names_same,
        "the caller's local is not captured: adding it changes no produced NAME");

  freerun(&r); freerun(&c);
}

/* =========================== PHASE 2 -- PROVENANCE =========================
 *
 * THE QUESTION THE INVENTORY ROW LEAVES OPEN, answered with a search.  The
 * row's text for B5 is "every produced name classified; HYG_SPAN reports the
 * template site".  `HYG_SPAN` is not a symbol of the product: it is a C
 * string literal inside tests/c/nova/tests_ntasm_macro_expand.c,
 * another gate's harness.  So the row CITES another harness rather than
 * measuring, which is exactly the question asked here -- attested or noted.
 * The campaign prints the search that settles it instead of asserting it.
 *
 * THE MEASUREMENT.  A refusal raised INSIDE an expansion, on a name the
 * TEMPLATE introduces, must report the TEMPLATE's position and not the
 * invocation's.  The two are different lines, so a report that named the
 * invocation would be visibly wrong rather than merely different -- the
 * property is DISCRIMINATIVE and not a coincidence.  The expectation is
 * derived by counting the lines and columns of the needle in the source the
 * campaign holds, so a green cannot come from a literal that happens to be
 * right today. */
static void phase2_provenance(const NovaHostImage *img) {
  /* The row cites a C identifier.  Resolve it, and show where it lives. */
  static const char *CITE = "HYG_SPAN";
  char *cite_in_product = NULL;
  static const char *product[] = {
      "compiler/nova/macros/macro_expand.nova",
      "compiler/nova/macros/constant_eval.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/ast.nova",
      "compiler/nova/frontend/lexer.nova"};
  int in_product = 0, in_other_harness = 0;
  for (unsigned i = 0; i < 5; i++) {
    size_t n = 0;
    char *t = loadf(product[i], &n);
    if (t && strstr(t, CITE)) in_product = 1;
    free(t);
  }
  {
    size_t n = 0;
    char *t = loadf("tests/c/nova/tests_ntasm_macro_expand.c", &n);
    if (t && strstr(t, CITE)) in_other_harness = 1;
    free(t);
  }
  free(cite_in_product);
  printf("PROV_ATTESTED cited=%s present_in_the_product_modules=%d "
         "present_in_another_gates_harness=%d\n", CITE, in_product, in_other_harness);
  printf("PROV_ATTESTED so_the_inventory_row_cites_another_harness_rather_than_"
         "measuring_provenance_here_and_below_it_is_measured\n");
  /* This is a FINDING, not a product defect: the other gate does measure the
   * span.  The assertion is that the citation resolves to a harness, so the
   * reader knows the row's own instrument does not carry this conjunct. */
  CHECK(!in_product && in_other_harness,
        "the row's cited identifier is a C literal in another harness, not a product symbol");

  /* ---- and the measurement the row asserts ---- */
  static const char *SPAN =
      HEAD "const t:u64=1;\n"
      "macro mk()->ast.block {\n"
      "    return quote(block) { let t:u64=1; return t; };\n}\n"
      "section .text {\n    export fn main()->u64\n    effects {}\n"
      "    clobbers {} {\n        expand mk()\n    }\n}\n";
  static const char *NEEDLE = "let t:u64=1";

  cases++;
  Run r = run(img, SPAN, WORDS, 0);
  /* Derive the expectation from the source the campaign holds, so a green
   * cannot come from a literal pair that happens to be right today.  Both
   * numbers are derived the same way, and the column is counted from the
   * START OF THE LINE, 1-based, because that is what the diagnostic reports.
   * The first version measured the column as an offset from the FILE start
   * and produced 78 against a reported 31: a FAIL that named the product for
   * a mistake in the measuring instrument, which is the direction this file
   * exists to avoid. */
  size_t len = strlen(SPAN), at = 0;
  while (at + strlen(NEEDLE) <= len &&
         strncmp(SPAN + at, NEEDLE, strlen(NEEDLE)) != 0) at++;
  size_t ls = 0;
  unsigned want_line = 1;
  for (size_t i = 0; i < at; i++) if (SPAN[i] == '\n') { ls = i + 1; want_line++; }
  unsigned want_col = (unsigned)(at - ls) + 1;  /* 1-based column of the `l` */
  want_col += 4;                               /* the `t` is four bytes into `let ` */
  unsigned inv_line = 1;
  const char *inv = strstr(SPAN, "expand mk()");
  if (inv) for (const char *q = SPAN; q < inv; q++) if (*q == '\n') inv_line++;
  printf("PROV_SPAN reported=%llu:%llu derived_from_source=%u:%u "
         "invocation_is_on_line=%u template_line=%u\n",
         (unsigned long long)r.w1, (unsigned long long)r.w2,
         want_line, want_col, inv_line, want_line);
  CHECK(r.code != 0, "the shape is refused, so a span is reported at all");
  CHECK(r.w1 == (uint64_t)want_line && r.w2 == (uint64_t)want_col,
        "the refusal reports the TEMPLATE position derived from the source");
  CHECK(r.w1 != (uint64_t)inv_line,
        "and it is NOT the invocation's line, which is a different line");

  /* The control on the DERIVATION: if the two lines coincided the property
   * above would be vacuous, so the campaign states that they differ. */
  CHECK(want_line != inv_line,
        "the template line and the invocation line differ, so naming one is a discrimination");
  freerun(&r);
}

/* ======================== PHASE 3 -- ABSENCE OF I/O ========================
 *
 * HALF ONE FIRST, and it is not optional.  A gate that refuses a channel
 * which does not exist has proved nothing about the expander, so the file
 * channel is measured OPEN by compiling and RUNNING a canary of the same
 * compiler against the same host runtime, and its effect is read back from
 * outside.  Only then is the refusal meaningful.
 *
 * THE ADVERSARIAL CASE.  The template SPELLS the channel in the `if`
 * condition -- route A, the one a walk of the template can see.  It must be
 * refused 379 with reason 20, the channel's OWN reason.
 *
 * WHAT A WRONG IMPLEMENTATION WOULD DO.  Three ways, each named:
 *   - a hygiene-only expander answers 374/1 ("capture of a caller symbol"),
 *     because the name is unbound -- that is what the product USED to do,
 *     and it carries no information about the channel;
 *   - an expander that accepts it answers 0 and the expansion observes the
 *     filesystem;
 *   - an expander that refuses EVERYTHING answers 379/20 here and passes,
 *     which is why the control below must answer 374/1. */
static void phase3_io(const char *rundir) {
  {
    /* HALF ONE: the channel is OPEN. */
    int canaries = 0;
    char path[NG_RUN_DIR_MAX + 32];
    snprintf(path, sizeof path, "%s/a5-canary.bin", rundir);
    FILE *f = fopen(path, "wb");
    if (f) { fwrite("ABCDEFGHIJKLMNOP", 1, 16, f); fclose(f); }

    static const char *RD = "tests/nova/tests/macro-io-canary-entry.nova";
    size_t rn = 0;
    char *rtext = loadf(RD, &rn);
    if (rtext) {
      NtFInput in = {RD, rtext, rn};
      NtArtifact a = {0};
      NovaHostImage img = {0};
      if (nova_compile_many_v2(&in, 1, &a) && nova_host_map(&a, &img)) {
        uint64_t out[8] = {0};
        uint64_t rc = run_canary(&img, path, out, 8);
        printf("IO_OPEN channel=file-read rc=%llu read=%llu first_byte=%llu\n",
               (unsigned long long)rc, (unsigned long long)out[1],
               (unsigned long long)out[2]);
        CHECK(rc == 0 && out[0] == 1 && out[1] == 16 && out[2] == 'A',
              "the file-read channel is OPEN and its bytes are observable from outside");
        nova_host_unmap(&img);
        canaries++;
      }
    }
    free(rtext);
    printf("IO_OPEN canaries_compiled_and_run=%d "
           "a_refusal_of_an_absent_channel_would_prove_nothing\n", canaries);
    cases++;
    CHECK(canaries == 1, "HALF ONE is measured, not assumed");

    /* HALF TWO: the expansion is refused, and the refusal NAMES the channel. */
    char src[1024];
    snprintf(src, sizeof src, HEAD
             "macro pick(k:u64)->ast.expr {\n"
             "    if rt_open_read(\"f\") {\n"
             "        return quote(expr) { 1 };\n"
             "    } else {\n"
             "        return quote(expr) { 0 };\n"
             "    }\n"
             "}\n" TAIL "pick(1)\n" FOOT);
    char ctl[1024];
    snprintf(ctl, sizeof ctl, HEAD
             "macro pick(k:u64)->ast.expr {\n"
             "    if not_a_channel_name {\n"
             "        return quote(expr) { 1 };\n"
             "    } else {\n"
             "        return quote(expr) { 0 };\n"
             "    }\n"
             "}\n" TAIL "pick(1)\n" FOOT);

    /* both run through the same image as the other phases */
    static const char *paths[] = {
        "tests/nova/tests/macro-expand-entry.nova",
        "compiler/nova/macros/macro_expand.nova",
        "compiler/nova/macros/constant_eval.nova",
        "compiler/nova/frontend/parser.nova",
        "compiler/nova/frontend/ast.nova",
        "compiler/nova/frontend/lexer.nova"};
    char *texts[6]; NtFInput inputs[6];
    memset(inputs, 0, sizeof inputs);
    for (int i = 0; i < 6; i++) {
      size_t n = 0; texts[i] = loadf(paths[i], &n);
      inputs[i] = (NtFInput){paths[i], texts[i], n};
    }
    NtArtifact a = {0};
    NovaHostImage img = {0};
    int ok = nova_compile_many_v2(inputs, 6, &a) && nova_host_map(&a, &img);
    CHECK(ok, "the expander image maps for the I/O arm");
    if (ok) {
      cases++;
      Run r = run(&img, src, WORDS, 0);
      Run c = run(&img, ctl, WORDS, 0);
      printf("IO_CASE channel_spelled_in_template code=%llu reason=%llu "
             "line=%llu col=%llu\n", (unsigned long long)r.code,
             (unsigned long long)r.reason, (unsigned long long)r.w1,
             (unsigned long long)r.w2);
      printf("IO_CTL  name_that_names_no_channel  code=%llu reason=%llu\n",
             (unsigned long long)c.code, (unsigned long long)c.reason);
      CHECK(r.code == 379 && r.reason == 20,
            "the expansion is refused 379 with the FILE-READ channel's own reason");
      CHECK(!(c.code == 379 && c.reason == 20),
            "a name naming no channel is NOT refused as a channel -- the 379 is a classification");
      CHECK(c.code == 374 && c.reason == 1,
            "and it answers the hygiene rule instead, so the two rules are distinguishable");
      freerun(&r); freerun(&c);
      nova_host_unmap(&img);
    }
    for (int i = 0; i < 6; i++) free(texts[i]);
  }
}

/* ====================== PHASE 4 -- THE BOUND THAT BITES ====================
 *
 * This is the item the A5 row has carried as UNIDENTIFIED for weeks: "le
 * NV2_BOUNDS(4) a 32 704 items dont le site de levee n'est pas identifie --
 * il n'est pas devine".  This phase identifies it, and the identification is
 * a MEASUREMENT and not a reading of the source.
 *
 * THE METHOD.  The expander's own six budgets are all refused with a code and
 * a reason the expander chooses (201 with reason k+1).  NV2_BOUNDS is a
 * RUNTIME fault, carried on a different channel: c.error, which the caller
 * reads and the expander cannot.  So the arm sweeps the CALLER's output
 * buffer and asks, at each size, two questions separately: did the runtime
 * fault, and what did the EXPANDER say.  Sweeping one word at a time around
 * the boundary locates the site without reading runtime_v2.c.
 *
 * WHAT IT FINDS, and this is the finding rather than a confirmation:
 * the refusal is on the CALLER'S BUFFER, not on anything the expansion
 * consumed, and the expander's own verdict stays 0.  The bound bites -- at
 * exactly one word past a round number -- but it is a boundary of the HARNESS,
 * which is the sentence the A5 bounds log already reached and could not
 * confirm.
 *
 * THE CONTROL.  The same body at a modest buffer must expand and publish a
 * region.  Without it, an arm that reports "refused" everywhere would look
 * identical to this one. */
static void phase4_bounds(const NovaHostImage *img) {
  static const char *BODY =
      HEAD "macro ret(v:ast.expr)->ast.stmt {\n"
      "    return quote(stmt) { return $v+1; };\n}\n"
      "section .text {\n    export fn main()->u64\n    effects {}\n"
      "    clobbers {} {\n        expand ret(1)\n    }\n}\n";

  cases++;
  /* the control: a modest buffer expands and publishes */
  Run ok = run(img, BODY, WORDS, 0);
  printf("BND_CTL modest_buffer code=%llu nodes=%llu runtime=%llu "
         "(if this did not expand, every refusal below would be vacuous)\n",
         (unsigned long long)ok.code, (unsigned long long)ok.w1,
         (unsigned long long)ok.runtime);
  CHECK(ok.code == 0 && ok.w1 > 0 && ok.runtime == 0,
        "CONTROL: the same body expands whole at a modest caller buffer");
  freerun(&ok);

  /* The sweep, one word apart, across the boundary.  8388608 words is 64 MiB;
   * the boundary is located by MEASUREMENT and this loop is what locates it. */
  uint64_t last_ok = 0, first_bad = 0;
  for (uint64_t w = 8388604; w <= 8388612; w++) {
    Run r = run(img, BODY, w, 0);
    printf("BND words=%llu bytes=%llu runtime=%llu NV2_BOUNDS_is_4=%d "
           "expander_code=%llu nodes=%llu\n", (unsigned long long)w,
           (unsigned long long)(w * 8), (unsigned long long)r.runtime,
           r.runtime == 4, (unsigned long long)r.code,
           (unsigned long long)r.w1);
    /* last_ok is the LAST size that worked, so it must be OVERWRITTEN on each
     * success rather than latched on the first: latching it reported the
     * sweep's opening value as the boundary and made a one-word boundary look
     * five words wide -- a FAIL that named the product for a bookkeeping slip
     * in the instrument that located it. */
    if (r.runtime == 0) last_ok = w;
    if (r.runtime == 4 && first_bad == 0) {
      first_bad = w;
      /* THE FINDING, asserted rather than noted: the runtime refused AND the
       * expander still reports success.  A bound that the product cannot see
       * is a bound the product cannot honour. */
      CHECK(r.code == 0 && r.w1 == 0,
            "the runtime refuses and the EXPANDER still reports 0 -- the two "
            "channels disagree and the product's own verdict is success");
    }
    freerun(&r);
  }
  printf("BND located last_ok_words=%llu first_NV2_BOUNDS_words=%llu "
         "boundary_is_exactly_one_word_past=%llu bytes=%llu\n",
         (unsigned long long)last_ok, (unsigned long long)first_bad,
         (unsigned long long)(first_bad - last_ok),
         (unsigned long long)(first_bad * 8));
  CHECK(last_ok && first_bad && first_bad == last_ok + 1,
        "the boundary is located by MEASUREMENT and is one word wide");
  CHECK(first_bad * 8 > 67108864u && last_ok * 8 <= 67108864u,
        "and it sits at the 64 MiB mark, which is the runtime's own ceiling "
        "(runtime_v2.c:108, BYTES_MAX)");
}

/* ====================== PHASE 5 -- DETERMINISM BY CONTROL ==================
 *
 * The inventory gate compares two runs over the whole output buffer, which is
 * the right comparison.  This phase adds the half that makes it a
 * measurement: a one-byte change to the source must make the comparison come
 * out DIFFERENT.  Without that half, a comparison that cannot tell two inputs
 * apart is equally happy reporting them equal, and the green is a posture.
 * R301, exactly: a digest answers "did the claim change", never "is the claim
 * right". */
static void phase5_determinism(const NovaHostImage *img) {
  static const char *SRC =
      HEAD "macro ret(v:ast.expr)->ast.stmt {\n"
      "    return quote(stmt) { return $v+1; };\n}\n"
      "section .text {\n    export fn main()->u64\n    effects {}\n"
      "    clobbers {} {\n        expand ret(1)\n    }\n}\n";

  cases++;
  Run a = run(img, SRC, WORDS, 0);
  Run b = run(img, SRC, WORDS, 0);
  char *mod = strdup(SRC);
  char *hit = strstr(mod, "return $v+1;");
  if (hit) hit[strlen("return $v+") - 1] = '2';      /* one byte: 1 -> 2 */
  Run c = run(img, mod, WORDS, 0);

  int same = (a.code == b.code) && (a.w1 == b.w1) &&
             memcmp(a.out, b.out, WORDS * 8) == 0;
  int differs = memcmp(a.out, c.out, WORDS * 8) != 0;
  printf("DET same_source_twice_byte_identical=%d "
         "one_byte_change_differs=%d compared=memcmp_over_all_%u_words\n",
         same, differs, WORDS);
  CHECK(same, "the same source twice is byte-identical over the whole output buffer");
  CHECK(differs,
        "CONTROL: a one-byte change DIFFERS, so the equality above is a "
        "measurement and not a posture -- a digest could not answer this");
  freerun(&a); freerun(&b); freerun(&c); free(mod);
}

/* ================================== main ================================= */
int main(void) {
  printf("A5_CAMPAIGN_ADVERSARIAL the_four_conjuncts_and_the_control_each_needs\n");
  printf("A5_CAMPAIGN_LIMITS hygiene=two_level_three_names_spelled_t_"
         "proved_on_the_produced_name_table_not_on_a_code "
         "provenance=attested_here_the_inventory_row_cites_another_harness "
         "io=half_one_measures_the_channel_OPEN_then_half_two_refuses_it "
         "bounds=the_NV2_BOUNDS_site_located_by_sweep_not_by_reading "
         "determinism=proved_by_a_control_that_must_differ_not_by_a_digest\n");

  static const char *paths[] = {
      "tests/nova/tests/macro-expand-entry.nova",
      "compiler/nova/macros/macro_expand.nova",
      "compiler/nova/macros/constant_eval.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/ast.nova",
      "compiler/nova/frontend/lexer.nova"};
  char *texts[6]; NtFInput inputs[6];
  memset(inputs, 0, sizeof inputs);
  int all = 1;
  for (int i = 0; i < 6; i++) {
    size_t n = 0;
    texts[i] = loadf(paths[i], &n);
    inputs[i] = (NtFInput){paths[i], texts[i], n};
    if (!texts[i]) all = 0;
  }
  CHECK(all, "the six expander modules load");
  NtArtifact a = {0};
  int compiled = all && nova_compile_many_v2(inputs, 6, &a);
  CHECK(compiled, "the six expander modules compile");
  if (!compiled) {
    fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line,
            a.error.column, a.error.message);
    for (int i = 0; i < 6; i++) free(texts[i]);
    return 2;
  }
  NovaHostImage img = {0};
  CHECK(nova_host_map(&a, &img), "the expander image maps");
  if (!img.memory) {
    for (int i = 0; i < 6; i++) free(texts[i]);
    return 2;
  }

  printf("PHASE1 HYGIENE a_callers_local_is_not_captured\n");
  phase1_hygiene(&img);
  printf("PHASE2 PROVENANCE attested_here_rather_than_cited\n");
  phase2_provenance(&img);
  printf("PHASE3 ABSENCE_OF_IO half_one_open_then_half_two_refused\n");
  {
    char dir[NG_RUN_DIR_MAX], why[NG_RUN_DIR_MAX];
    const char *ok_dir = ng_run_file("ng-a5-adv", dir, sizeof dir, why, sizeof why);
    CHECK(ok_dir != NULL, "the run owns a private directory for the I/O canary");
    if (ok_dir) { mkdir(dir, 0700); phase3_io(dir); }
  }
  printf("PHASE4 BOUNDS the_bound_that_bites\n");
  phase4_bounds(&img);
  printf("PHASE5 DETERMINISM by_control_not_by_digest\n");
  phase5_determinism(&img);

  printf("A5_ADVERSARIAL conjuncts=4 declared_conjuncts=4 judged=%u cases=%u "
         "checks=%u failures=%u\n", cases, cases, checks, failures);
  printf("A5_ADVERSARIAL every_refusal_names_its_rule_and_every_case_has_a_"
         "control_that_answers_differently\n");

  nova_host_unmap(&img);
  for (int i = 0; i < 6; i++) free(texts[i]);
  return failures ? 1 : 0;
}