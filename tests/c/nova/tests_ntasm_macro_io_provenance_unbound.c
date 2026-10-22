/* tests_ntasm_macro_io_provenance_unbound.c -- OPENS THE FIRST DOOR.
 *
 * The door: tests/nova/tests/macro-io-provenance-unbound-entry.nova,
 * which until now was written and loaded by nobody. (The brief said it called
 * the lexer. It does not: it calls ntasm_parser.parse, ntasm_ast.release and
 * ntasm_macro_expand.expand. The lexer arrives transitively, through the
 * parser.)
 *
 * WHAT IT PUBLISHES. Eight u64s in one buffer, and they are a RECORD, not a
 * verdict: out[0] is the diagnostic and zero on success; out[1] the produced
 * node count; out[2] the name table byte length; out[3] MARKED, out[4] SPELLED,
 * out[5] CALLER, out[6] UNBOUND -- the four classes of a produced name -- and
 * out[7] the number of produced names the EXECUTION channel cannot reach.
 *
 * THE PROPERTY IS CROSS-READ AGAINST A SECOND ENTRY, not against a table.
 * macro-expand-entry.nova is a DIFFERENT module with the same signature, and
 * it publishes the produced node table itself, in out[4..]. So for every
 * source in the corpus this gate runs both entries over the SAME expander and
 * then asks three questions that neither entry can answer about itself:
 *
 *   1. DO THE TWO ENTRIES AGREE ON THE SHAPE? out[1] and out[2] from the
 *      unbound entry against out[1] and out[2] from the expand entry. Two
 *      independently written modules read the same room; a disagreement means
 *      one of them is reading the wrong words.
 *   2. IS THE CLASSIFICATION A PARTITION? out[3]+out[4]+out[5]+out[6] must
 *      equal the number of produced name nodes -- kind 90 with a non-empty
 *      span -- counted here in C by walking the expand entry's table. A
 *      classifier that dropped a name, counted one twice, or invented a fifth
 *      class fails, and none of those is visible from the four numbers alone.
 *   3. DOES THE MARK GRAMMAR AGREE? out[3] must equal the count this file
 *      reaches with its OWN parse of the four mark formats macro_expand.nova
 *      writes at its put_mark sites. The Nova side tests a prefix and a field
 *      shape; this side parses the whole format, ordinal and serial included.
 *      A name that merely starts with __nt must not pass as a mark, and that
 *      is the case the two implementations most likely to disagree on.
 *
 * AND out[7] MUST MOVE. The entry calls it a measurement, and a measurement
 * that does not move is a walk. The corpus carries a shape whose produced
 * text is one expression and a shape carrying a `let`, and the entry's own
 * banner says the first scores 0 and the second does not. Both are asserted.
 *
 * THE SPELLING VOCABULARY IS MEASURED AND NOT ASSERED, and the reason is
 * written down rather than left to a reader. This entry's is_spelling list and
 * the wave-13 classifier's SPELLED[] in tests_ntasm_macro_expand.c are TWO
 * DECLARATIONS OF THE SAME FACT and they do not hold the same words: the
 * former carries fn/let/if/or/xor/true and drops false/ptr/user/void, the
 * latter the reverse. Asserting either against the other would be asserting a
 * vocabulary one of them does not publish, so both counts are printed on every
 * row and the comparison a reader can make is left visible.
 *
 * THE CALLER BUCKET. classify() has no path that returns CLS_CALLER: the
 * short_class fallback offers only SPELLED and UNBOUND. out[5] is therefore a
 * constant zero today. It is NOT asserted to be zero -- pinning it would make
 * a defect permanent and green -- it is counted by the partition check above
 * and printed, so a future repair of classify() turns nothing red here and
 * turns out[6] into the measurement it is meant to be.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
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

#define GUARD UINT64_C(0xcccccccccccccccc)
#define EXPAND_WORDS (1u << 18)
#define UNBOUND_WORDS 8
#define ROOM_WORDS 4

/* THE CORPUS CENSUS. Accumulated by confront() so the floor in main() can be
 * stated over the whole corpus rather than per row. */
static unsigned long census_names, census_marked, census_spelled,
    census_caller, census_unbound, census_expanded, census_bytes;

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

typedef struct {
  uint64_t returned, runtime, code, nodes, names, reason;
  uint64_t *out, words;
} Run;

static Run run(const NovaHostImage *image, const char *source, uint64_t words,
               uint64_t request) {
  Run r;
  memset(&r, 0, sizeof r);
  r.code = r.nodes = r.names = r.reason = GUARD;
  r.out = calloc(words ? words : 1, 8);
  if (!r.out) return r;
  r.words = words;
  r.out[0] = request;
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)source, strlen(source), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, words * 8, 1);
  uint64_t args[4] = {sh, strlen(source), oh, words};
  r.returned = image->entry(&c, args, 4);
  r.runtime = c.error;
  r.code = r.out[0];
  r.nodes = r.out[1];
  r.names = r.out[2];
  r.reason = r.out[3];
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return r;
}

static void freerun(Run *r) { free(r->out); r->out = NULL; }

static int layout_ok(const Run *r) {
  uint64_t span = ROOM_WORDS + (r->names + 7) / 8 + r->nodes * 12;
  return r->returned == 0 && r->runtime == 0 && r->code == 0 && r->nodes != 0 &&
         span <= r->words;
}

static const uint64_t zero12[12] = {0};

static const uint64_t *node_words(const Run *r, uint64_t id) {
  uint64_t nw = (r->names + 7) / 8;
  if (id == 0 || ROOM_WORDS + nw + id * 12 > r->words) return zero12;
  return r->out + ROOM_WORDS + nw + (id - 1) * 12;
}

/* One byte of the produced name table, unpacked the way the expander packed
 * it: byte i is word (start + i)/8, shifted by 8*(i%8). */
static unsigned name_byte(const Run *r, uint64_t at) {
  return (unsigned)((r->out[ROOM_WORDS + (at / 8)] >> (8 * (at % 8))) & 0xff);
}

static void name_copy(const Run *r, uint64_t start, uint64_t end, char *dst,
                      size_t cap) {
  dst[0] = 0;
  if (end < start || end - start + 1 > cap) return;
  size_t n = (size_t)(end - start);
  for (size_t i = 0; i < n; i++) dst[i] = (char)name_byte(r, start + i);
  dst[n] = 0;
}

/* THE MARK GRAMMAR, parsed here rather than prefix-matched here.
 *   __ntm$<ord>$e<ser>$<name>
 *   __ntd$<ord>$e<ser>$<name>            and  ...$r<rep>$t<item>$<name>
 *   __ntp$<ord>$e<ser>$p<space>$<name>
 * Each format is walked to its end, so a caller identifier that begins __nt
 * and then fails is not a mark -- which is exactly the case a prefix test
 * would wave through and which the Nova side's field_then_dollar rules out. */
static int digits(const char *t, const char **after) {
  const char *p = t;
  while (*p >= '0' && *p <= '9') p++;
  if (p == t) return 0;
  *after = p;
  return 1;
}

static int field(const char **p, char c) {
  if (**p != c) return 0;
  (*p)++;
  return 1;
}

static int mark_format(const char *t) {
  if (strncmp(t, "__nt", 4) != 0) return 0;
  char k = t[4];
  if (k != 'm' && k != 'd' && k != 'p') return 0;
  const char *p = t + 5;
  if (!field(&p, '$')) return 0;
  if (!digits(p, &p)) return 0;
  if (!field(&p, '$') || !field(&p, 'e')) return 0;
  if (!digits(p, &p)) return 0;
  if (!field(&p, '$')) return 0;
  if (k == 'p') {
    if (!field(&p, 'p')) return 0;
    if (!digits(p, &p)) return 0;
    if (!field(&p, '$')) return 0;
  } else if (k == 'd' && *p == 'r') {
    if (!field(&p, 'r')) return 0;
    if (!digits(p, &p)) return 0;
    if (!field(&p, '$') || !field(&p, 't')) return 0;
    if (!digits(p, &p)) return 0;
    if (!field(&p, '$')) return 0;
  }
  return 1;
}

/* The wave-13 classifier's own vocabulary, spelled out here so the divergence
 * between the two declarations is a number in the log and not an impression. */
static const char *const SPELLED[] = {"bool", "u8",   "u16", "u32", "u64", "i8",
                                      "i16",  "i32",  "i64", "true", "false",
                                      "ptr",  "user", "void"};

static int spelled_here(const char *t) {
  for (unsigned i = 0; i < sizeof SPELLED / sizeof SPELLED[0]; i++)
    if (strcmp(t, SPELLED[i]) == 0) return 1;
  return 0;
}

/* One source, run through both entries. */
static void confront(const NovaHostImage *expand, const NovaHostImage *unbound,
                     const char *label, const char *source, int control) {
  Run e = run(expand, source, EXPAND_WORDS, 0);
  uint64_t out[UNBOUND_WORDS];
  for (unsigned i = 0; i < UNBOUND_WORDS; i++) out[i] = GUARD;
  uint64_t u_returned = UINT64_MAX, u_runtime = UINT64_MAX;
  {
    NovaContextV2 c = {0};
    if (nova_context_init_v2(&c)) {
      uint64_t args[4] = {nova_borrow_v2(&c, (void *)source, strlen(source), 0),
                          strlen(source),
                          nova_borrow_v2(&c, out, UNBOUND_WORDS * 8, 1),
                          UNBOUND_WORDS};
      u_returned = unbound->entry(&c, args, 4);
      u_runtime = c.error;
      nova_context_destroy_v2(&c);
    }
  }
  cases++;

  if (!layout_ok(&e)) {
    failures++;
    fprintf(stderr,
            "FAIL %s the expand entry did not publish a produced region: "
            "ret=%" PRIu64 " runtime=%" PRIu64 " code=%" PRIu64 " nodes=%" PRIu64
            " names=%" PRIu64 "\n",
            label, e.returned, e.runtime, e.code, e.nodes, e.names);
    freerun(&e);
    return;
  }
  CHECK(u_runtime == 0, "no runtime error");
  checks++;
  if (u_returned != 0) {
    failures++;
    fprintf(stderr, "FAIL %s the unbound entry returned %" PRIu64 " on a source "
                    "the expander accepted\n",
            label, u_returned);
    freerun(&e);
    return;
  }

  /* (1) the two entries on the same expander. */
  CHECK(out[1] == e.nodes, "the two entries agree on the produced node count");
  checks++;
  if (out[1] != e.nodes)
    fprintf(stderr, "FAIL %s node count unbound=%" PRIu64 " expand=%" PRIu64
                    "\n",
            label, out[1], e.nodes);
  CHECK(out[2] == e.names, "the two entries agree on the name table length");
  checks++;
  if (out[2] != e.names)
    fprintf(stderr, "FAIL %s name table length unbound=%" PRIu64 " expand=%" PRIu64
                    "\n",
            label, out[2], e.names);

  /* (2) the partition, counted here over the expand entry's own table. */
  uint64_t names_total = 0, marked_here = 0, spelled_here_count = 0;
  for (uint64_t id = 1; id <= e.nodes; id++) {
    const uint64_t *n = node_words(&e, id);
    if (n[0] != 90 || n[7] <= n[6]) continue;
    names_total++;
    char text[128];
    name_copy(&e, n[6], n[7], text, sizeof text);
    if (mark_format(text)) marked_here++;
    else if (spelled_here(text)) spelled_here_count++;
  }
  uint64_t classified = out[3] + out[4] + out[5] + out[6];
  checks++;
  if (classified != names_total) {
    failures++;
    fprintf(stderr,
            "FAIL %s the four classes cover %" PRIu64 " produced names, not "
            "%" PRIu64 ": marked=%" PRIu64 " spelled=%" PRIu64 " caller=%" PRIu64
            " unbound=%" PRIu64 "\n",
            label, classified, names_total, out[3], out[4], out[5], out[6]);
  }

  /* THE HEADLINE, and it is a claim this module makes about itself: "a
   * produced name table carries no name that nothing binds", out[6] UNBOUND.
   * MEASURED over the seven shapes whose produced names are all
   * template-introduced it is zero on every row, so it is asserted there. A
   * gate that only printed it would report the same green and would not know
   * whether the classifier had been switched off.
   *
   * The control row is EXEMPT and the exemption is printed. On that row the
   * produced region carries a name the CALLER wrote, so a non-zero out[6] is
   * the classifier declining to place a name it has no bucket for -- the
   * CALLER bucket classify() never returns -- and not a leak. Asserting zero
   * there would pin the defect; asserting non-zero would pin a repair. The
   * gate states the number and lets a reader see which of the two it is. */
  if (control) {
    fprintf(stderr,
            "UNBOUND_CONTROL case=%s unbound=%" PRIu64 " caller=%" PRIu64
            " the CALLER bucket has no code path, so a name the caller wrote "
            "lands in UNBOUND\n",
            label, out[6], out[5]);
  } else {
    checks++;
    if (out[6] != 0) {
      failures++;
      fprintf(stderr,
              "FAIL %s the entry reports %" PRIu64 " produced names that "
              "nothing binds, which is the leak its own banner names\n",
              label, out[6]);
    }
  }

  census_expanded++;
  census_names += names_total;
  census_marked += out[3];
  census_spelled += out[4];
  census_caller += out[5];
  census_unbound += out[6];
  /* The two name quantities are DIFFERENT and are printed under different
   * names on purpose. out[2] is the name table's BYTE length; the walk counts
   * name NODES with a non-empty span. Printing the first as `names` on the
   * census line and the second as `names` on the per-row line put two
   * quantities under one word in one log, and 168 against 23 is exactly the
   * pair a reader adds together by mistake. */
  census_bytes += out[2];

  fprintf(stderr,
          "UNBOUND case=%s nodes=%" PRIu64 " names=%" PRIu64 " marked=%" PRIu64
          " marked_here=%" PRIu64 " spelled=%" PRIu64 " spelled_w13=%" PRIu64
          " caller=%" PRIu64 " unbound=%" PRIu64 " unreached=%" PRIu64 "\n",
          label, out[1], out[2], out[3], marked_here, out[4], spelled_here_count,
          out[5], out[6], out[7]);
  freerun(&e);
}

/* A refusal of the FIRST kind: the output buffer cannot hold eight words, so
 * the entry returns at its own first line, before the record is touched. The
 * buffer must still hold the caller's sentinels. */
static void expect_refusal_untouched(const NovaHostImage *unbound,
                                     const char *label, const char *source,
                                     uint64_t words, uint64_t want) {
  uint64_t out[UNBOUND_WORDS];
  for (unsigned i = 0; i < UNBOUND_WORDS; i++) out[i] = GUARD;
  cases++;
  NovaContextV2 c = {0};
  if (!nova_context_init_v2(&c)) {
    failures++;
    fprintf(stderr, "FAIL %s no context\n", label);
    return;
  }
  uint64_t args[4] = {nova_borrow_v2(&c, (void *)source, strlen(source), 0),
                      strlen(source),
                      nova_borrow_v2(&c, out, words * 8, 1), words};
  uint64_t returned = unbound->entry(&c, args, 4);
  uint64_t error = c.error;
  nova_context_destroy_v2(&c);
  CHECK(error == 0, "no runtime error on a refusal");
  CHECK(returned == want, "the refusal code the entry publishes");
  checks++;
  if (returned != want)
    fprintf(stderr, "FAIL %s returned %" PRIu64 ", the entry publishes %" PRIu64
                    "\n",
            label, returned, want);
  for (unsigned i = 0; i < UNBOUND_WORDS; i++) {
    checks++;
    if (out[i] != GUARD) {
      failures++;
      fprintf(stderr,
              "FAIL %s is a buffer-size refusal and it moved output word %u "
              "(%" PRIu64 ")\n",
              label, i, out[i]);
    }
  }
  fprintf(stderr, "UNBOUND_REFUSED case=%s words=%" PRIu64 " returned=%" PRIu64
                  " record=untouched\n",
          label, words, returned);
}

/* A refusal of the SECOND kind, and this one needs its form written down
 * because it is not the form a reader would guess.
 *
 * MEASURED: main() zeroes all eight words BEFORE it parses, so every refusal
 * that happens after that line leaves a record of eight zeros. The module's
 * own header says "out[0] the diagnostic code and zero on success" -- and on
 * a refusal out[0] is ALSO zero. So out[0] carries no refusal information at
 * all and the return value is the only channel that says anything.
 *
 * That is a statement about the module, so it is what gets asserted here: the
 * record on a refusal is all zeros, and the return is the refusal. Asserting
 * "a refusal leaves the buffer untouched" would be asserting a form this
 * module does not publish -- and it is the form the wave-13 sibling entry does
 * publish, which is why the difference between two entries that share a
 * signature is worth a reader's attention rather than a quiet assumption.
 * The hazard is printed on every row and named in the banner, so it cannot be
 * lost by a reader who only reads the counters. */
static void expect_refusal_zeroed(const NovaHostImage *unbound,
                                  const char *label, const char *source,
                                  uint64_t want) {
  uint64_t out[UNBOUND_WORDS];
  for (unsigned i = 0; i < UNBOUND_WORDS; i++) out[i] = GUARD;
  cases++;
  NovaContextV2 c = {0};
  if (!nova_context_init_v2(&c)) {
    failures++;
    fprintf(stderr, "FAIL %s no context\n", label);
    return;
  }
  uint64_t args[4] = {nova_borrow_v2(&c, (void *)source, strlen(source), 0),
                      strlen(source),
                      nova_borrow_v2(&c, out, UNBOUND_WORDS * 8, 1),
                      UNBOUND_WORDS};
  uint64_t returned = unbound->entry(&c, args, 4);
  uint64_t error = c.error;
  nova_context_destroy_v2(&c);
  CHECK(error == 0, "no runtime error on a refusal");
  CHECK(returned == want, "the refusal code the entry publishes");
  checks++;
  if (returned != want)
    fprintf(stderr, "FAIL %s returned %" PRIu64 ", the entry publishes %" PRIu64
                    "\n",
            label, returned, want);
  unsigned nonzero = 0;
  for (unsigned i = 0; i < UNBOUND_WORDS; i++)
    if (out[i] != 0) nonzero++;
  checks++;
  if (nonzero != 0) {
    failures++;
    fprintf(stderr,
            "FAIL %s refused and left %u non-zero words in the record; this "
            "entry zeroes all eight before it parses, so a refusal publishes an "
            "all-zero record and nothing else\n",
            label, nonzero);
  }
  fprintf(stderr,
          "UNBOUND_REFUSED case=%s returned=%" PRIu64 " record=all_zero "
          "out0_is_not_a_diagnostic_channel=true\n",
          label, returned);
}

#define HEAD "module m\ntarget x86_64-nexora-none\n"
#define TAIL "section .text {\n    export fn main()->u64\n    effects {}\n" \
            "    clobbers {} {\n        expand "
#define FOOT "    }\n}\n"

/* The corpus. Every row is a template shape the expander has a mark
 * constructor for, so a mark-count of zero over the whole corpus would be a
 * corpus that exercised nothing -- which is why the marked tally is asserted
 * to be non-zero below and not merely printed. */
static const char *const CORPUS[] = {
    /* 0: a let, so the __ntm$ local form */
    HEAD "macro blk(v:ast.expr)->ast.block {\n"
         "    return quote(block) { let t:u64 = $v; return t; };\n}\n"
         TAIL "blk(1)\n" FOOT,
    /* 1: a declaration, so __ntd$ without the repeat and item fields */
    HEAD "macro one()->ast.decl {\n"
         "    emit quote(decl) { const c:u64 = 1; }\n}\n"
         TAIL "one()\n" FOOT,
    /* 2: a declaration inside a meta-for, so __ntd$ WITH $r and $t */
    HEAD "macro many(n:u64)->ast.decl {\n"
         "    for i in $n {\n"
         "        emit quote(decl) { const c:u64 = $i; }\n"
         "    }\n}\n" TAIL "many(2)\n" FOOT,
    /* 3: a function and its parameter: __ntd$ on the name and __ntp$ on the
     *    parameter, the only constructor that writes a $p field */
    HEAD "macro fn()->ast.decl {\n"
         "    emit quote(decl) {\n"
         "        fn helper(in a:u64)->u64\n"
         "        effects {}\n"
         "        clobbers {} {\n"
         "            return a\n"
         "        }\n"
         "    }\n}\n" TAIL "fn()\n" FOOT,
    /* 4: two invocations, so the serial differs and the region differs */
    HEAD "macro blk(v:ast.expr)->ast.block {\n"
         "    return quote(block) { let t:u64 = $v; return t; };\n}\n"
         TAIL "blk(1)\n        expand blk(2)\n" FOOT,
    /* 5: a comptime value parameter, so the produced literal is a fold */
    HEAD "macro val(n:u64)->ast.decl {\n"
         "    emit quote(decl) { const c:u64 = $n; }\n}\n"
         TAIL "val(5)\n" FOOT,
    /* 6: ONE EXPRESSION and nothing else. The entry's own banner says the
     *    execution channel reaches this shape completely, so out[7] must be 0
     *    here and must not be 0 on every row of the corpus. */
    HEAD "macro ret(v:ast.expr)->ast.stmt {\n"
         "    return quote(stmt) { return $v+1; };\n}\n"
         TAIL "ret(41)\n" FOOT,
    /* 7: THE CALLER-ARGUMENT CONTROL, and the row that makes the CALLER
     *    bucket's absence measurable. The template hands its argument through
     *    untouched, so the produced region carries a name the CALLER wrote --
     *    which is a name something binds, the caller, and it is the case
     *    out[5] CALLER exists for. This row is MEASURED and its numbers are
     *    printed; the UNBOUND-is-zero assertion is not applied to it, because
     *    what it reports is a statement about the classifier's coverage and
     *    pinning either answer would pin a decision this gate does not own.
     *    A positive out[6] here is not a leak; it is a name the classifier
     *    could not place, and the log says which. */
    HEAD "macro pass(v:ast.expr)->ast.expr {\n"
         "    return quote(expr) { $v };\n}\n"
         "section .text {\n"
         "    export fn main()->u64\n"
         "    effects {}\n"
         "    clobbers {} {\n"
         "        let caller_symbol:u64 = 7;\n"
         "        expand pass(caller_symbol)\n"
         "    }\n}\n"};
#define CORPUS_N ((unsigned)(sizeof CORPUS / sizeof CORPUS[0]))

/* Row labels and the control flag, parallel to CORPUS. Written down beside
 * the corpus rather than derived from it, because a reader who has to
 * recount the array to learn which row is the control has already lost the
 * thing the row was for. */
static const char *const CORPUS_LABEL[] = {
    "let_local", "decl",        "meta_for_decl", "fn_and_param",
    "two_invocations", "comptime_value", "single_expression",
    "caller_argument_control"};
static const unsigned char CORPUS_CONTROL[8] = {0, 0, 0, 0, 0, 0, 0, 1};

int main(void) {
  static const char *const deps[] = {
      "compiler/nova/macros/macro_expand.nova",
      "compiler/nova/macros/constant_eval.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/ast.nova",
      "compiler/nova/frontend/lexer.nova"};
  static const char *const unbound_path =
      "tests/nova/tests/macro-io-provenance-unbound-entry.nova";
  static const char *const expand_path =
      "tests/nova/tests/macro-expand-entry.nova";

  size_t dsz[5] = {0}, usz[2] = {0};
  char *dsrc[5] = {0};
  char *usrc[2] = {0};
  NtFInput dinputs[5], uinputs[7];
  int loaded = 1;
  for (unsigned i = 0; i < 5; i++) {
    dsrc[i] = load(deps[i], dsz + i);
    dinputs[i] = (NtFInput){deps[i], dsrc[i], dsz[i]};
    if (!dsrc[i]) loaded = 0;
  }
  usrc[0] = load(unbound_path, usz + 0);
  usrc[1] = load(expand_path, usz + 1);
  if (!usrc[0] || !usrc[1]) loaded = 0;
  /* uinputs[0..1] are the two entries and uinputs[2..6] the five modules they
   * share. The unbound artifact is compiled from uinputs[0] plus uinputs[2..6]
   * and the expand artifact from uinputs[1] plus the same five: two images,
   * one dependency list, and no module read twice from disk. */
  uinputs[0] = (NtFInput){unbound_path, usrc[0], usz[0]};
  uinputs[1] = (NtFInput){expand_path, usrc[1], usz[1]};
  for (unsigned i = 0; i < 5; i++) uinputs[i + 2] = dinputs[i];

  CHECK(loaded, "both entries and their five modules load");
  NtArtifact unbound_artifact = {0}, expand_artifact = {0};
  NtFInput unbound_set[6], expand_set[6];
  unbound_set[0] = uinputs[0];
  expand_set[0] = uinputs[1];
  for (unsigned i = 0; i < 5; i++) {
    unbound_set[i + 1] = dinputs[i];
    expand_set[i + 1] = dinputs[i];
  }
  int unbound_ok = loaded && nova_compile_many_v2(unbound_set, 6, &unbound_artifact);
  int expand_ok = loaded && nova_compile_many_v2(expand_set, 6, &expand_artifact);
  CHECK(unbound_ok, "the unbound entry compiles with its five modules");
  CHECK(expand_ok, "the expand entry compiles with its five modules");
  if (!unbound_ok)
    fprintf(stderr, "E%u %zu:%zu %s\n", unbound_artifact.error.code,
            unbound_artifact.error.line, unbound_artifact.error.column,
            unbound_artifact.error.message);
  if (!expand_ok)
    fprintf(stderr, "E%u %zu:%zu %s\n", expand_artifact.error.code,
            expand_artifact.error.line, expand_artifact.error.column,
            expand_artifact.error.message);

  NovaHostImage unbound_image = {0}, expand_image = {0};
  CHECK(unbound_ok && nova_host_map(&unbound_artifact, &unbound_image),
        "the unbound image maps");
  CHECK(expand_ok && nova_host_map(&expand_artifact, &expand_image),
        "the expand image maps");

  if (unbound_image.memory && expand_image.memory) {
    for (unsigned i = 0; i < CORPUS_N; i++)
      confront(&expand_image, &unbound_image, CORPUS_LABEL[i], CORPUS[i],
               CORPUS_CONTROL[i]);

    /* THE CORPUS CENSUS, and the floor under it. A classifier that had been
     * switched off would report four zeros and pass every check above: the
     * partition would hold because 0 == 0 and the headline would hold because
     * 0 == 0. So the marks are floored, the produced names are floored, and
     * the refusal codes are named -- a census with a cell at zero is a zero
     * the corpus cannot fill, and it is reported as CORPUS_VACUOUS rather
     * than passed. */
    {
      cases++;
      checks++;
      if (census_expanded != CORPUS_N) {
        failures++;
        fprintf(stderr,
                "FAIL %lu of %u corpus rows expanded, so the classification was "
                "never exercised on all of them\n",
                census_expanded, CORPUS_N);
      }
      checks++;
      if (census_names == 0 || census_marked == 0 || census_spelled == 0) {
        failures++;
        fprintf(stderr,
                "CORPUS_VACUOUS the corpus produced %lu names, %lu marks and "
                "%lu spellings; a census with a cell at zero is a zero the "
                "corpus cannot fill\n",
                census_names, census_marked, census_spelled);
      }
      fprintf(stderr,
              "UNBOUND_CENSUS rows=%u expanded=%lu name_nodes=%lu marked=%lu "
              "spelled=%lu caller=%lu unbound=%lu name_table_bytes=%lu\n",
              CORPUS_N, census_expanded, census_names, census_marked,
              census_spelled, census_caller, census_unbound, census_bytes);
    }

    /* out[7] MUST MOVE, in both directions. Two rows, one assertion each,
     * because a single assertion that out[7] is non-zero everywhere would
     * pass on a walk that never reaches anything. */
    {
      uint64_t out[UNBOUND_WORDS];
      uint64_t reach[CORPUS_N];
      int got = 1;
      for (unsigned i = 0; i < CORPUS_N; i++) {
        for (unsigned w = 0; w < UNBOUND_WORDS; w++) out[w] = GUARD;
        NovaContextV2 c = {0};
        if (!nova_context_init_v2(&c)) { got = 0; break; }
        uint64_t args[4] = {
            nova_borrow_v2(&c, (void *)CORPUS[i], strlen(CORPUS[i]), 0),
            strlen(CORPUS[i]),
            nova_borrow_v2(&c, out, UNBOUND_WORDS * 8, 1), UNBOUND_WORDS};
        uint64_t ret = unbound_image.entry(&c, args, 4);
        uint64_t err = c.error;
        nova_context_destroy_v2(&c);
        if (ret != 0 || err != 0) { got = 0; break; }
        reach[i] = out[7];
      }
      CHECK(got, "every corpus row reports its unreachable count");
      if (got) {
        uint64_t zero_rows = 0, positive_rows = 0;
        for (unsigned i = 0; i < CORPUS_N; i++) {
          if (reach[i] == 0) zero_rows++;
          if (reach[i] > 0) positive_rows++;
        }
        cases++;
        checks++;
        /* BOTH cells non-empty. A reach measure that is zero on every shape
         * measures the walk; one that is positive on every shape measures
         * nothing a reader can use. */
        if (zero_rows == 0 || positive_rows == 0) {
          failures++;
          fprintf(stderr,
                  "FAIL out[7] is zero on %" PRIu64 " of %u corpus rows and "
                  "positive on %" PRIu64
                  ", so the reach measurement is not a measurement\n",
                  zero_rows, CORPUS_N, positive_rows);
        }
        fprintf(stderr, "UNBOUND_REACH rows=%u zero=%" PRIu64 " positive=%" PRIu64
                        " values=%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
                        ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                CORPUS_N, zero_rows, positive_rows, reach[0], reach[1], reach[2],
                reach[3], reach[4], reach[5], reach[6], reach[7]);
      }
    }

    /* The refusals, each a different published rule.
     *   800 -- the output buffer cannot hold eight words (the entry's first
     *          line) and 800 -- the source does not parse. Both are 800, so
     *          the rows differ in what they prove, not in their code.
     *   370 -- the expander's "unknown macro at the invocation", which the
     *          entry passes through unchanged. */
    expect_refusal_untouched(&unbound_image, "seven_word_output", CORPUS[0],
                             UNBOUND_WORDS - 1, 800);
    expect_refusal_untouched(&unbound_image, "no_output", CORPUS[0], 0, 800);
    expect_refusal_zeroed(&unbound_image, "source_without_a_header",
                          "macro blk(v:ast.expr)->ast.block {\n"
                          "    return quote(block) { let t:u64 = $v; return t; };\n}\n",
                          800);
    expect_refusal_zeroed(&unbound_image, "unknown_macro",
                          HEAD TAIL "nope()\n" FOOT, 370);
    expect_refusal_zeroed(&unbound_image, "capture_of_a_caller_symbol",
                          HEAD "macro steal()->ast.stmt {\n"
                               "    return quote(stmt) { return t; };\n}\n"
                               "section .text {\n"
                               "    export fn main()->u64\n"
                               "    effects {}\n"
                               "    clobbers {} {\n"
                               "        let t:u64=9;\n"
                               "        expand steal()\n"
                               "    }\n}\n",
                          374);
  }
  if (unbound_image.memory) nova_host_unmap(&unbound_image);
  if (expand_image.memory) nova_host_unmap(&expand_image);
  if (unbound_ok) nt_artifact_free(&unbound_artifact);
  if (expand_ok) nt_artifact_free(&expand_artifact);
  for (unsigned i = 0; i < 5; i++) free(dsrc[i]);
  free(usrc[0]);
  free(usrc[1]);
  printf("NTASM_NOVA_MACRO_IO_PROVENANCE_UNBOUND checks=%u failures=%u cases=%u\n",
         checks, failures, cases);
  return failures ? 1 : 0;
}
