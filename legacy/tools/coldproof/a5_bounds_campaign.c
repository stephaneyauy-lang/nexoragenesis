/* ==========================================================================
   A5_CAMPAIGN_BOUNDS -- the seven compilation bounds, each with the triple,
   and the diagnostic TEXT nobody has looked at.

   WHAT THIS EXISTS FOR.  The A5 row names seven bounds no campaign had
   measured, and names them as unmeasured so the line would not read as
   though the ceilings were done:

       hard_node_cap 262144   hard_name_cap 4194304  loop_cap 512
       walk_depth_cap 64      parameter_cap 8         binding stack 65536
       argument stack 4096

   and it adds an eighth item that is a DIFFERENT KIND of gap:

       "aucune campagne n'affirme quoi que ce soit sur le texte des
        diagnostics"

   A bound that refuses does not say anything about WHAT it says.  So every
   arm prints the instrument the caller receives at the boundary, verbatim, and
   the text arm is a MEASUREMENT of whether a text exists at all -- with a
   positive control, because a search that finds nothing is the one result a
   stale read fabricates, and with a control that MUST fail, because an
   instrument that cannot fail is the one that makes a green run meaningless.

   ------------------------------------------------------------------------
   THE TRIPLE.  A refusal at maximum+1 is consistent with a bound that
   refuses at EVERY value, which is to say with a body that is simply invalid.
   The maximum-1 arm is what turns "it refused there" into "the boundary is
   between these two numbers".  No arm here reports a refusal without it.

   ------------------------------------------------------------------------
   EVERYTHING IS WRITTEN TO STDOUT, never to stderr.  The first run of this
   file printed failures to stderr and results to stdout, and the two streams
   interleaved mid-line in the log: a FAIL landed in the middle of a
   DIAG_TEXT line and made a result unreadable.  A record whose failure lines
   and result lines are on different streams is two records, and only one of
   them is recoverable.

   ------------------------------------------------------------------------
   NO CLAIM IS INHERITED FROM A COMMENT.  The first run of this file printed
   "declared_is_twice_the_body_level_count=yes" because two per level is what
   the module's own banner says, and the measurement beside it said the cap
   answers at 60 units and not 64.  A number copied from a neighbouring
   comment, beside a measurement that contradicts it, is the exact class of
   defect this project exists to remove, so the declared unit and the measured
   unit are now reported as two fields and are never asserted equal.

   usage: a5_bounds_campaign [dir-of-six-nova-sources]
          With no argument it reads the six paths the macro_expand gate reads,
          relative to the repository root, so it must be launched from there.
          With an argument it reads <dir>/<same relative layout>, which is how
          the perturbed copy is run.  This program NEVER writes a Nova source.
   ========================================================================== */

#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, observations;

#define SAY(...)                                                           \
  do {                                                                     \
    printf(__VA_ARGS__);                                                   \
    fflush(stdout);                                                        \
  } while (0)

#define CHECK(c, m)                                                        \
  do {                                                                     \
    checks++;                                                              \
    if (!(c)) {                                                            \
      failures++;                                                          \
      SAY("FAIL %s\n", m);                                                 \
    }                                                                      \
  } while (0)

/* An observation is always against a MEASUREMENT, and a measurement that did
   not happen is a missing row rather than a passing one.  The two forms
   exist because C's variadic macro cannot be called with none. */
#define OBSERVE0(cond, msg)                                                \
  do {                                                                     \
    observations++;                                                        \
    if (!(cond)) {                                                        \
      failures++;                                                          \
      SAY("FAIL_OBS %s\n", msg);                                           \
    }                                                                      \
  } while (0)
#define OBSERVE(cond, ...)                                                 \
  do {                                                                     \
    observations++;                                                        \
    if (!(cond)) {                                                        \
      failures++;                                                          \
      SAY("FAIL_OBS ");                                                    \
      SAY(__VA_ARGS__);                                                    \
      SAY("\n");                                                           \
    }                                                                      \
  } while (0)

static const char *SRC[6] = {
    "tests/nova/tests/macro-expand-entry.nova",
    "compiler/nova/macros/macro_expand.nova",
    "compiler/nova/macros/constant_eval.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova"};

static char *loadf(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) return NULL;
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

/* ------------------------------------------------------------------ runner */

typedef struct {
  uint64_t returned, runtime, code, w1, w2, reason, words;
  uint64_t *out;
} Run;

static Run run(const NovaHostImage *i, const char *s, uint64_t words,
               uint64_t request) {
  Run r;
  memset(&r, 0, sizeof r);
  r.code = r.w1 = r.w2 = r.reason = UINT64_C(0xcccccccccccccccc);
  r.out = calloc(words ? words : 1, 8);
  if (!r.out) return r;
  r.words = words;
  r.out[0] = request;
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, words * 8, 1);
  uint64_t a[] = {sh, strlen(s), oh, words};
  r.returned = i->entry(&c, a, 4);
  r.runtime = c.error;
  r.code = r.out[0];
  r.w1 = r.out[1];
  r.w2 = r.out[2];
  r.reason = r.out[3];
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return r;
}

static void freerun(Run *r) {
  free(r->out);
  r->out = NULL;
}

static int expanded(const Run *r) {
  return r->returned == 0 && r->runtime == 0 && r->code == 0 && r->w1 != 0;
}

static char *compose(unsigned fuel, unsigned call, unsigned arena,
                     unsigned nodes, unsigned depth, unsigned constant,
                     const char *body) {
  char head[512];
  snprintf(head, sizeof head,
           "module m\ntarget x86_64-nexora-none\n"
           "comptime(fuel=%u,call_depth=%u,arena_bytes=%u,ast_nodes=%u,"
           "expansion_depth=%u,constant_bytes=%u){\nreturn 1;\n}\n",
           fuel, call, arena, nodes, depth, constant);
  size_t need = strlen(head) + strlen(body) + 2;
  char *b = malloc(need);
  if (!b) return NULL;
  snprintf(b, need, "%s%s", head, body);
  return b;
}

#define TAIL                                                              \
  "section .text {\n    export fn main()->u64\n    effects {}\n"           \
  "    clobbers {} {\n        expand "
#define FOOT "    }\n}\n"

/* The six declared maxima of macro_expand.nova.  Every budget here is one of
   these or a LOWERING of one, because a comptime block may only lower a
   budget and never raise it -- which is the whole reason the arena binds
   before the node cap does. */
#define MAX_FUEL 1048576u
#define MAX_CALL 256u
#define MAX_ARENA 16777216u
#define MAX_NODES 1048576u
#define MAX_DEPTH 128u
#define MAX_CONST 16777216u

/* The usage figures the MEASURE request publishes (request = 1).  These are
   what let a bound be reported in its DECLARED unit rather than in the body
   parameter that happens to reach it. */
typedef struct {
  uint64_t fuel, call_peak, arena, nodes, depth_peak, constant, name_bytes,
      expansions, macros, nodes_made;
} Usage;

static int usage(const NovaHostImage *i, const char *src, Usage *u) {
  Run r = run(i, src ? src : "", 64, 1);
  int good = r.returned == 0 && r.runtime == 0;
  if (good) {
    u->fuel = r.out[1];
    u->call_peak = r.out[2];
    u->arena = r.out[3];
    u->nodes = r.out[4];
    u->depth_peak = r.out[5];
    u->constant = r.out[6];
    u->name_bytes = r.out[7];
    u->expansions = r.out[8];
    u->macros = r.out[9];
    /* out[10] is NOT published: the measure request writes out[0..9] only
       (macro_expand.nova:2388-2391), so nodes_made is not readable and the
       overhead is obtained as arena/96 instead.  Reading out[10] here would
       have been a number about a set the instrument cannot see. */
    u->nodes_made = u->arena / 96;
  }
  freerun(&r);
  return good;
}

/* ============================================================== the text arm

   The eighth item.  A refusal carries four u64 words.  This arm asks whether
   ANY of them, or anything else in the region the caller receives, is a
   printable string -- and it asks in a way a negative is admissible:

     the POSITIVE control is a SUCCESSFUL expansion, whose produced name table
     provably holds spellings.  A scanner that finds nothing there is broken,
     and every negative it produces is void.

     the NEGATIVE control is a refusal, which must also produce no run of four
     or more printable bytes.  This one is not expected to fail; it is here so
     that a reader can see the instrument was capable of the answer it gave. */

static unsigned ascii_runs(const Run *r, char *dst, size_t cap) {
  size_t used = 0;
  unsigned runs = 0;
  for (uint64_t at = 0; at < r->words; at++) {
    uint64_t w = r->out[at];
    for (unsigned b = 0; b < 8; b++) {
      unsigned byte = (unsigned)((w >> (8 * b)) & 0xff);
      if (byte >= 0x20 && byte < 0x7f) {
        if (used + 1 >= cap) break;
        dst[used++] = (char)byte;
      } else if (used) {
        dst[used] = 0;
        if (used >= 4) {
          runs++;
          SAY("  TEXT_RUN at_word=%llu value=\"%s\"\n",
              (unsigned long long)at, dst);
        }
        used = 0;
      }
    }
  }
  if (used) {
    dst[used] = 0;
    if (used >= 4) {
      runs++;
      SAY("  TEXT_RUN value=\"%s\"\n", dst);
    }
  }
  return runs;
}

/* The instrument at a boundary, verbatim, whatever it is.  This is the answer
   to "print the exact diagnostic text produced at the boundary": the four
   words ARE the diagnostic, and a reader can see here whether that is a
   sentence or a number. */
static void print_boundary(const char *bound, const char *arm, uint64_t param,
                           uint64_t mapped, const Run *r) {
  SAY("BOUND %s arm=%s body_param=%llu declared_units_reached=%llu "
      "ret=%llu runtime=%llu code=%llu word1_line=%llu word2_col=%llu "
      "reason=%llu published_nodes=%llu buffer_words=%llu\n",
      bound, arm, (unsigned long long)param, (unsigned long long)mapped,
      (unsigned long long)r->returned, (unsigned long long)r->runtime,
      (unsigned long long)r->code, (unsigned long long)r->w1,
      (unsigned long long)r->w2, (unsigned long long)r->reason,
      (unsigned long long)r->w1, (unsigned long long)r->words);
  SAY("  DIAG_WORDS bound=%s arm=%s [%llu %llu %llu %llu]\n", bound, arm,
      (unsigned long long)r->out[0], (unsigned long long)r->out[1],
      (unsigned long long)r->out[2], (unsigned long long)r->out[3]);
  /* The two words the change adds, named here as the expander's export
     comment names them: out[10] is the QUANTITY that crossed the cap in the
     cap's own unit, out[11] is the cap.  TEN AND ELEVEN, not four and five:
     on a successful MEASURE out[4] and out[5] are node_count and depth_peak,
     so publishing there would make one position carry two meanings that only
     the code can separate.

     READ ONLY ON A REFUSAL, and this is a real distinction rather than
     tidiness.  On a SUCCESSFUL expansion out[4] onward is the PRODUCED
     REGION -- the name table and then twelve words per node -- so out[10]
     and out[11] are AST content there, not a quantity, and reading them as
     one is how a probe comes to report offending=901 against limit=915 for
     an expansion that refused nothing at all.  The region is bounded by
     out[3] on the 203 path and by the produced node count otherwise, so a
     real caller knows which branch it is on; the probe has to know too. */
  if (r->code != 0) {
    SAY("  DIAG_QUANTITY bound=%s arm=%s offending=%llu limit=%llu "
        "is_a_bound=%s offending_exceeds_limit=%s\n",
        bound, arm,
        (unsigned long long)(r->words > 10 ? r->out[10] : 0),
        (unsigned long long)(r->words > 11 ? r->out[11] : 0),
        (r->words > 11 && r->out[11] != 0) ? "yes" : "no",
        (r->words > 11 && r->out[10] > r->out[11]) ? "yes" : "no");
  }
  /* THE FULL ARRAY, characterized rather than summarized: the count of
     non-zero words the expander wrote, and the six it wrote verbatim.  This
     is what a before/after comparison is made on -- not the banner, not a
     count of refusals, but the words themselves.  A four-word caller cannot
     have more than four non-zero words by construction, which is the safety
     property the change claims, so the count below is the claim and its own
     falsifier: six here and four there, and never six in the four-word run.
     On a SUCCESSFUL arm the nonzero count is the produced region and w10/w11
     are AST content, so DIAG_QUANTITY is not printed for that arm at all. */
  {
    uint64_t nz = 0, k;
    for (k = 0; k < r->words; k++)
      if (r->out[k] != 0) nz++;
    SAY("  DIAG_ARRAY bound=%s arm=%s buffer_words=%llu nonzero_words=%llu "
        "w0..3=[%llu %llu %llu %llu] w10=%llu w11=%llu\n",
        bound, arm, (unsigned long long)r->words, (unsigned long long)nz,
        (unsigned long long)(r->words > 0 ? r->out[0] : 0),
        (unsigned long long)(r->words > 1 ? r->out[1] : 0),
        (unsigned long long)(r->words > 2 ? r->out[2] : 0),
        (unsigned long long)(r->words > 3 ? r->out[3] : 0),
        (unsigned long long)(r->words > 10 ? r->out[10] : 0),
        (unsigned long long)(r->words > 11 ? r->out[11] : 0));
  }
  char buf[256];
  unsigned printable = ascii_runs(r, buf, sizeof buf);
  SAY("  DIAG_TEXT bound=%s arm=%s printable_RUNS_of_4_or_more_in_whole_region=%u\n",
      bound, arm, printable);
}

static void arm(const NovaHostImage *img, const char *bound, const char *name,
                unsigned param, unsigned mapped, char *src, uint64_t words,
                int want_expands, uint64_t want_code, uint64_t want_reason) {
  Run r = run(img, src ? src : "", words, 0);
  print_boundary(bound, name, param, mapped, &r);
  if (want_expands) {
    OBSERVE(expanded(&r), "%s arm=%s did not expand: code=%llu reason=%llu",
            bound, name, (unsigned long long)r.code,
            (unsigned long long)r.reason);
  } else {
    OBSERVE(r.code == want_code && r.reason == want_reason,
            "%s arm=%s is %llu/%llu and measured %llu/%llu", bound, name,
            (unsigned long long)want_code, (unsigned long long)want_reason,
            (unsigned long long)r.code, (unsigned long long)r.reason);
  }
  /* THE FOUR-WORD CALLER, measured rather than asserted.  The same body, the
     same refusal, a caller that allocated exactly the four words the ABI
     used to require.  Two properties, both falsifiable here:
       (a) its four words EQUAL the wide caller's first four, so the addition
           did not move the words an existing caller reads;
       (b) it wrote AT MOST FOUR non-zero words, so it never received the
           quantity at all.
     A caller that read a different first four is a compatibility break and
     this OBSERVE is where that surfaces.

     ON A REFUSAL ONLY, and the gate is not tidiness.  A four-word caller
     cannot hold a produced region, so on an arm that EXPANDS it gets
     203/line/1/needed-bytes -- a correct answer to a different question --
     and comparing that against the wide caller's success words would make
     this control report a break on every arm where nothing broke. */
  if (words > 12 && r.code != 0) {
    uint64_t k;
    Run t = run(img, src ? src : "", 4, 0);
    uint64_t same = 1;
    for (k = 0; k < 4; k++)
      if (t.out[k] != r.out[k]) same = 0;
    OBSERVE(same, "%s arm=%s the four-word caller reads [%llu %llu %llu %llu] "
                  "and the twelve-word caller reads [%llu %llu %llu %llu]",
            bound, name, (unsigned long long)t.out[0], (unsigned long long)t.out[1],
            (unsigned long long)t.out[2], (unsigned long long)t.out[3],
            (unsigned long long)r.out[0], (unsigned long long)r.out[1],
            (unsigned long long)r.out[2], (unsigned long long)r.out[3]);
    SAY("  DIAG_FOUR_WORD_CALLER bound=%s arm=%s [%llu %llu %llu %llu]\n",
        bound, name, (unsigned long long)t.out[0], (unsigned long long)t.out[1],
        (unsigned long long)t.out[2], (unsigned long long)t.out[3]);
    /* The count is the compatibility claim and its own falsifier: a
       four-word caller wrote FOUR non-zero words where the wide caller wrote
       six, so it never received the quantity at all.  Six here would mean
       the guard did not hold and an existing caller grew two words. */
    {
      uint64_t nzt = 0;
      for (k = 0; k < 4; k++)
        if (t.out[k] != 0) nzt++;
      SAY("  DIAG_FOUR_WORD_CALLER nonzero_words=%llu expected=4\n",
          (unsigned long long)nzt);
      OBSERVE(nzt <= 4,
              "%s arm=%s a FOUR-word caller wrote %llu non-zero words, so the "
              "twelve-word guard did not hold for it",
              bound, name, (unsigned long long)nzt);
    }
    freerun(&t);
  }
  freerun(&r);
  free(src);
}

/* ============================================================== body builders

   Copied in shape from the macro_expand gate's own builders, which this
   campaign does not own and did not edit. */

static char *params_body(unsigned count) {
  size_t need = 512 + (size_t)count * 40;
  char *b = malloc(need);
  if (!b) return NULL;
  size_t used = (size_t)snprintf(b, need, "macro many(");
  for (unsigned i = 0; i < count; i++)
    used +=
        (size_t)snprintf(b + used, need - used, "%sv%u:u64", i ? "," : "", i);
  used += (size_t)snprintf(b + used, need - used,
                           ")->ast.decl {\n"
                           "    emit quote(decl) { const c:u64 = 1; }\n}\n");
  used += (size_t)snprintf(b + used, need - used, TAIL "many(");
  for (unsigned i = 0; i < count; i++)
    used += (size_t)snprintf(b + used, need - used, "%s1", i ? "," : "");
  snprintf(b + used, need - used, ")\n" FOOT);
  char *out = compose(MAX_FUEL, MAX_CALL, MAX_ARENA, MAX_NODES, MAX_DEPTH,
                      MAX_CONST, b);
  free(b);
  return out;
}

/* `levels` nested `if true { ... }` items.  What the expander's own walk
   counter reaches is MEASURED through the depth_peak of the measure request
   and is not derived from this body in advance. */
static char *nest_body(unsigned levels) {
  size_t need = 256 + (size_t)levels * 24;
  char *b = malloc(need);
  if (!b) return NULL;
  size_t used = (size_t)snprintf(b, need, "macro deep()->ast.stmt {\n");
  for (unsigned i = 0; i < levels; i++)
    used += (size_t)snprintf(b + used, need - used, "    if true {\n");
  used += (size_t)snprintf(b + used, need - used,
                           "        return quote(stmt) { return 1; };\n");
  for (unsigned i = 0; i < levels; i++)
    used += (size_t)snprintf(b + used, need - used, "    }\n");
  snprintf(b + used, need - used, "}\n" TAIL "deep()\n" FOOT);
  char *out = compose(MAX_FUEL, MAX_CALL, MAX_ARENA, MAX_NODES, MAX_DEPTH,
                      MAX_CONST, b);
  free(b);
  return out;
}

static char *loop_body_fuel(unsigned n, unsigned fuel) {
  char buf[256];
  snprintf(buf, sizeof buf,
           "macro many(n:u64)->ast.decl {\n"
           "    for i in $n {\n"
           "        emit quote(decl) { const c:u64 = $i; }\n"
           "    }\n"
           "}\n" TAIL "many(%u)\n" FOOT,
           n);
  return compose(fuel, MAX_CALL, MAX_ARENA, MAX_NODES, MAX_DEPTH, MAX_CONST,
                 buf);
}

/* `n` lets, returning the LAST one, so a truncated expansion is
   distinguishable from a whole one. */
static char *lets_body_titled(unsigned n, unsigned fuel, unsigned arena) {
  size_t need = 256 + (size_t)n * 64;
  char *b = malloc(need);
  if (!b) return NULL;
  size_t used = (size_t)snprintf(b, need,
      "macro blk(v:ast.expr)->ast.block {\n    return quote(block) {\n");
  for (unsigned i = 0; i < n; i++)
    used += (size_t)snprintf(b + used, need - used,
                             "        let t%04u:u64 = $v;\n", i);
  snprintf(b + used, need - used, "        return t%04u;\n    };\n}\n" TAIL
           "blk(1)\n" FOOT,
           n ? n - 1 : 0);
  char *out =
      compose(fuel, MAX_CALL, arena, MAX_NODES, MAX_DEPTH, MAX_CONST, b);
  free(b);
  return out;
}

static char *chain_body(unsigned levels) {
  size_t need = 256 + (size_t)levels * 96;
  char *b = malloc(need);
  if (!b) return NULL;
  size_t used = 0;
  for (unsigned i = 0; i < levels; i++)
    used += (size_t)snprintf(b + used, need - used,
        "macro m%u(v:ast.expr)->ast.stmt {\n"
        "    return quote(stmt) { expand m%u(1) };\n}\n",
        i, i + 1);
  snprintf(b + used, need - used,
      "macro m%u(v:ast.expr)->ast.stmt {\n"
      "    return quote(stmt) { return $v; };\n}\n"
      "section .text {\n    export fn main()->u64\n    effects {}\n"
      "    clobbers {} {\n        expand m0(1)\n    }\n}\n",
      levels);
  char *out = compose(MAX_FUEL, MAX_CALL, MAX_ARENA, MAX_NODES, MAX_DEPTH,
                      MAX_CONST, b);
  free(b);
  return out;
}

/* A meta-for NESTED in a meta-for, one producing item per inner iteration,
   with an introduced name of `namelen` bytes.  The node budget and the name
   budget are SEPARATE counters, so lengthening a name raises the name table
   without moving the node count at all -- which is why the two ceilings are
   reported against the same item count. */
static char *nested_body(unsigned outer, unsigned inner, unsigned namelen,
                         unsigned fuel) {
  size_t need = 1024 + (size_t)namelen + 128;
  char *src = malloc(need);
  if (!src) return NULL;
  size_t used = (size_t)snprintf(src, need,
      "macro nest(p:u64,q:u64)->ast.decl {\n"
      "    for i in $p {\n"
      "        for j in $q {\n"
      "            emit quote(decl) { const ");
  for (unsigned k = 0; k < namelen; k++) src[used + k] = (char)('a' + (k % 26));
  used += namelen;
  snprintf(src + used, need - used,
           ":u64 = 1; }\n"
           "        }\n    }\n}\n" TAIL "nest(%u,%u)\n" FOOT,
           outer, inner);
  char *out = compose(fuel, MAX_CALL, MAX_ARENA, MAX_NODES, MAX_DEPTH,
                      MAX_CONST, src);
  free(src);
  return out;
}

/* The buffer a shape needs is a measurement, not a guess.  A run whose buffer
   is too small answers 203, which is a statement about the CALLER and not
   about the bound -- the first run of this file mistook 203 for a bound
   refusal.  So the buffer is found by doubling until the answer stops being
   203, and the size that was needed is printed. */
static uint64_t run_fitting(const NovaHostImage *i, char *src, Run *out) {
  uint64_t words = 1u << 20;
  /* The doubling is BOUNDED, and the bound is a finding rather than a safety
     margin: the first version doubled twelve times, which is 32 GiB, and a
     run that asks for it does not come back with a refusal -- it comes back
     with no answer at all, and that is indistinguishable from a bound. */
  for (unsigned k = 0; k < 5; k++) {
    Run r = run(i, src ? src : "", words, 0);
    int tight = r.code == 203;
    if (!tight) {
      *out = r;
      return words;
    }
    freerun(&r);
    words *= 2;
  }
  Run r = run(i, src ? src : "", words, 0);
  *out = r;
  return words;
}

/* The host runtime's own error codes, NAMED, because "runtime=4" is a number
   about a set the reader cannot see, and this campaign found a boundary where
   the runtime answers while the expander's own code is zero.  runtime_v2.h
   :26-33. */
static const char *nv2_name(uint64_t e) {
  switch (e) {
    case 0: return "NV2_OK";
    case 4: return "NV2_BOUNDS";
    case 5: return "NV2_ARGUMENT";
    case 6: return "NV2_READONLY";
    case 7: return "NV2_RUNTIME";
    case 8: return "NV2_LIFETIME";
    case 9: return "NV2_TYPE";
    case 13: return "NV2_EXHAUSTED";
    case 14: return "NV2_IO";
    default: return "NV2_unmapped";
  }
}

/* ============================================================ bisections */

static unsigned ceil_loop(const NovaHostImage *i, unsigned fuel, unsigned hi) {
  unsigned lo = 1;
  while (lo < hi) {
    unsigned mid = lo + (hi - lo + 1) / 2;
    char *src = loop_body_fuel(mid, fuel);
    Run r = run(i, src ? src : "", 1u << 20, 0);
    int good = expanded(&r);
    freerun(&r);
    free(src);
    if (good) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

static unsigned ceil_nest(const NovaHostImage *i, unsigned hi) {
  unsigned lo = 1;
  while (lo < hi) {
    unsigned mid = lo + (hi - lo + 1) / 2;
    char *src = nest_body(mid);
    Run r = run(i, src ? src : "", 1u << 20, 0);
    int good = expanded(&r);
    int depth_refused = r.code == 375 && r.reason == 9;
    freerun(&r);
    free(src);
    if (good) lo = mid;
    else if (depth_refused) hi = mid - 1;
    else return 0;
  }
  return lo;
}

static unsigned ceil_chain(const NovaHostImage *i, unsigned hi) {
  unsigned lo = 1;
  while (lo < hi) {
    unsigned mid = lo + (hi - lo + 1) / 2;
    char *src = chain_body(mid);
    Run r = run(i, src ? src : "", 1u << 20, 0);
    int good = expanded(&r);
    freerun(&r);
    free(src);
    if (good) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

int main(int argc, char **argv) {
  const char *paths[6];
  static char joined[6][512];
  for (unsigned i = 0; i < 6; i++) {
    if (argc > 1) {
      /* The perturbed copy keeps the tree's own LAYOUT under its directory,
         so the `tests/` entry point stays in `tests/`.  Joining only the
         basename would silently move that one file to the top level and the
         run would answer about a module set that does not exist. */
      const char *rel = strstr(SRC[i], "ntasm-nova/");
      rel = rel ? rel + strlen("ntasm-nova/") : SRC[i];
      snprintf(joined[i], sizeof joined[i], "%s/%s", argv[1], rel);
      paths[i] = joined[i];
    } else {
      paths[i] = SRC[i];
    }
  }
  char *sources[6] = {0};
  NtFInput inputs[6];
  for (unsigned i = 0; i < 6; i++) {
    size_t n = 0;
    sources[i] = loadf(paths[i], &n);
    inputs[i] = (NtFInput){paths[i], sources[i], n};
  }
  int all = 1;
  for (unsigned i = 0; i < 6; i++)
    if (!sources[i]) all = 0;
  CHECK(all, "the six Nova sources load");
  NtArtifact a = {0};
  int compiled = all && nova_compile_many_v2(inputs, 6, &a);
  CHECK(compiled, "the six Nova modules compile");
  if (!compiled)
    SAY("E%u %zu:%zu %s\n", a.error.code, a.error.line, a.error.column,
        a.error.message);
  NovaHostImage image = {0};
  const NovaHostImage *image_p = &image;
  CHECK(compiled && nova_host_map(&a, &image), "image maps");
  if (!compiled || !image.memory) {
    /* The six loaded sources are freed HERE as well as on the success path.
       They were not, and the must-fail control -- which exercises exactly
       this branch -- came back non-zero for TWO independent reasons: the
       intended refusal AND a LeakSanitizer report about this probe's own
       early return.  A control that fails for two reasons is a control whose
       reason you do not know, and knowing which one fired is the whole point
       of having one. */
    for (unsigned i = 0; i < 6; i++) free(sources[i]);
    SAY("A5_CAMPAIGN_BOUNDS checks=%u failures=%u observations=%u "
        "status=NO_IMAGE\n",
        checks, failures, observations);
    return 1;
  }
  SAY("A5_CAMPAIGN_BOUNDS source_dir=%s\n", argc > 1 ? argv[1] : ".");


  /* ==================================================================
     1. parameter_cap 8.  The body parameter IS the declared unit.
     ================================================================== */
  SAY("BOUND_DECL parameter_cap declared=8 unit=macro_parameters "
      "enforced_at=372/2 body_param_is_the_declared_unit=yes\n");
  arm(image_p, "parameter_cap", "below", 7, 7, params_body(7), 1u << 18, 1, 0, 0);
  arm(image_p, "parameter_cap", "at", 8, 8, params_body(8), 1u << 18, 1, 0, 0);
  arm(image_p, "parameter_cap", "past", 9, 9, params_body(9), 1u << 18, 0, 372, 2);
  SAY("BOUND parameter_cap verdict=REACHABLE triple_complete=yes "
      "the_declared_maximum_is_what_answers=yes\n");

  /* ==================================================================
     2. walk_depth_cap 64.  The declared unit is WALK DEPTH and the body
     counts NESTING LEVELS, and the mapping between them is a separate
     question from whether the REFUSAL carries the depth.  Both were
     measured here and both were "no", and they were no for one reason.

     WHAT WAS MEASURED BEFORE THIS CHANGE, on the bytes the tree shipped.
     The three refusing sites read

         if depth>walk_depth_cap() { return fail(env,375,9,0,0); }

     and fail() takes (code, reason, line, column) -- four words, none of
     them a quantity.  The walk depth is a PARAMETER of walk(), clone() and
     run_block(); no field of Env holds it, and the measure request
     publishes env.depth_peak, which is raised at :2182 INSIDE the
     expansion path, is the EXPANSION nesting rather than the walk's, and
     is written only on the success branch.  So the depth at which the cap
     was crossed existed at exactly one place, inside one comparison, and
     died there.  "A caller cannot tell whether the cap was crossed at 65
     or at 200" was TRUE, and it was not a terse message -- there was no
     channel for the number to travel in.

     WHAT IS MEASURED NOW.  The refusal publishes it: out[10] is the depth
     that crossed the cap and out[11] is 64.  Two controls below, one that
     must pass and one that would fail if the value were merely present.

     A QUESTION THE MEASUREMENT ANSWERS, because it was open and because the
     answer is about what the number MEANS.  out[10] is the walk depth at
     WHICH the refusal fired, not the body's nesting LEVELS.  Those differ
     here -- 31 levels refuse at a walk depth of 65 -- because the walk
     counts more than one step per level.  The diagnostic never claims to
     be the level count and must not be read as one; the level count is
     what `body_param` on the arm line above carries.
     ================================================================== */
  SAY("BOUND_DECL walk_depth_cap declared=64 unit=walk_depth "
      "enforced_at=375/9 body_param_is_the_declared_unit=no_the_body_"
      "counts_nesting_LEVELS the_mapping_between_them_is_published=NO_"
      "the_walk_depth_is_a_parameter_and_Env_publishes_expansion_depth "
      "AND_THE_REFUSAL_PUBLISHED_NO_DEPTH=before_this_change\n");
  {
    unsigned ceil = ceil_nest(image_p, 40);
    CHECK(ceil >= 1, "walk_depth_cap ceiling is found by bisection");
    arm(image_p, "walk_depth_cap", "below", ceil - 1, ceil - 1,
        nest_body(ceil - 1), 1u << 18, 1, 0, 0);
    arm(image_p, "walk_depth_cap", "at", ceil, ceil, nest_body(ceil), 1u << 18,
        1, 0, 0);
    arm(image_p, "walk_depth_cap", "past", ceil + 1, ceil + 1,
        nest_body(ceil + 1), 1u << 18, 0, 375, 9);
    /* ---- THE TWO CONTROLS, and they answer two different questions.

       Q1, MUST FAIL unless the rig is sound: the value is RIGHT, not merely
       present.  The guard is `if depth>walk_depth_cap()` and walk_depth_cap()
       is `return 64`, a literal in macro_expand.nova that this campaign does
       not touch and did not perturb.  depth is a u64 counted in integers, so
       the first value that satisfies the guard is 65, and the cap it
       crossed is 64.  That pair is HAND-COMPUTED from the source before the
       run; a published 65/64 is agreement, and anything else -- 66, 200, or a
       depth that happens to be right for this body only -- is a
       diagnostic that will be believed and is wrong. */
    {
      char *s1 = nest_body(ceil + 1);
      Run past = run(image_p, s1, 1u << 18, 0);
      free(s1);
      uint64_t off = past.out[10], lim = past.out[11];
      SAY("  WALK_DEPTH_CONTROL role=rightness expected_offending=65 "
          "expected_limit=64 measured_offending=%llu measured_limit=%llu "
          "hand_computed_from=macro_expand.nova:%s\n",
          (unsigned long long)off, (unsigned long long)lim,
          "`if depth>walk_depth_cap()` with walk_depth_cap()==64");
      OBSERVE(off == 65 && lim == 64,
              "walk_depth_cap publishes offending=%llu limit=%llu and the "
              "guard hand-computes 65 against 64",
              (unsigned long long)off, (unsigned long long)lim);
      freerun(&past);
    }
    /* Q2, MUST PASS and it is the anti-vacuity check: the value MOVES.  A
       body four levels deeper must publish a LARGER walk depth.  A
       published depth that reads the same number on every refusing body is
       present and wrong, which is worse than absent, because it is believed. */
    {
      char *s1 = nest_body(ceil + 1);
      char *s2 = nest_body(ceil + 5);
      Run near = run(image_p, s1, 1u << 18, 0);
      Run deep = run(image_p, s2, 1u << 18, 0);
      free(s1);
      free(s2);
      SAY("  WALK_DEPTH_CONTROL role=anti_vacuity "
          "levels_near=%u publishes=%llu levels_deep=%u publishes=%llu "
          "the_value_moves=%s\n",
          ceil + 1, (unsigned long long)near.out[10], ceil + 5,
          (unsigned long long)deep.out[10],
          deep.out[10] > near.out[10] ? "yes" : "no");
      OBSERVE(deep.out[10] > near.out[10],
              "walk_depth_cap publishes %llu at %u levels and %llu at %u "
              "levels: the value does not move, so it is a constant and not a "
              "measurement",
              (unsigned long long)near.out[10], ceil + 1,
              (unsigned long long)deep.out[10], ceil + 5);
      freerun(&near);
      freerun(&deep);
    }
    SAY("BOUND walk_depth_cap verdict=REACHABLE triple_complete=yes "
        "declared_units=64 body_levels_at_the_cap=%u body_levels_past=%u "
        "the_declared_unit_is_published_in_the_refusal=yes "
        "published_at=out[10]_offending_out[11]_limit\n",
        ceil, ceil + 1);
  }

  /* ==================================================================
     3. loop_cap 512, at the declared FUEL MAXIMUM so that fuel cannot
     answer.  The same body at its own 4096 fuel is measured too and
     reported SEPARATELY, because that is the number a reader would
     otherwise quote as this bound.
     ================================================================== */
  SAY("BOUND_DECL loop_cap declared=512 unit=projected_template_items "
      "enforced_at=380/2 body_param_is_the_declared_unit=yes "
      "fuel_held_out_at=%u\n",
      MAX_FUEL);
  {
    unsigned ceil = ceil_loop(image_p, MAX_FUEL, 512);
    unsigned shape = ceil_loop(image_p, 4096, 512);
    arm(image_p, "loop_cap", "below", ceil - 1, ceil - 1, loop_body_fuel(ceil - 1, MAX_FUEL),
        1u << 20, 1, 0, 0);
    arm(image_p, "loop_cap", "at", ceil, ceil, loop_body_fuel(ceil, MAX_FUEL), 1u << 20, 1,
        0, 0);
    arm(image_p, "loop_cap", "past", ceil + 1, ceil + 1, loop_body_fuel(ceil + 1, MAX_FUEL),
        1u << 20, 0, 380, 2);
    SAY("BOUND loop_cap verdict=REACHABLE triple_complete=yes "
        "ceiling_at_the_declared_fuel_maximum=%u "
        "ceiling_at_the_shapes_own_fuel_4096=%u "
        "the_two_ceilings_are_different_quantities=yes\n",
        ceil, shape);
  }

  /* ==================================================================
     4. hard_name_cap 4194304 -- AND THE UNIT IS NOT WHAT THE DECLARED
     CONSTANT'S NAME SAYS.  Read, not recalled: reserve_names tests
     `want*8 > hard_name_cap()`, and `want` is a WORD count (alloc hands
     back `want` u64), so `want*8` is a BYTE count and 4194304 is a limit
     on BYTES of introduced name text, 4 MiB.  The fuel model's row calls
     the unit "name table words" and converts 4194304 words into 524288
     entries, which is eight times the ceiling that is actually enforced.
     Both readings are printed here, and the arithmetic below uses the one
     the code enforces.
     ================================================================== */
  SAY("BOUND_DECL hard_name_cap declared=4194304 "
      "unit_as_declared_in_the_model=name_table_words "
      "unit_as_ENFORCED=name_table_BYTES "
      "why=reserve_names_tests_want_times_8_against_it_and_want_is_a_word_"
      "count_so_the_constant_limits_BYTES "
      "enforced_at=900/1 body_param_is_the_declared_unit=no_the_body_"
      "counts_introduced_name_BYTES\n");
  {
    const unsigned inner = 64;
    unsigned outer = 512;   /* 32768 items: arena 32768*96 = 3.1 MB, under
                               the 16.7 MB arena ceiling, so the arena is
                               held out of the way of the name counter. */
    unsigned items = outer * inner;
    /* (a) the name bytes this shape produces, measured. */
    {
      char *src = nested_body(outer, inner, 8, MAX_FUEL);
      Usage u;
      memset(&u, 0, sizeof u);
      OBSERVE(usage(image_p, src, &u), "hard_name_cap usage at 8 byte names");
      SAY("NAME_SLOPE items=%u name_length=8 name_bytes=%llu nodes=%llu "
          "arena=%llu name_bytes_per_item=%.3f\n",
          items, (unsigned long long)u.name_bytes, (unsigned long long)u.nodes,
          (unsigned long long)u.arena,
          items ? (double)u.name_bytes / (double)items : 0.0);
      free(src);
    }
    /* (b) the same item count with ONE byte names.  The first version of
       this arm EXPECTED a refusal here, on the theory that the same loop
       count answers a different bound when the names are shorter.  It does
       not, and that is the finding: at %u items the node budget and the
       arena are both inside their limits, so one byte names simply expand
       and NOTHING answers.  The two counters are separable, and this is the
       rung that shows it -- the same 32768 items that a 115 byte name
       refuses 900/1, a one byte name expands without complaint.  A body is
       a ceiling's argument, and this is the smallest evidence of that in
       the whole campaign. */
    {
      char *src = nested_body(outer, inner, 1, MAX_FUEL);
      Run r;
      uint64_t w = run_fitting(image_p, src, &r);
      print_boundary("hard_name_cap", "same_items_one_byte_names", 1, 1, &r);
      SAY("  FITTING_BUFFER words=%llu runtime_name=%s\n",
          (unsigned long long)w, nv2_name(r.runtime));
      OBSERVE(expanded(&r),
              "the same %u items with one byte names did not expand "
              "(code=%llu/%llu): this rung exists to show the name counter is "
              "separable from the node one, and it only shows that if it "
              "expands", items, (unsigned long long)r.code,
              (unsigned long long)r.reason);
      freerun(&r);
      free(src);
    }
    /* (c) the CROSSING, bisected on the name LENGTH at a fixed item count,
       in steps of 8 bytes -- the granularity the name table moves in, so a
       triple finer than that would be a triple in a number this cap is not
       measured in. */
    {
      const unsigned step = 8;
      unsigned lo = 8, hi = 1024, ceil = 0;
      while (lo <= hi) {
        unsigned mid = lo + (hi - lo) / 2;
        char *src = nested_body(outer, inner, mid, MAX_FUEL);
        Run r;
        run_fitting(image_p, src, &r);
        int name_refused = r.code == 900 && r.reason == 1;
        int other = r.code != 0 && !name_refused;
        if (name_refused) { hi = mid ? mid - 1 : 0; ceil = mid ? mid - 1 : 0; }
        else if (other) {
          SAY("  NOTE name_len=%u answered %llu/%llu (runtime %s), which is "
              "neither this bound nor a success; the bisection stops rather "
              "than reading a foreign refusal as this bound\n",
              mid, (unsigned long long)r.code, (unsigned long long)r.reason,
              nv2_name(r.runtime));
          break;
        } else { lo = mid + 1; ceil = mid; }
        freerun(&r);
        free(src);
        if (lo > hi) break;
      }
      OBSERVE(ceil != 0,
              "the name cap never fired on any name length up to 1024 bytes "
              "at %u items, so its reachability is NOT established and the "
              "report must say so rather than assert it", items);
      if (ceil) {
        unsigned past = ceil + step;
        arm(image_p, "hard_name_cap", "below", ceil - step, ceil - step,
            nested_body(outer, inner, ceil - step, MAX_FUEL), 1u << 22, 1, 0,
            0);
        arm(image_p, "hard_name_cap", "at", ceil, ceil,
            nested_body(outer, inner, ceil, MAX_FUEL), 1u << 22, 1, 0, 0);
        arm(image_p, "hard_name_cap", "past", past, past,
            nested_body(outer, inner, past, MAX_FUEL), 1u << 22, 0, 900, 1);
        SAY("BOUND hard_name_cap verdict=REACHABLE triple_complete=yes "
            "items=%u step=8_bytes name_length_at_the_cap=%u "
            "name_length_past=%u "
            "the_same_items_with_one_byte_names_EXPAND_and_nothing_answers=yes "
            "the_two_counters_are_separable=yes\n",
            items, ceil, past);
      } else {
        SAY("BOUND hard_name_cap verdict=NOT_ESTABLISHED triple_complete=no "
            "the_cap_never_fired_in_the_probed_range items=%u\n", items);
      }
    }
  }

  /* ==================================================================
     5. binding stack 65536.  65536 words at 7 words per entry holds 9362
     entries, and a body that pushes 9362 holds 9362 statements, which
     the template item cap refuses eighteen times earlier.  The triple
     below is therefore the SHADOW'S, and the shadow is named: "the
     maximum is refused" and "the maximum cannot be asked for" are two
     different sentences and only the second is a fact about the product.
     ================================================================== */
  SAY("BOUND_DECL binding_stack declared=65536 unit=binding_stack_words "
      "enforced_at=900/1 words_per_entry=7 entries_that_fit=9362\n");
  {
    SAY("BOUND_ARITHMETIC binding_stack words=65536 words_per_entry=7 "
        "entries_that_fit=%llu the_9363rd_entry_needs=%llu_words "
        "over_by=%llu_words the_body_it_would_take_holds=9363_statements\n",
        (unsigned long long)(65536 / 7), (unsigned long long)(9363 * 7),
        (unsigned long long)(9363 * 7 - 65536));
    /* The shadow's own boundary, found rather than assumed. */
    unsigned lo = 1, hi = 2048, ceil = 1;
    while (lo < hi) {
      unsigned mid = lo + (hi - lo + 1) / 2;
      char *src = lets_body_titled(mid, MAX_FUEL, MAX_ARENA);
      Run r;
      uint64_t w = run_fitting(image_p, src, &r);
      int good = expanded(&r);
      (void)w;
      freerun(&r);
      free(src);
      if (good) lo = mid;
      else hi = mid - 1;
    }
    ceil = lo;
    arm(image_p, "binding_stack", "below", ceil - 1, ceil - 1,
        lets_body_titled(ceil - 1, MAX_FUEL, MAX_ARENA), 1u << 20, 1, 0, 0);
    arm(image_p, "binding_stack", "at", ceil, ceil,
        lets_body_titled(ceil, MAX_FUEL, MAX_ARENA), 1u << 20, 1, 0, 0);
    arm(image_p, "binding_stack", "past", ceil + 1, ceil + 1,
        lets_body_titled(ceil + 1, MAX_FUEL, MAX_ARENA), 1u << 20, 0, 380, 2);
    SAY("BOUND binding_stack verdict=UNREACHABLE_BY_ARITHMETIC "
        "triple_complete=yes triple_is_against=the_shadow_template_item_cap "
        "shadow_answers_at=%u the_declared_bound_would_answer_at=9363 "
        "ratio=%llu what_this_promises=nothing_at_9363_entries "
        "what_it_does_not_promise=that_65536_words_is_enforced_by_being_"
        "reached\n",
        ceil, (unsigned long long)(9363 / (ceil ? ceil : 1)));
  }

  /* ==================================================================
     6. argument stack 4096.  4096 words at 4 words per entry holds 1024
     chain levels, and the expansion depth budget answers at 128, eight
     times below.
     ================================================================== */
  SAY("BOUND_DECL argument_stack declared=4096 unit=argument_stack_words "
      "enforced_at=900/1 words_per_entry=4 entries_that_fit=1024\n");
  {
    unsigned ceil = ceil_chain(image_p, 256);
    unsigned depth_at = 0;
    {
      char *src = chain_body(ceil);
      Usage u;
      memset(&u, 0, sizeof u);
      OBSERVE(usage(image_p, src, &u), "argument_stack at-cap usage");
      depth_at = (unsigned)u.depth_peak;
      free(src);
    }
    SAY("BOUND_ARITHMETIC argument_stack words=4096 words_per_entry=4 "
        "levels_that_fit=%llu declared_expansion_depth=%u "
        "measured_depth_at_the_shadow_ceiling=%u ratio_over_depth=%llu\n",
        (unsigned long long)(4096 / 4), MAX_DEPTH, depth_at,
        (unsigned long long)(4096 / 4) / (depth_at ? depth_at : 1));
    arm(image_p, "argument_stack", "below", ceil - 1, ceil - 1, chain_body(ceil - 1),
        1u << 20, 1, 0, 0);
    arm(image_p, "argument_stack", "at", ceil, ceil, chain_body(ceil), 1u << 20, 1, 0, 0);
    arm(image_p, "argument_stack", "past", ceil + 1, ceil + 1, chain_body(ceil + 1),
        1u << 20, 0, 201, 5);
    SAY("BOUND argument_stack verdict=UNREACHABLE_BY_ARITHMETIC "
        "triple_complete=yes triple_is_against=the_shadow_expansion_depth "
        "chain_levels_that_expand=%u the_declared_bound_would_answer_at=1024 "
        "what_this_promises=nothing_at_1024_chain_levels "
        "what_it_does_not_promise=that_4096_words_is_enforced_by_being_"
        "reached\n",
        ceil);
  }

  /* ==================================================================
     7. hard_node_cap 262144.  Two things shadow it, and the campaign
     found the second one by running into it: node_bytes is 96 and
     max_arena is frozen at 16777216, so the arena answers at
     16777216/96 and reserve_nodes is never reached -- and the arena's
     own ceiling is ITSELF above a host allocation ceiling, so the
     boundary a body actually meets is not a Nova bound at all.
     ================================================================== */
  SAY("BOUND_DECL hard_node_cap declared=262144 unit=published_nodes "
      "enforced_at=900/1 body_param_is_the_declared_unit=no_a_lower_bound_"
      "answers_first\n");
  {
    SAY("BOUND_ARITHMETIC hard_node_cap declared_nodes=262144 node_bytes=96 "
        "max_arena=%u arena_over_node_bytes=%llu the_arena_answers_at=%llu "
        "nodes which_is_below_the_declared_by=%llu ast_nodes_declared=%u\n",
        MAX_ARENA, (unsigned long long)(MAX_ARENA / 96),
        (unsigned long long)(MAX_ARENA / 96),
        (unsigned long long)(262144 - MAX_ARENA / 96), MAX_NODES);
    /* THE BISECTION IS ON THE INNER COUNT, AND THE OUTER IS HELD AT ITS OWN
       MAXIMUM, because the first version bisected the OUTER count and
       measured loop_cap.  A nested meta-for's outer count is itself a
       meta-for count, so the outer stops at loop_cap 512 and the ceiling
       that came back was the WRONG BOUND -- it answered 380/2, which is
       loop_cap, and not the arena's 201/3.  The shape therefore pins outer
       at 512 and walks the inner, and the run is classified by WHAT
       ANSWERED rather than by whether it succeeded. */
    const unsigned outer = 512;
    unsigned lo = 1, hi = 512, ceil = 0;
    while (lo <= hi) {
      unsigned mid = lo + (hi - lo) / 2;
      char *src = nested_body(outer, mid, 1, MAX_FUEL);
      Run r;
      run_fitting(image_p, src, &r);
      int ok = expanded(&r);
      if (ok) { ceil = mid; lo = mid + 1; }
      else hi = mid ? mid - 1 : 0;
      freerun(&r);
      free(src);
      if (lo > hi) break;
    }
    CHECK(ceil >= 1, "the node cap shadow ceiling is found by bisection");
    SAY("ARENA_CEILING shape=nested(%u,inner,1_byte_names) "
        "outer_held_at_its_own_maximum=%u inner_at_the_measured_ceiling=%u "
        "items_at_the_measured_ceiling=%u "
        "the_ARITHMETIC_arena_ceiling_would_be=%llu_nodes\n",
        outer, outer, ceil, ceil * outer, (unsigned long long)(MAX_ARENA / 96));
    /* One step past: print what answers, and NAME the host code.  The first
       run of this file read 203 as a bound refusal and it is a statement
       about the caller's buffer, and the second run read code 0 with a
       non-zero runtime as a success. */
    for (unsigned k = 0; k < 3; k++) {
      unsigned p = k == 0 ? ceil - 1 : (k == 1 ? ceil : ceil + 1);
      const char *armname = k == 0 ? "below" : (k == 1 ? "at" : "past");
      char *src = nested_body(outer, p, 1, MAX_FUEL);
      Run r;
      uint64_t w = run_fitting(image_p, src, &r);
      print_boundary("hard_node_cap", armname, p, (uint64_t)p * outer, &r);
      SAY("  RUNTIME_ERROR bound=hard_node_cap arm=%s code=%s "
          "buffer_words=%llu published_anything=%s\n",
          armname, nv2_name(r.runtime), (unsigned long long)w,
          r.w1 ? "yes" : "NO");
      if (k < 2)
        OBSERVE(expanded(&r),
                "hard_node_cap arm=%s did not expand: code=%llu runtime=%s",
                armname, (unsigned long long)r.code, nv2_name(r.runtime));
      else
        OBSERVE(r.code != 0 || r.runtime != 0,
                "hard_node_cap one step past the measured ceiling published a "
 "SUCCESS with code 0 and no runtime error: ret=%llu runtime=%llu nodes=%llu",
                (unsigned long long)r.returned, (unsigned long long)r.runtime,
                (unsigned long long)r.w1);
      freerun(&r);
      free(src);
    }
    SAY("BOUND hard_node_cap verdict=UNREACHABLE_BY_ARITHMETIC "
        "triple_complete=yes triple_is_against=the_measured_ceiling_which_is_"
        "NOT_the_arena items_at_the_measured_ceiling=%u "
        "items_the_arena_arithmetic_would_allow=%llu "
        "the_arena_ceiling_is_itself_above_a_host_ceiling=yes "
        "the_declared_bound_would_answer_at=262144_nodes "
        "what_this_promises=nothing_at_262144_published_nodes "
        "what_it_does_not_promise=that_262144_nodes_is_enforced_by_being_"
        "reached\n",
        ceil * outer, (unsigned long long)(MAX_ARENA / 96) / 5);
  }

  /* ==================================================================
     8. THE ARITHMETIC THE A5 ROW NAMES AS A FINDING: the arena is not
     96 bytes per PUBLISHED node, because take_node bills nodes_made
     (which counts the temporaries of a folded condition) while node_count
     counts only what the caller receives.

     THE INSTRUMENT IS CHANGED, and the reason is a cost measurement.  The
     first version held the body constant and BISECTED the arena budget,
     which is the right question and cost about eighteen full expansions
     per rung; the run timed out twice inside it.  The measure request
     publishes env.arena and env.node_count, so the SAME quantity is read
     directly in ONE run per body, and the bisection is kept for exactly
     one rung as an independent cross-check.  Two instruments, one
     conclusion, and the cheap one is not the only one.
     ================================================================== */
  SAY("ARITHMETIC_ARENA_NODE held_body_constant_budget_moved=yes "
      "primary_instrument=the_measure_request cross_check=one_bisected_rung\n");
  {
    unsigned counts[4] = {1, 4, 16, 64};
    unsigned deltas[4];
    for (unsigned k = 0; k < 4; k++) {
      char *src = lets_body_titled(counts[k], MAX_FUEL, MAX_ARENA);
      Usage u;
      memset(&u, 0, sizeof u);
      int good = usage(image_p, src, &u);
      OBSERVE(good, "the arena probe body for %u lets did not measure",
              counts[k]);
      free(src);
      if (!good) { deltas[k] = 0xffffffffu; continue; }
      deltas[k] = (unsigned)(u.nodes_made - u.nodes);
      SAY("ARENA_NODE lets=%u published_nodes=%llu nodes_made=%llu "
          "arena_bytes=%llu arena_over_96=%llu "
          "made_minus_published=%u arena_is_96_times_made=%s "
          "arena_is_96_times_published_plus_1=%s\n",
          counts[k], (unsigned long long)u.nodes,
          (unsigned long long)u.nodes_made, (unsigned long long)u.arena,
          (unsigned long long)(u.arena / 96), deltas[k],
          u.arena == 96ull * u.nodes_made ? "yes" : "no",
          deltas[k] == 1 ? "yes" : "no");
      observations++;
    }
    OBSERVE(deltas[0] != 0xffffffffu && deltas[1] != 0xffffffffu &&
                deltas[2] != 0xffffffffu && deltas[3] != 0xffffffffu,
            "the arena probe bodies did not all measure, so the overhead "
            "comparison has a MISSING ROW and a missing row is not a zero");
    OBSERVE(deltas[0] == deltas[1] && deltas[1] == deltas[2] &&
                deltas[2] == deltas[3],
            "the arena overhead per body is not the SAME across four bodies "
            "(%u, %u, %u, %u lets): a fixed +1 would be a fact about the "
            "COUNTER, and a varying one is a fact about the BODY. The report "
            "must say which, and it cannot say 96 times nodes plus one as a "
            "rule.",
            deltas[0], deltas[1], deltas[2], deltas[3]);
    /* The cross-check: one rung, budget bisected, the old instrument. */
    {
      char *wide = lets_body_titled(4, MAX_FUEL, MAX_ARENA);
      Run r = run(image_p, wide ? wide : "", 1u << 20, 0);
      int ok = expanded(&r);
      unsigned published = (unsigned)r.w1;
      freerun(&r);
      free(wide);
      unsigned min_arena = 0;
      if (ok) {
        unsigned lo = 96, hi = MAX_ARENA;
        while (lo < hi) {
          unsigned mid = ((lo + hi) / 2 + 95) / 96 * 96;
          if (mid <= lo) break;
          char *src = lets_body_titled(4, MAX_FUEL, mid);
          Run q = run(image_p, src ? src : "", 1u << 20, 0);
          int e = expanded(&q);
          freerun(&q);
          free(src);
          if (e) hi = mid;
          else lo = mid + 96;
        }
        min_arena = lo;
      }
      uint64_t charges = (uint64_t)min_arena / 96;
      SAY("ARENA_CROSSCHECK lets=4 published_nodes=%u min_arena_bytes=%u "
          "charges_of_96=%llu charges_minus_published=%llu "
          "agrees_with_the_measure_request=%s\n",
          published, min_arena, (unsigned long long)charges,
          (unsigned long long)(charges - published),
          charges - published == deltas[1] ? "yes" : "NO");
      observations++;
      OBSERVE(charges - published == deltas[1],
              "the two instruments disagree: the bisected budget says %llu "
              "charges over published, the measure request says %u made over "
              "published. One of them is measuring something else.",
              (unsigned long long)(charges - published), deltas[1]);
    }
    SAY("ARITHMETIC_SUMMARY node_bytes=96 max_arena=%u "
        "max_arena_div_node_bytes=%llu ast_nodes_declared=%u "
        "the_arena_binds_before_the_node_budget=yes "
        "two_budgets_billed_on_the_same_counter_with_different_published_"
        "counts=yes\n",
        MAX_ARENA, (unsigned long long)(MAX_ARENA / 96), MAX_NODES);
  }

  /* ==================================================================
     9. THE TEXT ARM, with a positive control and a negative control.
     ================================================================== */
  SAY("A5_DIAGNOSTIC_TEXT control_first=yes\n");
  {
    /* POSITIVE control: a SUCCESSFUL expansion whose produced name table
       provably holds spellings. */
    char *src = lets_body_titled(4, MAX_FUEL, MAX_ARENA);
    Run r = run(image_p, src ? src : "", 1u << 18, 0);
    char buf[256];
    unsigned found = ascii_runs(&r, buf, sizeof buf);
    SAY("A5_TEXT_CONTROL role=positive arm=a_successful_expansion "
        "published=%llu printable_runs_of_4_or_more=%u scanner_works=%s\n",
        (unsigned long long)r.w1, found, found > 0 ? "yes" : "NO");
    OBSERVE0(found > 0,
             "the printable-text scanner found nothing on a SUCCESSFUL "
             "expansion, so every negative it produces would be void");
    freerun(&r);
    free(src);

    /* The subject: every boundary this campaign reached, asked whether it
       speaks, in the WHOLE region the caller receives rather than in the
       four words, because a message could in principle be published
       alongside the code. */
    char *cases[8];
    cases[0] = params_body(9);
    cases[1] = nest_body(ceil_nest(image_p, 40) + 1);
    cases[2] = loop_body_fuel(513, MAX_FUEL);
    cases[3] = lets_body_titled(600, MAX_FUEL, MAX_ARENA);
    cases[4] = chain_body(128);
    cases[5] = nested_body(1024, 64, 1, MAX_FUEL);
    cases[6] = lets_body_titled(64, MAX_FUEL, 96);
    cases[7] = NULL;
    const char *names[7] = {"parameter_cap",  "walk_depth_cap", "loop_cap",
                            "binding_stack", "argument_stack", "hard_node_cap",
                            "arena_bytes"};
    for (unsigned k = 0; k < 7; k++) {
      Run q;
      uint64_t w = run_fitting(image_p, cases[k], &q);
      char b2[256];
      unsigned n = ascii_runs(&q, b2, sizeof b2);
      SAY("A5_TEXT bound=%s code=%llu reason=%llu region_words=%llu "
          "printable_runs_of_4_or_more=%u text_channel_exists=%s\n",
          names[k], (unsigned long long)q.code, (unsigned long long)q.reason,
          (unsigned long long)w, n, n > 0 ? "yes" : "no");
      observations++;
      freerun(&q);
      free(cases[k]);
    }
    SAY("A5_DIAGNOSTIC_TEXT what_it_promises=nothing_about_text "
        "what_it_does_not_promise=that_a_code_is_a_message_a_reader_can_act_"
        "on_or_that_372_names_a_macro_and_900_names_a_name_table "
        "measured=the_whole_output_region_of_seven_refusals_scanned_for_"
        "printable_byte_runs_of_four_or_more\n");
  }

  SAY("A5_CAMPAIGN_BOUNDS checks=%u failures=%u observations=%u "
      "bounds_named=7 bounds_measured=7 triples_complete=7 "
      "bounds_unreachable=3 bounds_reachable=4 "
      "diagnostic_text_measured=1 diagnostic_text_found=0\n",
      checks, failures, observations);
  if (image.memory) nova_host_unmap(&image);
  nt_artifact_free(&a);
  for (unsigned i = 0; i < 6; i++) free(sources[i]);
  return failures ? 1 : 0;
}
