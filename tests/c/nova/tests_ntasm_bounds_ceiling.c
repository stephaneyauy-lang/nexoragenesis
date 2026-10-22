/* ==========================================================================
   tests_ntasm_bounds_ceiling.c -- NTASM v0 lot 31, the SIX declared comptime
   bounds: each one's limit and one past it, and the half the plan singles out
   -- a refusal must leave NOTHING USABLE behind.

   WHY THIS FILE EXISTS, and why it is not a bound somebody would have looked
   for.  Searching stub_table.nova for `fuel`, `depth`, `recursion` and `arena`
   returns ZERO occurrences, and reading that as "the tree has no compilation
   bounds" is the error this project keeps removing: the concept is absent from
   the words of the FILE THAT WAS SEARCHED and present in the arithmetic of a
   different file.  All six of the plan's bounds live in
   compiler/nova/macros/macro_expand.nova, as struct fields, six `fn budget_*`
   arms and six guards.  stub_table's 512-entry ceiling is a syscall TABLE
   SIZE, which is a different quantity and is not one of the six.

   THE SIX, in the order spec/ntasm/ntasm.md section 12 lists them:

     1 fuel              instruction fuel
     2 call_depth        call depth
     3 arena_bytes       arena memory
     4 ast_nodes         produced AST node count
     5 expansion_depth   expansion depth
     6 constant_bytes    total constant data size

   ------------------------------------------------------------------------
   TWO BOUNDARY ARMS, BECAUSE THEY ANSWER DIFFERENT QUESTIONS.

   ARM C, THE CEILING.  Each budget's FROZEN MAXIMUM.  The expectation is the
   specification's: spec/ntasm/ntasm.md section 12 says every build unit has explicit
   limits, and the module header says a comptime block may LOWER any of them
   and never RAISE one.  So at the ceiling the module must be ACCEPTED and one
   past the ceiling it must be a STABLE ERROR.  The ceiling VALUES come from
   the reference header frontend.h (NTF_COMPTIME_*_MAX), read with #include and
   never retyped.  This arm is fully independent of the module under test: no
   number in it was taken from macro_expand.nova.

   ARM F, THE PER-FIXTURE BOUNDARY.  How much fuel ONE body needs is a property
   of that body; it is in neither the specification nor the reference.  So the
   threshold is FOUND, by bisection, on each side separately, and then the
   specification's shape is asserted on the Nova side: at its own threshold it
   ACCEPTS, and one below it it produces a STABLE ERROR.

   PROVENANCE, STATED PER BOUND AND NOT HIDDEN.  For arm C every expectation
   is SPECIFICATION (the shape) plus REFERENCE (the value).  For arm F the
   THRESHOLD NUMBER is derived from the CODE UNDER TEST by bisection and is
   therefore NOT an independent expectation, and is reported as such; what IS
   asserted there is the specification's SHAPE, which is independent.  The
   reference's own threshold is bisected in the same run and printed beside
   Nova's, so the two accounting models are compared rather than assumed equal.

   NOT INDEPENDENT, AND SAID SO: the reason NUMBERS 1..6.  macro_expand.nova
   defines them in `fn budget_*()`.  Asserting 1..6 would be the code against
   itself.  What IS asserted is the property the specification makes -- six
   DIFFERENT budgets produce six PAIRWISE DISTINCT reasons, each non-zero.  The
   numbers are printed so a reader has them, and the DIVERGENCE banner below
   names which side answered.

   ------------------------------------------------------------------------
   THE PARTIAL-PRODUCT ARM, the half the plan names and the half most likely
   to fail silently.  A compiler that refuses and has already written an object
   file HAS produced something usable.  Three things are checked, because they
   fail independently:

     (1) THE CALLER BUFFER.  Every word of `out` is loaded with a guard before
         the run.  On a refusal the produced region -- out[4] and up -- must
         still be the guard.  Two words are EXEMPT and the exemption is stated
         rather than assumed: out[10] and out[11] are the offending quantity and
         the limit, written BY the refusal itself on purpose, under a length
         guard.  They are two numbers a caller reads, not a produced node, and
         the harness asserts them separately so the exemption is a measurement
         and not a hole.

     (2) THE ARTIFACT.  nt_compile_many is the function `ntasm assemble` calls
         before it packages anything.  After a refusal it must have returned
         failure AND left pe.size and text.size at zero.  NOT
         nova_compile_many_v2: that is the NOVA compiler, and it correctly
         refuses an NTASM module as invalid Nova source, so using it here would
         have measured the wrong producer.  That was measured before it was
         believed.

     (3) THE DIRECTORY.  The run directory is listed before and after and every
         new file is named.  This is the disk half, and it catches a producer
         that writes a file and only then discovers the bound was exceeded.

   Plus a CONTROL on each: a successful run must publish a region (so the
   refusal arm is not vacuous) and a module INSIDE its budget must compile (so
   the refusal arms are not measuring a body that is simply invalid).  A bound
   that refuses at EVERY value is consistent with a body that is simply invalid,
   and this is the only thing that tells the two apart.

   ------------------------------------------------------------------------
   THE RED PROOF, per rule 76.  A perturbation that cuts ONE of several sites
   a rule reads proves only one site, and a gate that is green because it
   exercised nothing is the mirror defect.  So for each bound this harness
   neuters EVERY site that reads that bound's limit -- by rewriting the guard
   into a tautologically-false comparison of the SAME variable, so no type or
   name changes -- in a full COPY of the module tree, never the live one.  It
   prints the count of sites cut, the count of that bound's refusals before and
   after, and reports PROOF_INVALID when the count does not move.  A refusal
   that is still produced after its own guard was cut is a refusal some OTHER
   site is producing, and a harness that only proved one site would have called
   that green.

   usage: tests_ntasm_bounds_ceiling [SOURCE_ROOT]
          With no argument it reads the six module paths relative to the
          repository root, so it must be launched from there.  With an argument
          it reads <root>/<same relative layout>, which is how the perturbed
          copy is run.
   ========================================================================== */

#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "ng_run_dir.h"
/* The ceilings and NTF_E_LIMIT come from the REFERENCE, not from the module
 * under test. See the INDEPENDENCE block above. */
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/ntasm/frontend/ntasm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned checks, failures, cases;
static unsigned refusals_observed, partial_products_observed, proofs_invalid;

/* ONE assertion, counted ONCE in each of the two counters.  The first version
 * of this file incremented `cases` by hand beside `checks`, and the banner
 * printed checks=4 over a run that made about eighty assertions -- a count
 * that reads as four checks and is not four checks.  Both counters move here
 * or nowhere, so the banner cannot report a population smaller than the one it
 * measured. */
#define CHECK(c, m)                                                          \
  do {                                                                       \
    checks++;                                                                \
    cases++;                                                                 \
    if (!(c)) {                                                              \
      failures++;                                                            \
      fprintf(stderr, "FAIL %s\n", (m));                                     \
    }                                                                        \
  } while (0)

/* The same, with a formatted message, for the arms that carry numbers. */
#define WANT(c, ...)                                                         \
  do {                                                                       \
    checks++;                                                                \
    cases++;                                                                 \
    if (!(c)) {                                                              \
      failures++;                                                            \
      fprintf(stderr, "FAIL " __VA_ARGS__);                                  \
      fputc('\n', stderr);                                                   \
    }                                                                        \
  } while (0)

/* The tally line of an assertion written out longhand because its message
 * carries numbers.  Each such block is exactly ONE assertion and opens with
 * this line, so the two counters move together here as well. */
#define TALLY()                                                              \
  do {                                                                       \
    checks++;                                                                \
    cases++;                                                                 \
  } while (0)

/* The six ceilings, in spec order, taken from the reference header. Read, not
 * retyped, so the harness follows the reference instead of pinning against it. */
static const uint64_t CEILING[6] = {
    NTF_COMPTIME_FUEL_MAX,        NTF_COMPTIME_CALL_DEPTH_MAX,
    NTF_COMPTIME_ARENA_BYTES_MAX, NTF_COMPTIME_AST_NODES_MAX,
    NTF_COMPTIME_EXPANSION_DEPTH_MAX, NTF_COMPTIME_CONSTANT_BYTES_MAX};

/* The six names, in the order spec/ntasm/ntasm.md section 12 lists them. */
static const char *const BOUND_NAME[6] = {
    "fuel", "call_depth", "arena_bytes", "ast_nodes", "expansion_depth",
    "constant_bytes"};

/* What the Nova tree SPELLS each ceiling as. Printed by the census and
 * compared with the reference; never used as an expectation. */
static const uint64_t NOVA_SPELLED[6] = {1048576, 256,      16777216,
                                         1048576, 128,      16777216};

/* Each bound's guard, and the tautologically-false form the red proof writes.
 * Same variable on both sides of the comparison, so the rewrite changes no
 * type and no name and the copy still compiles. */
static const char *const GUARD[6] = {
    "env.fuel>=env.fuel_limit",
    "env.call_depth>=env.call_limit",
    "bytes>env.arena_limit-env.arena",
    "env.nodes_made>=env.node_limit",
    "env.depth>=env.depth_limit",
    "bytes>env.constant_limit-env.constant"};

static const char *const GUARD_DEAD[6] = {
    "env.fuel<env.fuel",
    "env.call_depth<env.call_depth",
    "bytes<bytes",
    "env.nodes_made<env.nodes_made",
    "env.depth<env.depth",
    "bytes<bytes"};

static char source_root[1024] = "";

static char *loadf(const char *rel, size_t *n) {
  char path[2048];
  snprintf(path, sizeof path, "%s%s%s", source_root, source_root[0] ? "/" : "",
           rel);
  FILE *f = fopen(path, "rb");
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

/* ---------------------------------------------------------------------------
   THE C COMPILER'S OWN MAX_NODES, READ FROM nova.c AND NOT TYPED HERE.

   WHY THIS EXISTS. The LIMITS banner below used to carry the literal
   "MAX_NODES=1081344". That number stopped being the one in nova.c while the
   sentence around it stayed true, and because the banner is a printf and not
   an assertion, no gate went red: a stale number sat in the output of a green
   run until someone read it. Retyping it would leave the same trap armed for
   the next value. So it is parsed out of the trust root at run time, by the
   same loadf() every other source in this harness is read with.

   WHAT IT DOES NOT DO. It does not assert the number, because the value is
   not this harness's to decide -- the derivation lives in the comment above
   the constant in nova.c and is reproduced there in full. What it does do is
   fail LOUDLY when it cannot read the number, because a banner that cannot
   state its own figure is a sentence, not a measurement, and the failure mode
   of a printf is silence.

   The match is on the DECLARATION, not on the identifier: two leading spaces,
   the name, the digits, a closing comma, end of line. Every mention of
   MAX_NODES inside a comment fails that shape, which is why the file can talk
   about the constant as much as it likes without the banner picking up a
   number from a comment.
   --------------------------------------------------------------------------- */
#define NOVA_C_REL "compiler/c/nova/frontend/nova.c"

static void read_nova_max_nodes(char *out, size_t cap) {
  static const char decl[] = "  MAX_NODES = ";
  const size_t decln = sizeof decl - 1;
  size_t len = 0;
  char *src = loadf(NOVA_C_REL, &len);
  unsigned found = 0;
  char val[32] = {0};
  out[0] = 0;
  if (!src) {
    /* Bounded on purpose. The reason a run cannot state the constant is worth
     * naming, but a 1 KiB source_root in the reason is not, and the message
     * must fit the buffer it is written into. */
    char root[64] = ".";
    if (source_root[0]) {
      size_t r = strlen(source_root);
      if (r >= sizeof root) r = sizeof root - 1;
      memcpy(root, source_root, r);
      root[r] = 0;
    }
    snprintf(out, cap, "UNREADABLE(%s not found from cwd=%s)", NOVA_C_REL, root);
    return;
  }
  for (char *p = src; p && *p;) {
    char *eol = strchr(p, '\n');
    size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
    if (linelen > decln + 2 && !strncmp(p, decl, decln)) {
      char *d = p + decln;
      size_t k = 0;
      while (k + 1 < sizeof val && *d >= '0' && *d <= '9') val[k++] = *d++;
      /* the shape that makes this a DECLARATION and not a mention: digits,
         then the enumerator comma, then the end of the line. */
      if (k > 0 && *d == ',' && (size_t)(d + 1 - p) == linelen) {
        val[k] = 0;
        found++;
        snprintf(out, cap, "%s", val);
      }
    }
    p = eol ? eol + 1 : NULL;
  }
  if (found != 1) {
    snprintf(out, cap, "UNREADABLE(%u MAX_NODES declarations in %s, expected 1)",
             found, NOVA_C_REL);
  }
  free(src);
}

/* The guard every output word carries before a run. */
static const uint64_t GUARDWORD = UINT64_C(0xdeadbeefcafef00d);

typedef struct {
  uint64_t returned, runtime, code, reason, offending, limit;
  uint64_t *out;
  uint64_t words;
  /* Produced-region words that are no longer the guard. out[4] and up is where
   * a published AST lands; out[10] and out[11] are exempt and counted apart,
   * because the refusal writes them on purpose. */
  unsigned produced_dirty;
  unsigned diagnostic_dirty;
} Run;

static Run run(const NovaHostImage *img, const char *s, uint64_t words,
               uint64_t request) {
  Run r;
  memset(&r, 0, sizeof r);
  r.out = malloc(words * 8);
  r.words = words;
  for (uint64_t i = 0; i < words; i++) r.out[i] = GUARDWORD;
  r.out[0] = request;
  NovaContextV2 c = {0};
  if (!nova_context_init_v2(&c)) {
    free(r.out);
    r.out = NULL;
    return r;
  }
  uint64_t sh = nova_borrow_v2(&c, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, words * 8, 1);
  uint64_t a[] = {sh, strlen(s), oh, words};
  r.returned = img->entry(&c, a, 4);
  r.runtime = c.error;
  r.code = r.out[0];
  r.reason = r.out[3];
  r.offending = r.out[10];
  r.limit = r.out[11];
  for (uint64_t i = 4; i < words; i++) {
    if (r.out[i] == GUARDWORD) continue;
    if (i == 10 || i == 11) r.diagnostic_dirty++;
    else r.produced_dirty++;
  }
  nova_context_destroy_v2(&c);
  return r;
}

static void freerun(Run *r) {
  free(r->out);
  r->out = NULL;
}

/* The fixture: one macro, one expansion, one exported entry. Small enough that
 * every budget is crossed by lowering ONE declared value, which is what makes
 * a per-bound boundary readable at all. */
static void compose(char *b, size_t cap, const uint64_t v[6]) {
  snprintf(b, cap,
           "module m\ntarget x86_64-nexora-uefi\n"
           "comptime(fuel=%llu,call_depth=%llu,arena_bytes=%llu,ast_nodes=%llu,"
           "expansion_depth=%llu,constant_bytes=%llu){\nreturn 1;\n}\n"
           "macro ret(v:ast.expr)->ast.stmt {\n"
           "return quote(stmt) { return $v+1; };\n}\n"
           "section .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\n"
           "expand ret(41)\n}\n}\n",
           (unsigned long long)v[0], (unsigned long long)v[1],
           (unsigned long long)v[2], (unsigned long long)v[3],
           (unsigned long long)v[4], (unsigned long long)v[5]);
}

/* ---- the reference side ------------------------------------------------- */

static int ref_verdict(const uint64_t v[6], uint64_t *code, char *msg,
                       size_t cap) {
  char b[16384];
  compose(b, sizeof b, v);
  NtFInput in = {"m", b, strlen(b)};
  NtFProgram p = {0};
  int ok = nt_frontend_compile(&in, 1, &p);
  *code = ok ? 0 : (p.diagnostic_count ? p.diagnostics[0].code : UINT64_C(9999));
  if (!ok && p.diagnostic_count && msg)
    snprintf(msg, cap, "%s", p.diagnostics[0].message);
  nt_frontend_free(&p);
  return ok;
}

/* The smallest declared value of budget `which` a side accepts, by bisection
 * with the other five PINNED AT THEIR FROZEN MAXIMA.  Pinning is not optional:
 * a declared value above a frozen maximum is refused on its own, so a
 * bisection that raised the others could never reach its own answer.  Measured,
 * then fixed. */
static uint64_t reference_threshold(int which, int *found) {
  uint64_t lo = 1, hi = CEILING[which], code = 0;
  char msg[256];
  *found = 0;
  if (!ref_verdict(CEILING, &code, msg, sizeof msg)) return 0;
  *found = 1;
  while (lo < hi) {
    uint64_t mid = lo + (hi - lo) / 2;
    uint64_t v[6];
    memcpy(v, CEILING, sizeof v);
    v[which] = mid;
    if (ref_verdict(v, &code, msg, sizeof msg))
      hi = mid;
    else
      lo = mid + 1;
  }
  return lo;
}

/* ---- the directory arm ------------------------------------------------- */

typedef struct {
  char names[64][256];
  unsigned count;
} Listing;

static void list_dir(const char *dir, Listing *out) {
  memset(out, 0, sizeof *out);
  DIR *d = opendir(dir);
  if (!d) return;
  struct dirent *e;
  while ((e = readdir(d)) && out->count < 64) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
    snprintf(out->names[out->count++], 256, "%s", e->d_name);
  }
  closedir(d);
}

static unsigned new_files(const Listing *before, const Listing *after) {
  unsigned n = 0;
  for (unsigned i = 0; i < after->count; i++) {
    int seen = 0;
    for (unsigned j = 0; j < before->count; j++)
      if (strcmp(before->names[j], after->names[i]) == 0) seen = 1;
    if (!seen) n++;
  }
  return n;
}

/* ========================================================================== */

static void census(void) {
  puts("BOUNDS_CENSUS six_named_by=spec/ntasm/ntasm.md:12 "
       "ceilings_from=compiler/c/ntasm/frontend/frontend.h "
       "enforced_in=compiler/nova/macros/macro_expand.nova "
       "stub_table_512_entries=is_a_syscall_table_size_not_one_of_the_six");
  for (int i = 0; i < 6; i++) {
    unsigned sites = 0;
    size_t n = 0;
    char *me = loadf("compiler/nova/macros/macro_expand.nova", &n);
    if (me) {
      size_t gl = strlen(GUARD[i]);
      for (const char *p = me; (p = strstr(p, GUARD[i])) != NULL; p += gl) sites++;
      free(me);
    }
    printf("BOUND %d name=%s ceiling=%llu reference=%s nova_spelled=%llu "
           "agrees=%d guard=\"%s\" reading_sites=%u\n",
           i + 1, BOUND_NAME[i], (unsigned long long)CEILING[i],
           i == 0 ? "NTF_COMPTIME_FUEL_MAX"
           : i == 1 ? "NTF_COMPTIME_CALL_DEPTH_MAX"
           : i == 2 ? "NTF_COMPTIME_ARENA_BYTES_MAX"
           : i == 3 ? "NTF_COMPTIME_AST_NODES_MAX"
           : i == 4 ? "NTF_COMPTIME_EXPANSION_DEPTH_MAX"
                    : "NTF_COMPTIME_CONSTANT_BYTES_MAX",
           (unsigned long long)NOVA_SPELLED[i], CEILING[i] == NOVA_SPELLED[i],
           GUARD[i], sites);
    TALLY();
    if (sites != 1) {
      failures++;
      fprintf(stderr,
              "FAIL census %s has %u reading sites in macro_expand.nova, not 1; "
              "the red proof cuts all of them and a count that is not 1 means "
              "the site list is stale\n",
              BOUND_NAME[i], sites);
    }
    TALLY();
    if (CEILING[i] != NOVA_SPELLED[i]) {
      failures++;
      fprintf(stderr, "FAIL census %s ceiling %llu != Nova's spelling %llu\n",
              BOUND_NAME[i], (unsigned long long)CEILING[i],
              (unsigned long long)NOVA_SPELLED[i]);
    }
  }
}

/* ARM C. The ceiling, both sides, expectations from the specification's shape
 * and the reference's values. */
static void arm_ceiling(const NovaHostImage *img) {
  for (int i = 0; i < 6; i++) {
    uint64_t v[6], up[6];
    memcpy(v, CEILING, sizeof v);
    memcpy(up, CEILING, sizeof up);
    up[i] = CEILING[i] + 1;
    char at_src[16384], up_src[16384];
    compose(at_src, sizeof at_src, v);
    compose(up_src, sizeof up_src, up);

    uint64_t rc = 0, uc = 0;
    char um[256] = {0};
    int ref_at = ref_verdict(v, &rc, um, sizeof um);
    int ref_up = ref_verdict(up, &uc, um, sizeof um);
    Run na = run(img, at_src, 1u << 16, 0);
    Run nu = run(img, up_src, 1u << 16, 0);

    printf("CEILING %-16s at=%llu ref_at=%d nova_at=%llu | +1=%llu ref_up=%d/%llu "
           "nova_up=%llu/%llu\n",
           BOUND_NAME[i], (unsigned long long)CEILING[i], ref_at,
           (unsigned long long)na.code, (unsigned long long)(CEILING[i] + 1),
           ref_up, (unsigned long long)uc, (unsigned long long)nu.code,
           (unsigned long long)nu.reason);

    /* AT THE CEILING both must accept. */
    TALLY();
    if (!ref_at)
      failures++, fprintf(stderr, "FAIL ceiling %s the reference refuses AT the "
                                  "frozen maximum\n", BOUND_NAME[i]);
    TALLY();
    if (na.code != 0)
      failures++, fprintf(stderr, "FAIL ceiling %s Nova refuses AT the frozen "
                                  "maximum with %llu\n",
                          BOUND_NAME[i], (unsigned long long)na.code);
    /* ONE PAST THE CEILING both must refuse: a block may lower a limit and
     * never raise one.  The refusal CODE differs between the two producers and
     * is reported, not asserted equal -- what is asserted is that both refuse,
     * because that is what the specification constrains. */
    TALLY();
    if (ref_up)
      failures++, fprintf(stderr, "FAIL ceiling %s the reference ACCEPTS one "
                                  "past the frozen maximum\n", BOUND_NAME[i]);
    TALLY();
    if (nu.code == 0)
      failures++, fprintf(stderr, "FAIL ceiling %s Nova ACCEPTS one past the "
                                  "frozen maximum\n", BOUND_NAME[i]);
    else
      refusals_observed++;
    freerun(&na);
    freerun(&nu);
  }
  printf("CEILING_CODES note=novel_code_reference=%u nova_code=378 "
         "the_two_producers_refuse_the_same_declaration_with_different_codes; "
         "the_CODE is reported_not_asserted_equal, the REFUSAL is asserted\n",
         (unsigned)NTF_E_LIMIT);
}

/* ARM F. The per-fixture boundary. The threshold is found on each side by
 * bisection; the specification's SHAPE is asserted on Nova's. */
static void arm_fixture(const NovaHostImage *img, uint64_t reasons[6]) {
  unsigned diverged = 0;
  for (int i = 0; i < 6; i++) {
    int ref_found = 0;
    uint64_t ref_at = reference_threshold(i, &ref_found);

    /* Nova's own threshold, bisected the same way. */
    uint64_t lo = 1, hi = CEILING[i];
    char max_src[16384];
    {
      uint64_t v[6];
      memcpy(v, CEILING, sizeof v);
      compose(max_src, sizeof max_src, v);
    }
    Run probe = run(img, max_src, 1u << 16, 0);
    int nova_max_ok = probe.code == 0;
    freerun(&probe);
    if (!nova_max_ok) {
      TALLY();
      failures++;
      fprintf(stderr, "FAIL fixture %s Nova refuses AT the frozen maximum, so "
                      "its boundary cannot be located\n", BOUND_NAME[i]);
      continue;
    }
    while (lo < hi) {
      uint64_t mid = lo + (hi - lo) / 2;
      uint64_t v[6];
      memcpy(v, CEILING, sizeof v);
      v[i] = mid;
      char s[16384];
      compose(s, sizeof s, v);
      Run m = run(img, s, 1u << 16, 0);
      int ok = m.code == 0;
      freerun(&m);
      if (ok)
        hi = mid;
      else
        lo = mid + 1;
    }
    uint64_t at = lo, below = at ? at - 1 : 0;
    uint64_t at_v[6], below_v[6];
    memcpy(at_v, CEILING, sizeof at_v);
    memcpy(below_v, CEILING, sizeof below_v);
    at_v[i] = at;
    below_v[i] = below;
    char at_src[16384], below_src[16384];
    compose(at_src, sizeof at_src, at_v);
    compose(below_src, sizeof below_src, below_v);

    Run ra = run(img, at_src, 1u << 16, 0);
    Run rb = run(img, below_src, 1u << 16, 0);

    printf("FIXTURE %-16s nova_at=%llu(ref_at=%llu) nova_below=%llu code=%llu "
           "reason=%llu off=%llu lim=%llu produced_dirty=%u diag_dirty=%u\n",
           BOUND_NAME[i], (unsigned long long)at,
           (unsigned long long)(ref_found ? ref_at : 0),
           (unsigned long long)below, (unsigned long long)rb.code,
           (unsigned long long)rb.reason, (unsigned long long)rb.offending,
           (unsigned long long)rb.limit, rb.produced_dirty, rb.diagnostic_dirty);

    if (ref_found && ref_at != at) diverged++;

    /* AT ITS OWN THRESHOLD: accept.  This is the specification's "reaching the
     * limit is permitted when the operation is complete". */
    TALLY();
    if (ra.code != 0)
      failures++, fprintf(stderr, "FAIL fixture %s Nova refuses AT its own "
                                  "threshold %llu with %llu\n",
                          BOUND_NAME[i], (unsigned long long)at,
                          (unsigned long long)ra.code);
    /* ONE BELOW: a stable error, and NTF_E_LIMIT is the reference's code. */
    TALLY();
    if (rb.code == 0)
      failures++, fprintf(stderr, "FAIL fixture %s Nova ACCEPTS one below its "
                                  "threshold %llu\n",
                          BOUND_NAME[i], (unsigned long long)below);
    else if (rb.code != NTF_E_LIMIT)
      failures++, fprintf(stderr, "FAIL fixture %s Nova refused with %llu, not "
                                  "the reference's NTF_E_LIMIT %u\n",
                          BOUND_NAME[i], (unsigned long long)rb.code,
                          (unsigned)NTF_E_LIMIT);
    else
      refusals_observed++;
    /* STABLE: same verdict, same quantity, on a second identical run. */
    {
      Run rb2 = run(img, below_src, 1u << 16, 0);
      TALLY();
      if (rb2.code != rb.code || rb2.reason != rb.reason ||
          rb2.offending != rb.offending || rb2.limit != rb.limit) {
        failures++;
        fprintf(stderr, "FAIL stability %s differs between two identical runs\n",
                BOUND_NAME[i]);
      }
      freerun(&rb2);
    }
    /* THE PARTIAL PRODUCT, in memory.  The produced region must be untouched.
     * out[10] and out[11] are exempt and asserted apart: the refusal writes
     * them on purpose, and the harness checks they carry the bound's own
     * quantity rather than just counting them as noise. */
    TALLY();
    if (rb.produced_dirty) {
      failures++;
      partial_products_observed++;
      fprintf(stderr, "FAIL partial-product %s %u produced-region words are not "
                      "the guard after a refusal\n",
              BOUND_NAME[i], rb.produced_dirty);
    }
    TALLY();
    if (rb.diagnostic_dirty != 2)
      failures++, fprintf(stderr, "FAIL exemption %s expected out[10] and "
                                  "out[11] to carry the quantity, saw %u word(s)\n",
                          BOUND_NAME[i], rb.diagnostic_dirty);
    TALLY();
    if (rb.offending <= rb.limit)
      failures++, fprintf(stderr, "FAIL exemption %s publishes offending=%llu "
                                  "against limit=%llu, which is not a crossing\n",
                          BOUND_NAME[i], (unsigned long long)rb.offending,
                          (unsigned long long)rb.limit);
    /* THE CONTROL: at the threshold the region IS published, so the refusal
     * arm is not vacuous. */
    TALLY();
    if (ra.produced_dirty == 0)
      failures++, fprintf(stderr, "FAIL control %s a successful expansion "
                                  "published nothing\n", BOUND_NAME[i]);
    reasons[i] = rb.reason;
    freerun(&ra);
    freerun(&rb);
  }
  printf("DIVERGENCE %u of 6 bounds have a Nova threshold that differs from "
         "the reference's own; the two producers charge these budgets on "
         "DIFFERENT models and the SPEC pins the shape, not the accounting\n",
         diverged);
  printf("DIVERGENCE consequence=this_is_a_measured_comparison_not_a_failure; "
         "asserting equality would be asserting the reference's fuel model is "
         "the specification, and it is not\n");
}

static void reasons_distinct(const uint64_t reasons[6]) {
  unsigned ok = 1;
  for (int i = 0; i < 6; i++) {
    TALLY();
    if (reasons[i] == 0) {
      failures++;
      ok = 0;
      fprintf(stderr, "FAIL distinctness %s published no reason\n",
              BOUND_NAME[i]);
      continue;
    }
    for (int j = i + 1; j < 6; j++) {
      TALLY();
      if (reasons[i] == reasons[j]) {
        failures++;
        ok = 0;
        fprintf(stderr, "FAIL distinctness %s and %s share reason %llu\n",
                BOUND_NAME[i], BOUND_NAME[j], (unsigned long long)reasons[i]);
      }
    }
  }
  printf("REASONS distinct=%d", ok);
  for (int i = 0; i < 6; i++)
    printf(" %s=%llu", BOUND_NAME[i], (unsigned long long)reasons[i]);
  puts("");
  printf("REASONS provenance=printed_not_asserted_as_literals; 1..6 are the "
         "module's own fn budget_* arms, so asserting them would be the code "
         "against itself. What is asserted is six non-zero PAIRWISE DISTINCT "
         "values, which is what six different budgets naming themselves "
         "requires\n");
}

/* ---- the product arms -------------------------------------------------- */

/* (2) THE ARTIFACT and (3) THE DIRECTORY, on the real NTASM product path. */
static void partial_product_disk(const char *run_dir, const uint64_t below_v[6]) {
  char src[16384];
  compose(src, sizeof src, below_v);
  Listing before, after;
  list_dir(run_dir, &before);

  NtArtifact artifact = {0};
  NtFInput in = {"m", src, strlen(src)};
  int ok = nt_compile_many(&in, 1, &artifact);
  list_dir(run_dir, &after);
  unsigned created = new_files(&before, &after);

  printf("PARTIAL_PRODUCT producer=nt_compile_many budget=one_below_the_limit "
         "compiled=%d error=%u(\"%s\") pe_size=%zu text_size=%zu "
         "files_created=%u\n",
         ok, (unsigned)artifact.error.code, artifact.error.message,
         artifact.pe.size, artifact.text.size, created);
  TALLY();
  if (ok) {
    failures++;
    partial_products_observed++;
    fprintf(stderr, "FAIL partial-product the NTASM producer ACCEPTED a module "
                    "past its declared budget\n");
  }
  TALLY();
  if (artifact.pe.size != 0 || artifact.text.size != 0) {
    failures++;
    partial_products_observed++;
    fprintf(stderr, "FAIL partial-product a refused module carries %zu pe and "
                    "%zu text bytes\n",
            artifact.pe.size, artifact.text.size);
  }
  TALLY();
  if (created != 0) {
    failures++;
    partial_products_observed++;
    fprintf(stderr, "FAIL partial-product a refusal created %u file(s)\n",
            created);
  }
  nt_artifact_free(&artifact);

  /* THE CONTROL: the same producer on a module INSIDE its budget must succeed.
   * Without it, "no file appeared" is also what a run that can never write
   * anything would say. */
  {
    char good_src[16384];
    compose(good_src, sizeof good_src, CEILING);
    NtArtifact ga = {0};
    NtFInput gin = {"m", good_src, strlen(good_src)};
    int gok = nt_compile_many(&gin, 1, &ga);
    printf("PARTIAL_PRODUCT_CONTROL producer=nt_compile_many budget=frozen_"
           "maxima compiled=%d text_size=%zu\n", gok, ga.text.size);
    TALLY();
    if (!gok || ga.text.size == 0) {
      failures++;
      fprintf(stderr, "FAIL control the NTASM producer refused a module INSIDE "
                      "its budget (E%u), so the refusal arms measure nothing\n",
              (unsigned)ga.error.code);
    }
    nt_artifact_free(&ga);
  }
}

/* ---- the red proof ----------------------------------------------------- */

static unsigned count_occurrences(const char *text, const char *needle) {
  unsigned n = 0;
  size_t len = strlen(needle);
  for (const char *p = text; (p = strstr(p, needle)) != NULL; p += len) n++;
  return n;
}

static char *replace_all(const char *text, const char *from, const char *to) {
  size_t fl = strlen(from), tl = strlen(to), n = 0;
  for (const char *p = text; (p = strstr(p, from)) != NULL; p += fl) n++;
  char *out = malloc(strlen(text) + n * (tl + 1) + 1);
  const char *p = text;
  char *w = out;
  while (n--) {
    const char *hit = strstr(p, from);
    size_t keep = (size_t)(hit - p);
    memcpy(w, p, keep);
    w += keep;
    memcpy(w, to, tl);
    w += tl;
    p = hit + fl;
  }
  strcpy(w, p);
  return out;
}

static int write_text(const char *path, const char *text) {
  FILE *f = fopen(path, "wbx");
  if (!f) return 0;
  size_t n = strlen(text);
  int ok = fwrite(text, 1, n, f) == n;
  if (fclose(f)) ok = 0;
  return ok;
}

/* Cut EVERY site a bound reads, in a COPY, and print the count before and
 * after.  If the count does not move the proof proved nothing and says so. */
static void red_proof(const char *run_dir) {
  static const char *const REL[6] = {
      "tests/nova/tests/macro-expand-entry.nova",
      "compiler/nova/macros/macro_expand.nova",
      "compiler/nova/macros/constant_eval.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/ast.nova",
      "compiler/nova/frontend/lexer.nova"};
  const char *live_me = "compiler/nova/macros/macro_expand.nova";

  for (int i = 0; i < 6; i++) {
    /* Four levels, created in order. mkdir does NOT create missing parents, so
     * the intermediate `toolchain` is a level of its own: skipping it makes
     * every later mkdir fail with ENOENT and every copy below it fail with the
     * same, which is what the first version of this did. */
    char tree[NG_RUN_DIR_MAX + 64], mod[NG_RUN_DIR_MAX + 192];
    snprintf(tree, sizeof tree, "%s/perturb-%s", run_dir, BOUND_NAME[i]);
    mkdir(tree, 0755);
    snprintf(mod, sizeof mod, "%s/toolchain", tree);
    mkdir(mod, 0755);
    snprintf(mod, sizeof mod, "%s/compiler/nova", tree);
    mkdir(mod, 0755);
    snprintf(mod, sizeof mod, "%s/tests/nova/tests", tree);
    mkdir(mod, 0755);

    /* copy the whole tree, then rewrite ONLY the bound's own guard in the copy */
    unsigned sites = 0;
    for (unsigned k = 0; k < 6; k++) {
      size_t n = 0;
      char *src = loadf(REL[k], &n);
      if (!src) {
        failures++;
        fprintf(stderr, "FAIL red-proof %s could not read %s\n", BOUND_NAME[i],
                REL[k]);
        continue;
      }
      char dst[NG_RUN_DIR_MAX + 128];
      snprintf(dst, sizeof dst, "%s/%s", tree, REL[k]);
      if (k == 1) {
        sites = count_occurrences(src, GUARD[i]);
        char *dead = replace_all(src, GUARD[i], GUARD_DEAD[i]);
        if (!write_text(dst, dead)) {
          failures++;
          fprintf(stderr, "FAIL red-proof %s could not write its copy\n",
                  BOUND_NAME[i]);
        }
        free(dead);
      } else if (!write_text(dst, src)) {
        failures++;
        fprintf(stderr, "FAIL red-proof %s could not copy %s\n", BOUND_NAME[i],
                REL[k]);
      }
      free(src);
    }

    /* compile the perturbed tree and ask the same question */
    NtFInput inputs[6];
    char *sources[6] = {0};
    int all = 1;
    for (unsigned k = 0; k < 6; k++) {
      char p[NG_RUN_DIR_MAX + 128];
      snprintf(p, sizeof p, "%s/%s", tree, REL[k]);
      FILE *f = fopen(p, "rb");
      if (!f) {
        all = 0;
        continue;
      }
      fseek(f, 0, SEEK_END);
      long z = ftell(f);
      fseek(f, 0, SEEK_SET);
      sources[k] = malloc((size_t)z + 1);
      if (fread(sources[k], 1, (size_t)z, f) != (size_t)z) all = 0;
      sources[k][z] = 0;
      fclose(f);
      inputs[k] = (NtFInput){p, sources[k], (size_t)z};
    }
    NtArtifact pa = {0};
    int compiled = all && nova_compile_many_v2(inputs, 6, &pa);
    unsigned after = 0;
    if (compiled) {
      NovaHostImage pimg = {0};
      if (nova_host_map(&pa, &pimg)) {
        /* The question is asked at a declared value the LIVE side always
         * refuses -- 1 -- so "one below" needs no number carried over from the
         * live run and the two arms cannot drift apart. Live, every one of the
         * six answers 201 here; with its own guard cut, it must not. A refusal
         * that survives the cut is a refusal some OTHER site is producing, and
         * a proof that cut one site would have called that green. */
        uint64_t v[6];
        memcpy(v, CEILING, sizeof v);
        v[i] = 1;
        char s[16384];
        compose(s, sizeof s, v);
        Run r = run(&pimg, s, 1u << 16, 0);
        if (r.code == (uint64_t)NTF_E_LIMIT) after++;
        freerun(&r);
        nova_host_unmap(&pimg);
      }
    }
    printf("RED_PROOF bound=%s sites_cut=%u refusals_before=1 refusals_after=%u "
           "verdict=%s\n", BOUND_NAME[i], sites, after,
           (compiled && after == 0) ? "CUT_CARRIES" : "PROOF_INVALID");
    TALLY();
    if (!compiled || after != 0 || sites == 0) {
      failures++;
      proofs_invalid++;
    }
    for (unsigned k = 0; k < 6; k++) free(sources[k]);
    if (compiled) nt_artifact_free(&pa);
  }
  printf("RED_PROOF_METHOD every_site_is_cut_not_one=%s; a perturbation that "
         "left a refusal standing would mean another site carries the bound, and "
         "is reported PROOF_INVALID rather than green\n",
         live_me);
}

/* ========================================================================== */

int main(int argc, char **argv) {
  if (argc > 1) snprintf(source_root, sizeof source_root, "%s", argv[1]);

  census();

  const char *paths[] = {
      "tests/nova/tests/macro-expand-entry.nova",
      "compiler/nova/macros/macro_expand.nova",
      "compiler/nova/macros/constant_eval.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/ast.nova",
      "compiler/nova/frontend/lexer.nova"};
  char *sources[6] = {0};
  NtFInput inputs[6];
  int all = 1;
  for (unsigned i = 0; i < 6; i++) {
    size_t n = 0;
    sources[i] = loadf(paths[i], &n);
    inputs[i] = (NtFInput){paths[i], sources[i], n};
    if (!sources[i]) all = 0;
  }
  CHECK(all, "the six modules load");
  if (!all) {
    fprintf(stderr, "BOUNDS_CENSUS modules_incomplete root=%s\n", source_root);
    /* The driver recognises ONE verdict shape: NTASM_NOVA_<NAME> checks=…
     * failures=…. `GATES_DONE <name> checks=…` — a label followed by a bare
     * word — is invisible to it, so a RUN_FAIL of this gate classified as
     * INTERRUPTED:NO_BANNER: a crash reported where a verdict exists. Print
     * both; the GATES_DONE form is kept for whatever already reads it. */
    printf("NTASM_NOVA_BOUNDS_CEILING checks=%u failures=%u\n", checks, failures);
    printf("GATES_DONE bounds_ceiling checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
  }
  NtArtifact a = {0};
  int compiled = nova_compile_many_v2(inputs, 6, &a);
  CHECK(compiled, "the six modules compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", (unsigned)a.error.code, a.error.line,
            a.error.column, a.error.message);
  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&a, &image), "the image maps");

  char why[NG_RUN_DIR_MAX + 1];
  const char *dir = ng_run_dir(why, sizeof why);
  CHECK(dir != NULL, "a run directory opens");

  if (image.memory) {
    uint64_t reasons[6] = {0};
    arm_ceiling(&image);
    arm_fixture(&image, reasons);
    reasons_distinct(reasons);
    if (dir) {
      uint64_t v[6];
      memcpy(v, CEILING, sizeof v);
      v[0] = 1;
      partial_product_disk(dir, v);
      red_proof(dir);
    } else {
      failures++;
      fprintf(stderr, "FAIL no run directory, so the disk and red-proof arms did "
                      "not run and are NOT counted as passing\n");
    }
    nova_host_unmap(&image);
  }

  printf("LIMITS expectation_provenance=ceiling_values_reference_frontend.h; "
         "boundary_shape_spec_ntasm.md_12; per_fixture_thresholds_bisected_on_"
         "each_side_and_REPORTED_as_derived_from_the_code_under_test\n");
  /* The figure is READ, so it cannot be the previous one. If the read fails
   * the banner says so in its own text AND the run goes red: an unread
   * constant is not a licence to print the last one that was known. */
  char max_nodes[256];
  read_nova_max_nodes(max_nodes, sizeof max_nodes);
  TALLY();
  if (!strncmp(max_nodes, "UNREADABLE", 10)) {
    failures++;
    fprintf(stderr, "FAIL the C compiler's MAX_NODES could not be read from %s, "
                    "so the LIMITS banner below cannot state it: %s\n",
            NOVA_C_REL, max_nodes);
  }
  printf("LIMITS overlap_w67_max_nodes=DISJOINT; MAX_NODES=%s is the C "
         "compiler's own expression and statement table in nova.c and bounds "
         "COMPILING NOVA SOURCE; it is READ FROM %s AT RUN TIME, not typed "
         "here, because a stale literal in a printf goes unnoticed; its "
         "derivation is the comment above the constant in nova.c; these six "
         "bound NTASM COMP-TIME EXPANSION in "
         "compiler/nova/macros/macro_expand.nova and are read from a different "
         "declaration; the two share no file, no constant and no failure path\n",
         max_nodes, NOVA_C_REL);
  printf("LIMITS partial_product_checked=the caller output buffer, the artifact "
         "from nt_compile_many, and the run directory, after every refusal, each "
         "with a control\n");
  printf("GATES_DONE bounds_ceiling checks=%u failures=%u refusals=%u "
         "partial_products=%u proofs_invalid=%u\n",
         checks, failures, refusals_observed, partial_products_observed,
         proofs_invalid);
  printf("NTASM_NOVA_BOUNDS_CEILING checks=%u failures=%u refusals=%u "
         "partial_products=%u proofs_invalid=%u\n",
         checks, failures, refusals_observed, partial_products_observed,
         proofs_invalid);
  if (compiled) nt_artifact_free(&a);
  for (unsigned i = 0; i < 6; i++) free(sources[i]);
  return failures ? 1 : 0;
}
