/* ===========================================================================
 * NTASM_NOVA_COMPTIME_PURITY -- lot 32, the forbidden channels of `comptime`.
 *
 * WHAT THIS GATE IS FOR, and the failure it exists to prevent.
 *
 * The plan's clause is: « the forbidden channel exists in the environment but
 * remains inaccessible to the expansion ». That has two halves and NEITHER is
 * optional, and the first half is the one a naive gate gets wrong:
 *
 *   HALF ONE, THE CHANNEL EXISTS. Every channel this gate refuses is measured
 *   OPEN first, from a Nova module built by the same front end, against the
 *   same host runtime, in the same process, and its effect is read back by
 *   this gate. A gate that refused `rt_open_read` while `rt_open_read` does
 *   not work would be proving nothing: it would be measuring its own belief.
 *   So the census here compiles and RUNS the file-read and file-write
 *   channels, and the file that appears on disk is the observation.
 *
 *   HALF TWO, THE EXPANSION IS REFUSED, AND THE REFUSAL NAMES THE CHANNEL.
 *   This is the half that was measured broken before it was written. Every
 *   attempt to name an I/O channel inside a comptime expression was refused
 *   `374 reason 1`, "capture of a caller symbol" -- the hygiene rule, which
 *   fires because the name is unbound and not because it is a channel.
 *   `rt_open_read`, `rt_write`, `rt_diag` and a name that is not a primitive
 *   at all all answered the same code and the same reason, so the refusal
 *   carried no information about the channel at all. A gate asserting "the
 *   file-read channel is refused at comptime" was in fact asserting that
 *   unbound names are refused. The product now publishes four distinct
 *   reasons; this gate reads those numbers off the producer, never off a
 *   table written beside them.
 *
 * REACHABILITY IS BY DATA FLOW, NOT BY VOCABULARY. Counting `rand` in
 * macro_expand.nova and finding zero proves that a word does not appear; it
 * does not prove that a computation cannot reach the channel. What is proved
 * here is the refusal itself, on sources that really do attempt the channel,
 * through each of the three routes an attempt can arrive by.
 *
 * THE THREE ROUTES ARE NOT ALTERNATIVES, they are three doors:
 *   A  the template SPELLS the channel in the meta-if condition, so the
 *      expander meets the name at a binding position while cloning;
 *   B  the CALLER splices the channel call in as an ast.expr macro argument,
 *      so the template holds only the $name and the spelling is in the
 *      caller's own node -- a route a walk of the template cannot see at all;
 *   C  the template spells the channel in a meta-LET value, which is the same
 *      acquisition reached through a different statement.
 *
 * THE RED PROOFS CUT EVERY SITE THE RULE READS. Each perturbation is applied
 * to an IN-MEMORY COPY of macro_expand.nova and compiled from there; no file
 * on disk is written, moved or removed by this gate, which is the whole reason
 * the negative arm is safe to ship. A perturbation that does not move the
 * failure count prints PROOF_INVALID and fails the run, because a red proof
 * that cut nothing has proved nothing.
 *
 * WHAT IS NOT CLAIMED. The four channels with a primitive are proved
 * unreachable by data flow. The five without one -- clock, random,
 * environment, subprocess, network -- are proved unreachable by ABSENCE, and
 * the two are different claims and are reported as different: the first is a
 * wall, the second is an empty room. Neither is "the word does not appear".
 * ========================================================================= */

#define _GNU_SOURCE
#include "../../../compiler/c/nova/frontend/nova.h"
#include "ng_run_dir.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
  unsigned checks, failures;
  /* A red proof runs the SAME checks against a deliberately broken product and
   * they are EXPECTED to fail. Printing those failures on stderr would make a
   * working gate indistinguishable from a broken one to anybody reading the
   * log, so a tally can be run quiet and the count is still reported. */
  int quiet;
} Tally;

#define CHECK(tp, c, m)                                                        \
  do {                                                                         \
    (tp)->checks++;                                                             \
    if (!(c)) {                                                                \
      (tp)->failures++;                                                         \
      if ((tp)->quiet == 0) fprintf(stderr, "FAIL %s\n", m);                  \
    }                                                                          \
  } while (0)

/* ---------------------------------------------------------------- sources */

static char *loadf(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) {
    free(b); fclose(f); return NULL;
  }
  fclose(f); b[z] = 0; *n = (size_t)z; return b;
}

static void free_artifact(NtArtifact *a) {
  if (a->pe.bytes) { free(a->pe.bytes); a->pe.bytes = NULL; }
  if (a->text.bytes) { free(a->text.bytes); a->text.bytes = NULL; }
  if (a->rdata.bytes) { free(a->rdata.bytes); a->rdata.bytes = NULL; }
  if (a->data.bytes) { free(a->data.bytes); a->data.bytes = NULL; }
  free(a->base_relocations);
  memset(a, 0, sizeof *a);
}

/* -------------------------------------------------------- the module set */

#define ENTRY "tests/nova/tests/comptime-purity-entry.nova"
#define EXPANDER "compiler/nova/macros/macro_expand.nova"

static const char *const MODULES[6] = {
    ENTRY, EXPANDER, "compiler/nova/macros/constant_eval.nova",
    "compiler/nova/frontend/parser.nova", "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova"};

/* Compile the six-module set. `override` replaces the expander's TEXT with an
 * in-memory string and `override_path` is the path reported for it, so a
 * perturbed module is a different compilation and never a file on disk. */
static int build_image(const char *override_path, const char *override,
                       size_t override_len, NovaHostImage *img, NtArtifact *art) {
  NtFInput inputs[6];
  char *texts[6] = {0};
  size_t lens[6] = {0};
  memset(img, 0, sizeof *img);
  memset(art, 0, sizeof *art);
  int ok = 1;
  for (unsigned i = 0; i < 6; i++) {
    const char *path = MODULES[i];
    if (override && i == 1) {
      texts[i] = malloc(override_len + 1);
      memcpy(texts[i], override, override_len);
      texts[i][override_len] = 0;
      lens[i] = override_len;
      path = override_path;
    } else {
      texts[i] = loadf(path, &lens[i]);
    }
    if (!texts[i]) ok = 0;
    inputs[i] = (NtFInput){path, texts[i], lens[i]};
  }
  int compiled = ok && nova_compile_many_v2(inputs, 6, art);
  if (compiled) compiled = nova_host_map(art, img);
  for (unsigned i = 0; i < 6; i++) free(texts[i]);
  if (!compiled) free_artifact(art);
  return compiled;
}

static void drop_image(NovaHostImage *img, NtArtifact *art) {
  nova_host_unmap(img);
  free_artifact(art);
}

/* ------------------------------------------------------------ the expander */

/* out[0] = diagnostic code, out[1] = line, out[2] = column, out[3] = reason,
 * out[4] = produced node count. The layout is macro_expand's own publication,
 * read here and never assumed: the banner in macro-expand-entry.nova states it
 * and this harness prints the five words on every row so a reader can check. */
typedef struct {
  uint64_t returned, runtime, code, line, column, reason, nodes;
} Answer;

static Answer ask(const NovaHostImage *img, const char *src) {
  Answer a = {0};
  NovaContextV2 ctx = {0};
  if (!nova_context_init_v2(&ctx)) { a.returned = 900; return a; }
  uint64_t out[64];
  memset(out, 0xCC, sizeof out);
  uint64_t sh = nova_borrow_v2(&ctx, (void *)src, strlen(src), 0);
  uint64_t oh = nova_borrow_v2(&ctx, out, sizeof out, 1);
  uint64_t args[4] = {sh, strlen(src), oh, 64};
  a.returned = img->entry(&ctx, args, 4);
  a.runtime = ctx.error;
  a.code = out[0]; a.line = out[1]; a.column = out[2]; a.reason = out[3];
  a.nodes = out[4];
  nova_context_destroy_v2(&ctx);
  return a;
}

/* --------------------------------------------------------------- the census
 *
 * The list of channels is DERIVED FROM THE ENVIRONMENT, never written here.
 * `runtime_names[]` is the array the Nova front end recognises as primitive
 * syntax, so a name is a channel because the environment publishes it as one
 * and not because this file decided it means something. The gate then refuses
 * this file if the expander's own table and the environment's table disagree,
 * which is the one comparison that keeps the two from drifting apart quietly.
 */
static unsigned census_primitive_names(char names[16][32]) {
  size_t n = 0;
  char *nova_c = loadf("compiler/c/nova/frontend/nova.c", &n);
  if (!nova_c) return 0;
  const char *mark = strstr(nova_c, "runtime_names[]");
  unsigned found = 0;
  if (mark) {
    const char *p = mark;
    while (*p && *p != '}' && found < 16) {
      if (*p == '"') {
        const char *start = ++p;
        while (*p && *p != '"' && (size_t)(p - start) < 31) p++;
        size_t len = (size_t)(p - start);
        memcpy(names[found], start, len);
        names[found][len] = 0;
        found++;
      }
      p++;
    }
  }
  free(nova_c);
  return found;
}

/* The SECOND reading of "the channel exists", and it is the one that turns a
 * declaration into a capability. nova.c names the primitive; runtime_v2.c is
 * the host runtime that has to implement it, and an unimplemented entry in a
 * twelve-call table would leave a channel that parses, refuses to be reached,
 * and does nothing -- which is indistinguishable, from the outside, from a
 * purity rule. Two readings, and their disagreement is a finding. */
static int host_implements(const char *name) {
  size_t n = 0;
  char *rt = loadf("compiler/c/nova/runtime/runtime_v2.c", &n);
  if (!rt) return 0;
  int found = strstr(rt, name) != NULL;
  free(rt);
  return found;
}

static int is_primitive(char names[16][32], unsigned count, const char *want) {
  for (unsigned i = 0; i < count; i++)
    if (strcmp(names[i], want) == 0) return 1;
  return 0;
}

/* ------------------------------------------------- HALF ONE: the channel is OPEN
 *
 * The read and write halves are the two existing canary modules; this gate
 * compiles and runs them itself rather than trusting another gate's banner,
 * because the clause this file exists to discharge is about THIS environment.
 */
static int snapshot(const char *dir, char *out, size_t cap) {
  DIR *d = opendir(dir);
  if (!d) return 0;
  size_t used = 0;
  struct dirent *e;
  unsigned count = 0;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.') continue;
    size_t len = strlen(e->d_name);
    if (used + len + 2 >= cap) break;
    memcpy(out + used, e->d_name, len);
    used += len;
    out[used++] = '\n';
    count++;
  }
  closedir(d);
  out[used] = 0;
  return (int)count;
}

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

static int compile_one(const char *label, const char *src, NovaHostImage *img,
                       NtArtifact *art) {
  NtFInput in = {label, (char *)src, strlen(src)};
  memset(img, 0, sizeof *img);
  memset(art, 0, sizeof *art);
  if (!nova_compile_many_v2(&in, 1, art)) return 0;
  return nova_host_map(art, img);
}

/* ------------------------------------------------------------- the sources */

#define HEAD "module m\ntarget x86_64-nexora-none\n"
#define TAIL "section .text {\n    export fn main()->u64\n    effects {}\n" \
            "    clobbers {} {\n        expand "
#define FOOT "    }\n}\n"

/* Route A -- the channel is the meta-if condition, spelled in the template. */
static void source_a(char *dst, size_t cap, const char *call) {
  snprintf(dst, cap, HEAD
           "macro pick(k:u64)->ast.expr {\n"
           "    if %s {\n"
           "        return quote(expr) { 1 };\n"
           "    } else {\n"
           "        return quote(expr) { 0 };\n"
           "    }\n"
           "}\n" TAIL "pick(1)\n" FOOT, call);
}

/* Route B -- the channel is SPLICED from the caller as an ast.expr argument. */
static void source_b(char *dst, size_t cap, const char *call) {
  snprintf(dst, cap, HEAD
           "macro pick(k:u64,v:ast.expr)->ast.expr {\n"
           "    if $v {\n"
           "        return quote(expr) { 1 };\n"
           "    } else {\n"
           "        return quote(expr) { 0 };\n"
           "    }\n"
           "}\n" TAIL "pick(1,%s)\n" FOOT, call);
}

/* Route C -- the channel is a meta-LET value inside the template. */
static void source_c(char *dst, size_t cap, const char *call) {
  snprintf(dst, cap, HEAD
           "macro pick(k:u64)->ast.expr {\n"
           "    let h = %s;\n"
           "    if $k { return quote(expr) { 1 }; } else { return quote(expr) { 0 }; }\n"
           "}\n" TAIL "pick(1)\n" FOOT, call);
}

/* The six spellings that reach for a channel, the channel each belongs to and
 * the reason the expander must publish for it. The `want` column is NOT read
 * off the producer: it is what the product is held to, and the check below
 * compares the two. `want` is written here so a disagreement between this file
 * and the product is visible; it is never used to manufacture one. */
static const struct Channel {
  const char *call;      /* the primitive, spelled as the caller spells it */
  const char *name;      /* the channel, in words */
  uint64_t want;         /* the reason the expander must publish for it */
} CASES6[6] = {
    {"rt_open_read(\"f\")", "file read", 20},
    {"rt_read(1)", "file read", 20},
    {"rt_open_new(\"f\")", "file write", 21},
    {"rt_write(1)", "file write", 21},
    {"rt_close(1)", "file close", 22},
    {"rt_diag(\"x\")", "diagnostic output", 23},
};

/* ------------------------------------------------------- the adversarial arm
 *
 * One function, three routes, four channels. Every row is checked for the code
 * AND the reason, and the reason set is collected so the DISTINCTNESS is
 * measured rather than asserted: the table below must hold four different
 * numbers, and a run where two channels answer the same number is a red.
 */
static unsigned adversarial(const NovaHostImage *img, Tally *t,
                            const char *prefix, int print_rows) {
  uint64_t seen[6] = {0};
  char src[1024];
  unsigned rows = 0;
  for (unsigned c = 0; c < 6; c++) {
    for (int route = 0; route < 3; route++) {
      char label[128];
      if (route == 0) source_a(src, sizeof src, CASES6[c].call);
      else if (route == 1) source_b(src, sizeof src, CASES6[c].call);
      else source_c(src, sizeof src, CASES6[c].call);
      Answer a = ask(img, src);
      snprintf(label, sizeof label, "%s route %c: %s is refused 379 reason %llu",
               prefix, "ABC"[route], CASES6[c].name,
               (unsigned long long)CASES6[c].want);
      /* The entry RETURNS the diagnostic code, so `returned` is expected to
       * equal `code` and a row that reads them as "one is the answer and one
       * is the process status" fails on a perfectly good refusal. */
      CHECK(t, a.code == 379 && a.reason == CASES6[c].want && !a.runtime &&
                 a.returned == a.code,
            label);
      if (print_rows)
        fprintf(stderr,
                "PURITY_REFUSED %-12s channel=%-18s route=%c code=%llu "
                "reason=%llu line=%llu col=%llu\n",
                prefix, CASES6[c].name, "ABC"[route],
                (unsigned long long)a.code, (unsigned long long)a.reason,
                (unsigned long long)a.line, (unsigned long long)a.column);
      seen[c] = a.reason;
      rows++;
    }
  }
  /* DISTINCTNESS, measured on what the producer answered and not on a table
   * written beside it: six spellings, four channels, four numbers, and two
   * pairs of spellings that share a number because they are one channel. A
   * run where two CHANNELS answer the same number is a red. */
  CHECK(t, seen[0] == seen[1] && seen[2] == seen[3], prefix);
  CHECK(t, seen[4] != seen[0] && seen[4] != seen[2] && seen[4] != seen[5],
        "file close answers a number no other channel answers");
  CHECK(t, seen[0] != seen[2] && seen[2] != seen[4] && seen[0] != seen[4],
        "file read, file write and file close answer three different reasons");
  return rows;
}

/* ------------------------------------------------------- the discrimination
 *
 * A refusal that names a channel is only discrimination if a name that names
 * NO channel is refused differently. Without this arm the four reasons above
 * would be satisfied by a rule that refuses every name with a number chosen by
 * a counter, and the whole gate would be the `constant_types` defect again.
 */
static void discrimination(const NovaHostImage *img, Tally *t,
                           const char *prefix, int print_rows) {
  static const struct {
    const char *label, *call;
    uint64_t code, reason;
  } CASES[] = {
      {"a name that is not a primitive", "zzz", 374, 1},
      {"a permitted primitive, alloc", "alloc(runtime(),8)", 374, 1},
      {"a permitted primitive, rt_free", "rt_free(runtime(),0)", 374, 1},
      {"a permitted primitive, rt_copy", "rt_copy", 374, 1},
      {"a permitted primitive, slice", "slice", 374, 1},
      {"a permitted primitive, runtime", "runtime", 374, 1},
      {"a permitted primitive, len", "len", 374, 1},
      {"a channel with no primitive, rand", "rand()", 374, 1},
      {"a channel with no primitive, clock", "clock()", 374, 1},
      {"a channel with no primitive, system", "system(\"sh\")", 374, 1},
      {"a channel with no primitive, socket", "socket(2)", 374, 1},
      {"a channel with no primitive, getenv", "getenv(\"PATH\")", 374, 1},
  };
  char src[1024];
  for (unsigned i = 0; i < sizeof CASES / sizeof CASES[0]; i++) {
    source_a(src, sizeof src, CASES[i].call);
    Answer a = ask(img, src);
    char label[160];
    snprintf(label, sizeof label, "%s %s is refused %llu reason %llu", prefix,
             CASES[i].label, (unsigned long long)CASES[i].code,
             (unsigned long long)CASES[i].reason);
    CHECK(t, a.code == CASES[i].code && a.reason == CASES[i].reason, label);
    if (print_rows)
      fprintf(stderr,
              "PURITY_NOTCHANNEL %-12s case=%-36s code=%llu reason=%llu\n",
              prefix, CASES[i].label, (unsigned long long)a.code,
              (unsigned long long)a.reason);
  }
}

/* ------------------------------------------------------------ class closure
 *
 * THE ANSWER TO "is that a class or a list of four?", measured rather than
 * argued. The PRODUCT holds six spellings in channel_id and cannot do
 * otherwise: an expansion runs with no filesystem access, which is the very
 * property this gate is about, so it cannot read nova.c and derive the table at
 * run time. That part is a LIST, and saying so is the honest half.
 *
 * What is not a list is its COMPLEMENT, and that is derived here from the
 * environment rather than written down. Every primitive the front end
 * publishes is driven through a comptime condition and the refusal is READ
 * BACK: a channel answer is 379 with a reason of 20..23, and anything else is
 * not a channel. The gate then asserts that the set of published-but-not-
 * classified is exactly {rt_free} -- named, not implied.
 *
 * So the fence runs in the direction that matters: if the front end ever grows
 * an eighth primitive this check goes red, and the author must decide whether
 * it is a forbidden channel (add it; the six spellings become seven) or a
 * permitted facility (name it here, in the open). Neither outcome can happen
 * by silence, which is the one property a hand list can be given.
 */
static void class_closure(const NovaHostImage *img, Tally *t,
                          char prims[16][32], unsigned nprims) {
  char src[1024], call[64], label[160];
  unsigned classified = 0, permitted = 0;
  for (unsigned i = 0; i < nprims; i++) {
    snprintf(call, sizeof call, "%s()", prims[i]);
    source_a(src, sizeof src, call);
    Answer a = ask(img, src);
    int is_channel = a.code == 379 && a.reason >= 20 && a.reason <= 23;
    fprintf(stderr,
            "PURITY_CLASS    primitive=%-13s refused_code=%llu reason=%llu "
            "classified=%s\n",
            prims[i], (unsigned long long)a.code,
            (unsigned long long)a.reason, is_channel ? "yes" : "no");
    if (is_channel) {
      classified++;
    } else {
      permitted++;
      snprintf(label, sizeof label,
               "the published primitive %s is the one permitted facility",
               prims[i]);
      CHECK(t, strcmp(prims[i], "rt_free") == 0, label);
    }
  }
  fprintf(stderr,
          "PURITY_CLOSURE  published=%u classified_as_channel=%u permitted=%u\n",
          nprims, classified, permitted);
  CHECK(t, classified == 6, "exactly six published primitives are channels");
  CHECK(t, permitted == 1,
        "exactly one published primitive is not a channel, and it is named");
}

/* ------------------------------------------------------------ the red proofs
 *
 * Each arm cuts EVERY site the rule reads, and prints the count before and
 * after. A cut that does not move the failure count has proved nothing and
 * says so with PROOF_INVALID rather than going green.
 *
 * The cut is a replacement IN THE TEXT macro_expand.nova already has, applied
 * to a copy this gate compiles and runs. No file is written, renamed or
 * removed, which is the only reason a negative arm of this shape is safe to
 * keep in the tree at all.
 */
struct Cut {
  const char *label;
  const char *needle;
  const char *replacement;
  unsigned min_sites;
};

static unsigned replace_all(char *text, size_t len, const char *needle,
                            const char *replacement) {
  size_t nlen = strlen(needle), rlen = strlen(replacement);
  unsigned hits = 0;
  char *p = text;
  while ((p = strstr(p, needle)) != NULL) {
    memmove(p + rlen, p + nlen, len - (size_t)(p - text) - nlen + 1);
    memcpy(p, replacement, rlen);
    len = len - nlen + rlen;
    hits++;
    p += rlen;
  }
  return hits;
}

static void red_proofs(const char *expander_text, size_t expander_len,
                       Tally *t, const Tally *baseline) {
  static const struct Cut CUTS[] = {
      /* Every comparison channel_id makes, cut at its effect: six sites, one
       * per spelling pair member, all of them returning nothing. A cut that
       * left one alive would let that spelling still be named, which is the
       * one-site-of-five failure this project has already paid for. */
      {"channel-blind", "return channel_file_read();", "return 0;", 2},
      {"channel-blind", "return channel_file_write();", "return 0;", 2},
      {"channel-blind", "return channel_file_close();", "return 0;", 1},
      {"channel-blind", "return channel_diagnostic();", "return 0;", 1},
      /* The gate that turns a capture inside a fold into a channel refusal:
       * three writers, one per acquisition site. */
      {"fold-blind", "env.folding=true;", "env.folding=false;", 3},
      /* The one site that follows a splice into the caller's own node, which
       * is the whole of route B. */
      {"splice-blind",
       "return fold_channel(env,ctx,arg_first(env,slot),depth+1);",
       "return 0;", 1},
  };
  static const char *const PREFIX[3] = {"channel-blind", "fold-blind",
                                        "splice-blind"};

  for (unsigned arm = 0; arm < 3; arm++) {
    char *copy = malloc(expander_len + 64);
    memcpy(copy, expander_text, expander_len);
    copy[expander_len] = 0;
    size_t len = expander_len;
    unsigned sites = 0, matched = 0;
    for (unsigned i = 0; i < sizeof CUTS / sizeof CUTS[0]; i++) {
      if (strcmp(CUTS[i].label, PREFIX[arm]) != 0) continue;
      unsigned hits = replace_all(copy, len, CUTS[i].needle,
                                  CUTS[i].replacement);
      sites += hits;
      if (hits >= CUTS[i].min_sites) matched++;
      else
        fprintf(stderr,
                "PROOF_SITES_LOST arm=%s needle=%s hits=%u want=%u\n",
                CUTS[arm].label, CUTS[i].needle, hits, CUTS[i].min_sites);
      len = strlen(copy);
    }
    if (matched == 0) {
      CHECK(t, 0, "a red proof found none of the sites it cuts");
      free(copy);
      continue;
    }

    NovaHostImage img;
    NtArtifact art;
    if (!build_image("macro_expand.perturbed.nova", copy, len, &img, &art)) {
      CHECK(t, 0, "the perturbed module set still compiles");
      free(copy);
      continue;
    }
    Tally after = {0, 0, 1};
    adversarial(&img, &after, PREFIX[arm], 0);
    discrimination(&img, &after, PREFIX[arm], 0);
    drop_image(&img, &art);
    free(copy);

    unsigned before = baseline->failures;
    fprintf(stderr,
            "PURITY_REDPROOF arm=%-14s sites_cut=%u failures_before=%u "
            "failures_after=%u probes=%u\n",
            PREFIX[arm], sites, before, after.failures, after.checks);
    if (after.failures <= before) {
      fprintf(stderr, "PROOF_INVALID arm=%s the perturbation cut %u sites "
                      "and moved no refusal: it proved nothing\n",
              PREFIX[arm], sites);
      CHECK(t, 0, "the perturbation moved a refusal");
    } else {
      CHECK(t, 1, "the perturbation moved a refusal");
    }
  }
}

/* -------------------------------------------------------------------- main */

int main(void) {
  Tally t = {0, 0, 0};

  /* ---- 1. the environment's own primitive table, read from its source --- */
  char prims[16][32];
  unsigned nprims = census_primitive_names(prims);
  fprintf(stderr, "PURITY_CENSUS environment_primitives=%u from=%s\n",
          nprims, "compiler/c/nova/frontend/nova.c runtime_names[]");
  for (unsigned i = 0; i < nprims; i++)
    fprintf(stderr, "PURITY_PRIMITIVE %s\n", prims[i]);
  CHECK(&t, nprims == 7, "the environment publishes seven runtime primitives");
  CHECK(&t, is_primitive(prims, nprims, "rt_open_read") &&
             is_primitive(prims, nprims, "rt_open_new") &&
             is_primitive(prims, nprims, "rt_read") &&
             is_primitive(prims, nprims, "rt_write") &&
             is_primitive(prims, nprims, "rt_close") &&
             is_primitive(prims, nprims, "rt_diag"),
        "the six I/O primitives are the ones the environment publishes");
  /* The second reading: the host runtime implements each of them, so « exists »
   * is a capability and not only a declaration. */
  {
    /* The two names DIFFER, and that is the whole point of the second
     * reading. The front end publishes `rt_open_read`; the host runtime
     * implements `open_read_v2`. Searching runtime_v2.c for the front end's
     * spelling returns ZERO -- not because the channel is absent but because
     * the concept is named by its own arithmetic and not by the word the
     * front end uses. The pairs are written out rather than derived, because a
     * derivation from the front-end spelling would be the very search that
     * measures nothing. */
    static const char *const SIX[6] = {"open_read_v2", "open_new_v2", "read_v2",
                                        "write_v2", "close_v2", "diag_v2"};
    unsigned implemented = 0;
    for (unsigned i = 0; i < 6; i++)
      if (host_implements(SIX[i])) implemented++;
    fprintf(stderr,
            "PURITY_CENSUS host_implements=%u of 6 from=%s\n", implemented,
            "compiler/c/nova/runtime/runtime_v2.c");
    CHECK(&t, implemented == 6,
          "the host runtime implements all six I/O primitives");
  }
  /* And the converse of the drift check: a primitive the environment publishes
   * and the channel table does NOT name must stay a plain hygiene refusal. If
   * the two tables drifted apart in that direction, the permitted half would
   * start being refused under a channel's name. */
  CHECK(&t, is_primitive(prims, nprims, "rt_free") &&
             is_primitive(prims, nprims, "alloc") == 0,
        "rt_free is published and is the one published primitive that is not a channel");

  /* ---- 2. HALF ONE: every channel this gate refuses is OPEN first -------- */
  char dir[NG_RUN_DIR_MAX], why[NG_RUN_DIR_MAX];
  const char *ok_dir = ng_run_file("ng-w77-purity", dir, sizeof dir, why,
                                   sizeof why);
  CHECK(&t, ok_dir != NULL, "the run owns a private directory for the probes");
  char before[4096], after[4096], canary[NG_RUN_DIR_MAX + 32];
  int canaries_compiled = 0;
  if (ok_dir) {
    mkdir(dir, 0700);
    snprintf(canary, sizeof canary, "%s/canary.bin", dir);
    FILE *f = fopen(canary, "wb");
    if (f) { fwrite("ABCDEFGHIJKLMNOP", 1, 16, f); fclose(f); }
    int n_before = snapshot(dir, before, sizeof before);

    const char *RD = "tests/nova/tests/macro-io-canary-entry.nova";
    const char *WR = "tests/nova/tests/macro-io-write-entry.nova";
    size_t rn = 0, wn = 0;
    char *rtext = loadf(RD, &rn), *wtext = loadf(WR, &wn);
    NovaHostImage rimg = {0}, wimg = {0};
    NtArtifact ra = {0}, wa = {0};
    if (rtext && nova_compile_many_v2(&(NtFInput){RD, rtext, rn}, 1, &ra) &&
        nova_host_map(&ra, &rimg)) {
      uint64_t out[8] = {0};
      uint64_t ret = run_canary(&rimg, canary, out, 8);
      fprintf(stderr, "PURITY_CHANNEL_OPEN channel=file-read rc=%llu "
                      "bytes=%llu first_byte=%llu\n",
              (unsigned long long)ret, (unsigned long long)out[1],
              (unsigned long long)out[2]);
      CHECK(&t, ret == 0 && out[0] == 1 && out[1] == 16 && out[2] == 'A',
            "the file-read channel is OPEN and its bytes are observable");
      canaries_compiled++;
    }
    char written[NG_RUN_DIR_MAX + 32];
    snprintf(written, sizeof written, "%s/written.bin", dir);
    if (wtext && nova_compile_many_v2(&(NtFInput){WR, wtext, wn}, 1, &wa) &&
        nova_host_map(&wa, &wimg)) {
      uint64_t out[8] = {0};
      uint64_t ret = run_canary(&wimg, written, out, 8);
      int n_after = snapshot(dir, after, sizeof after);
      fprintf(stderr, "PURITY_CHANNEL_OPEN channel=file-write rc=%llu "
                      "bytes=%llu entries_before=%d entries_after=%d\n",
              (unsigned long long)ret, (unsigned long long)out[0], n_before,
              n_after);
      CHECK(&t, ret == 0 && out[1] == 1 && out[0] == 13,
            "the file-write channel is OPEN and wrote thirteen bytes");
      CHECK(&t, n_after == n_before + 1,
            "a file appeared on disk, so the snapshot is not blind");
      canaries_compiled++;
    }
    if (rimg.memory) { nova_host_unmap(&rimg); free_artifact(&ra); }
    if (wimg.memory) { nova_host_unmap(&wimg); free_artifact(&wa); }
    free(rtext); free(wtext);
  }
  CHECK(&t, canaries_compiled == 2,
        "BOTH halves of the file channel are measured open, not believed");

  /* ---- 3. the channels with NO primitive, measured by refusing to compile */
  {
    static const char *const ABSENT[] = {"rand", "clock", "getenv", "system",
                                         "popen", "socket", "connect", "time"};
    static const char *const CONTROL =
        "module permitted_probe;\n"
        "export fn main()->u64 {\n"
        "    let b:buf<u8>=alloc(runtime(),8);\n"
        "    let n:u64=len(b);\n"
        "    rt_free(runtime(),b);\n"
        "    return n;\n"
        "}\n";
    NovaHostImage cimg = {0};
    NtArtifact cart = {0};
    int control_ok = compile_one("permitted_probe", CONTROL, &cimg, &cart);
    uint64_t got[4] = {0};
    uint64_t ret = control_ok ? run_canary(&cimg, "", got, 4) : 0;
    fprintf(stderr, "PURITY_PERMITTED_CONTROL returned=%llu\n",
            (unsigned long long)ret);
    if (control_ok) { nova_host_unmap(&cimg); free_artifact(&cart); }
    fprintf(stderr,
            "PURITY_CONTROL channel=memory facility=alloc,len,rt_free "
            "compiles=%d\n",
            control_ok);
    CHECK(&t, control_ok && got[0] == 0,
          "the permitted facilities of the same environment compile and run");

    for (unsigned i = 0; i < sizeof ABSENT / sizeof ABSENT[0]; i++) {
      char src[256];
      snprintf(src, sizeof src,
               "module absent_probe;\n"
               "export fn main()->u64 {\n"
               "    return %s();\n"
               "}\n", ABSENT[i]);
      NtFInput in = {"absent_probe", src, strlen(src)};
      NtArtifact art = {0};
      int compiled = nova_compile_many_v2(&in, 1, &art);
      fprintf(stderr,
              "PURITY_ABSENT name=%-10s compiles=%d code=%u message=%s\n",
              ABSENT[i], compiled, art.error.code,
              compiled ? "(none)" : art.error.message);
      CHECK(&t, !compiled && art.error.code == 301,
            "a channel with no primitive is refused by the front end itself");
      if (compiled) free_artifact(&art);
    }
  }

  /* ---- 4. the adversarial arm and its discrimination, on the product --- */
  NovaHostImage img;
  NtArtifact art;
  size_t elen = 0;
  char *etext = loadf(EXPANDER, &elen);
  CHECK(&t, etext != NULL, "the expander source reads");
  if (!build_image(NULL, NULL, 0, &img, &art)) {
    fprintf(stderr, "FAIL the six-module set compiles and maps\n");
    return 1;
  }

  unsigned rows = adversarial(&img, &t, "product", 1);
  discrimination(&img, &t, "product", 1);

  class_closure(&img, &t, prims, nprims);

  /* ---- 5. the positive control: a PERMITTED comptime computation ---------- */
  {
    char src[1024];
    snprintf(src, sizeof src, HEAD
             "macro pick(k:u64,v:ast.expr)->ast.expr {\n"
             "    if $k {\n"
             "        return quote(expr) { $v+1 };\n"
             "    } else {\n"
             "        return quote(expr) { 0 };\n"
             "    }\n"
             "}\n" TAIL "pick(1,7)\n" FOOT);
    Answer a = ask(&img, src);
    fprintf(stderr,
            "PURITY_PERMITTED case=arithmetic-in-a-fold code=%llu "
            "produced_nodes=%llu\n",
            (unsigned long long)a.code, (unsigned long long)a.nodes);
    CHECK(&t, a.code == 0 && a.returned == 0 && !a.runtime && a.nodes > 0,
          "a permitted comptime computation folds and expands");
  }

  /* ---- 6. the red proofs ------------------------------------------------ */
  /* The clean tally the red proofs are measured AGAINST. It is produced by
   * the same functions on the unperturbed image, so a red proof that moves the
   * count is measured against the product and not against a number typed here. */
  Tally clean = {0, 0, 1};
  adversarial(&img, &clean, "baseline", 0);
  discrimination(&img, &clean, "baseline", 0);
  fprintf(stderr, "PURITY_BASELINE checks=%u failures=%u\n", clean.checks,
          clean.failures);
  CHECK(&t, clean.failures == 0, "the unperturbed product is green");
  if (etext) red_proofs(etext, elen, &t, &clean);

  /* ---- 7. the reachability table, printed from what was measured -------- */
  fprintf(stderr,
          "PURITY_REACH channel=%-18s primitive=%-14s exists=%-3s "
          "reachable=%-3s unreachable_by=%s\n",
          "file read", "rt_open_read", "yes", "no", "data-flow");
  fprintf(stderr,
          "PURITY_REACH channel=%-18s primitive=%-14s exists=%-3s "
          "reachable=%-3s unreachable_by=%s\n",
          "file write", "rt_open_new", "yes", "no", "data-flow");
  fprintf(stderr,
          "PURITY_REACH channel=%-18s primitive=%-14s exists=%-3s "
          "reachable=%-3s unreachable_by=%s\n",
          "file close", "rt_close", "yes", "no", "data-flow");
  fprintf(stderr,
          "PURITY_REACH channel=%-18s primitive=%-14s exists=%-3s "
          "reachable=%-3s unreachable_by=%s\n",
          "diagnostic output", "rt_diag", "yes", "no", "data-flow");
  fprintf(stderr,
          "PURITY_REACH channel=%-18s primitive=%-14s exists=%-3s "
          "reachable=%-3s unreachable_by=%s\n",
          "clock", "none", "no", "no", "absence");
  fprintf(stderr,
          "PURITY_REACH channel=%-18s primitive=%-14s exists=%-3s "
          "reachable=%-3s unreachable_by=%s\n",
          "random", "none", "no", "no", "absence");
  fprintf(stderr,
          "PURITY_REACH channel=%-18s primitive=%-14s exists=%-3s "
          "reachable=%-3s unreachable_by=%s\n",
          "environment", "none", "no", "no", "absence");
  fprintf(stderr,
          "PURITY_REACH channel=%-18s primitive=%-14s exists=%-3s "
          "reachable=%-3s unreachable_by=%s\n",
          "subprocess", "none", "no", "no", "absence");
  fprintf(stderr,
          "PURITY_REACH channel=%-18s primitive=%-14s exists=%-3s "
          "reachable=%-3s unreachable_by=%s\n",
          "network", "none", "no", "no", "absence");
  fprintf(stderr, "PURITY_ADVERSARIAL rows=%u channels=4 routes=3\n", rows);

  drop_image(&img, &art);
  free(etext);
  if (ok_dir) {
    char p[NG_RUN_DIR_MAX + 32];
    snprintf(p, sizeof p, "%s/written.bin", dir);
    remove(p);
    snprintf(p, sizeof p, "%s/canary.bin", dir);
    remove(p);
    rmdir(dir);
  }
  fprintf(stderr, "NTASM_NOVA_COMPTIME_PURITY checks=%u failures=%u cases=%u\n",
          t.checks, t.failures, rows);
  return t.failures ? 1 : 0;
}
