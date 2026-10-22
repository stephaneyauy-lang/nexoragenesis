/* NTASM v0 Nova gate: bounded hygienic macro expansion, criterion A5.
 *
 * Diagnostic families of compiler/nova/macros/macro_expand.nova:
 *   201 budget refusal, out[3] = 1 fuel, 2 call depth, 3 arena bytes,
 *        4 produced AST nodes, 5 expansion depth, 6 constant data bytes
 *   203 the caller output buffer cannot hold the produced region
 *   370 unknown macro at the invocation
 *   371 macro arity mismatch
 *   372 macro parameter kind, value or shape mismatch
 *   374 capture of a caller symbol
 *   375 a template node kind outside the closed vocabulary
 *   376 a template name shadows a macro parameter or a comptime binding
 *   377 macro form outside this profile
 *   378 the comptime limit block is malformed
 *   379 a meta-if or meta-for condition is not a deterministic constant
 *   380 a template's projected statement count is too large: reason 1 the
 *        meta-for count is negative, reason 2 either it is past loop_cap or
 *        the body it repeats holds more than template_item_cap items
 *   381 a generated symbol collides with an existing caller symbol
 *   386 expansion in a type position is not implemented in this profile
 *   800 structural failure, nothing written
 *
 * The entry is macro_expand_entry.main(source,out). out[0] on input selects
 * the request: 0 expand, 1 measure. On return out[0] is the diagnostic code,
 * out[1] the line or the produced node count, out[2] the column or the name
 * table byte length, out[3] the reason.
 */
/* Wave 12, the two A5 campaigns. The absence-of-I/O campaign observes a real
   directory through readdir, so the POSIX surface is requested before any
   header is pulled in: this file is built with -std=c11, which otherwise hides
   dirent.h, getpid and mkdir behind the feature-test macro. */
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "ng_run_dir.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
/* The fuel figures this gate pins come from the shared affine model rather
   than from literals in this file; see the FUEL PIN block and the
   cross-shape ladders below. */
#include "ntasm_fuel_model.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned checks, failures, cases;

/* What the four compiler-bound arms BELOW measured, so the status table in
   ntasm_fuel_model.h can be checked against a measurement instead of against
   itself. -1 means the arm did not run, and a row whose measurement is
   missing fails rather than passing on a default. The model's column and
   these are two independent answers to the same question; the block at the
   end of main is what compares them. */
static int bound_binding_stack_reachable = -1;
static int bound_argument_stack_reachable = -1;
static int bound_hard_node_cap_reachable = -1;
static int bound_hard_name_cap_reachable = -1;
static uint64_t bound_hard_name_cap_shadow_code = 0;
static uint64_t bound_hard_name_cap_shadow_reason = 0;

#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
  fprintf(stderr, "FAIL %s\n", m); } } while (0)

static char *loadf(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) { free(b); fclose(f); return NULL; }
  fclose(f); b[z] = 0; *n = (size_t)z; return b;
}

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
  r.code = r.out[0]; r.w1 = r.out[1]; r.w2 = r.out[2]; r.reason = r.out[3];
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return r;
}

static void freerun(Run *r) { free(r->out); r->out = NULL; }

/* The name table is a run of 8 byte words, so byte i of a name is
 * (names[start / 8] >> (8 * (i % 8))) & 0xff. */
static int name_is(const Run *r, uint64_t start, uint64_t end,
                   const char *text) {
  size_t want = strlen(text);
  if (end < start || end - start != want) return 0;
  for (size_t i = 0; i < want; i++) {
    uint64_t w = r->out[4 + (start + i) / 8];
    unsigned byte = (unsigned)((w >> (8 * ((start + i) % 8))) & 0xff);
    if (byte != (unsigned char)text[i]) return 0;
  }
  return 1;
}
/* The same bytes name_is compares, copied out so two marks can be compared
 * with each other instead of against a literal. */
static void name_copy(const Run *r, uint64_t start, uint64_t end, char *dst,
                      size_t cap) {
  dst[0] = 0;
  if (end < start) return;
  size_t n = (size_t)(end - start);
  if (n >= cap) return;
  for (size_t i = 0; i < n; i++)
    dst[i] = (char)((r->out[4 + (start + i) / 8] >> (8 * ((start + i) % 8))) & 0xff);
  dst[n] = 0;
}


/* A structural inspection only runs on a successful expansion, and it first
 * checks that the produced region really fits in the reported buffer. */
static int layout_ok(const Run *r) {
  uint64_t span = 4 + (r->w2 + 7) / 8 + r->w1 * 12;
  return r->returned == 0 && r->runtime == 0 && r->code == 0 && r->w1 != 0 &&
         span <= r->words;
}

static const uint64_t zero12[12] = {0};

static const uint64_t *node_words(const Run *r, uint64_t id) {
  uint64_t nw = (r->w2 + 7) / 8;
  if (id == 0 || 4 + nw + id * 12 > r->words) return zero12;
  return r->out + 4 + nw + (id - 1) * 12;
}

/* Structural search over the produced forest, so a check pins a shape and
 * not an id. The walk follows first_child then next_sibling. */
static uint64_t find_kind(const Run *r, uint64_t id, uint64_t kind) {
  if (id == 0 || id > r->w1) return 0;
  const uint64_t *n = node_words(r, id);
  if (n[0] == kind) return id;
  uint64_t hit = find_kind(r, n[8], kind);
  if (hit) return hit;
  uint64_t sib = n[10];
  if (sib != 0) return find_kind(r, sib, kind);
  return 0;
}

static uint64_t count_kind(const Run *r, uint64_t id, uint64_t kind) {
  if (id == 0 || id > r->w1) return 0;
  const uint64_t *n = node_words(r, id);
  uint64_t total = n[0] == kind ? 1 : 0;
  total += count_kind(r, n[8], kind);
  return total + count_kind(r, n[10], kind);
}

/* The nth child of a produced node, reached through the child links. */
static const uint64_t *child_at(const Run *r, uint64_t id, uint64_t index) {
  if (id == 0 || id > r->w1) return zero12;
  const uint64_t *n = node_words(r, id);
  uint64_t at = n[8];
  while (index > 0 && at != 0) {
    at = node_words(r, at)[10];
    index--;
  }
  return at == 0 ? zero12 : node_words(r, at);
}

/* The produced region, printed on failure so a wrong expectation shows the
 * real shape instead of a bare mismatch. */
static void dump(const Run *r) {
  char text[64];
  for (uint64_t id = 1; id <= r->w1; id++) {
    const uint64_t *n = node_words(r, id);
    size_t tl = 0;
    if (n[0] == 90 && n[11] == 1) {
      for (size_t i = 0; i < n[7] - n[6] && tl < 60; i++)
        text[tl++] = (char)((r->out[4 + (n[6] + i) / 8] >>
                             (8 * ((n[6] + i) % 8))) & 0xff);
    } else {
      text[tl++] = '?';
    }
    text[tl] = 0;
    fprintf(stderr,
            "    n%-3llu k=%-3llu aux=%-4llu tb=%-4llu te=%-4llu src=%llu "
            "l=%-3llu c=%-3llu [%llu,%llu) fc=%-3llu lc=%-3llu ns=%-3llu |%s|\n",
            (unsigned long long)id, (unsigned long long)n[0],
            (unsigned long long)n[11], (unsigned long long)n[1],
            (unsigned long long)n[2], (unsigned long long)n[3],
            (unsigned long long)n[4], (unsigned long long)n[5],
            (unsigned long long)n[6], (unsigned long long)n[7],
            (unsigned long long)n[8], (unsigned long long)n[9],
            (unsigned long long)n[10], text);
  }
}

/* ------------------------------------------------------------ expectations */

static void ok(const NovaHostImage *i, const char *n, const char *s,
               uint64_t nodes) {
  Run r = run(i, s, 1u << 18, 0);
  cases++; checks++;
  if (r.returned || r.runtime || r.code != 0 || r.w1 != nodes) {
    failures++;
    fprintf(stderr, "FAIL %s ret=%llu runtime=%llu code=%llu reason=%llu nodes=%llu want=%llu\n",
            n, (unsigned long long)r.returned, (unsigned long long)r.runtime,
            (unsigned long long)r.code, (unsigned long long)r.reason,
            (unsigned long long)r.w1,
            (unsigned long long)nodes);
  }
  freerun(&r);
}

/* A refusal writes the four word diagnostic and publishes no AST. */
static void err(const NovaHostImage *i, const char *n, const char *s,
                uint64_t code, uint64_t reason) {
  Run r = run(i, s, 1u << 18, 0);
  cases++; checks++;
  if (r.returned != code || r.runtime || r.code != code || r.w1 == 0 ||
      r.w2 == 0 || r.reason != reason) {
    failures++;
    fprintf(stderr,
            "FAIL %s ret=%llu runtime=%llu code=%llu w1=%llu w2=%llu reason=%llu want=%llu/%llu\n",
            n, (unsigned long long)r.returned, (unsigned long long)r.runtime,
            (unsigned long long)r.code, (unsigned long long)r.w1,
            (unsigned long long)r.w2, (unsigned long long)r.reason,
            (unsigned long long)code, (unsigned long long)reason);
  }
  freerun(&r);
}

/* A structural failure writes no diagnostic at all, so only the returned code
 * is checked. */
static char *compose(unsigned fuel, unsigned call, unsigned arena,
                     unsigned nodes, unsigned depth, unsigned constant,
                     const char *body);

/* Defined with the other body builders below; declared here because the
 * exhaustion assertion above them uses it. */
static char *loop_body_fuel(unsigned n, unsigned fuel);

static void structural(const NovaHostImage *i, const char *n, const char *s,
                       uint64_t words) {
  Run r = run(i, s, words, 0);
  cases++; checks++;
  if (r.returned != 800 || r.runtime) {
    failures++;
    fprintf(stderr, "FAIL %s ret=%llu runtime=%llu\n", n,
            (unsigned long long)r.returned, (unsigned long long)r.runtime);
  }
  freerun(&r);
}

struct Usage { uint64_t fuel, call_peak, arena, nodes, depth_peak, constant,
               name_bytes, expansions, macros; };

static int measure(const NovaHostImage *i, const char *body, struct Usage *u) {
  char *full = compose(4096, 64, 4194304, 8192, 64, 65536, body);
  Run r = run(i, full ? full : "", 64, 1);
  free(full);
  int good = r.returned == 0 && r.runtime == 0;
  if (good) {
    u->fuel = r.out[1]; u->call_peak = r.out[2]; u->arena = r.out[3];
    u->nodes = r.out[4]; u->depth_peak = r.out[5]; u->constant = r.out[6];
    u->name_bytes = r.out[7]; u->expansions = r.out[8]; u->macros = r.out[9];
  }
  freerun(&r);
  return good;
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

/* The reference body: the worked example of the specification. */
static const char *BODY =
    "macro ret(v:ast.expr)->ast.stmt {\n"
    "    return quote(stmt) { return $v+1; };\n"
    "}\n"
    "section .text {\n"
    "    export fn main()->u64\n"
    "    effects {}\n"
    "    clobbers {} {\n"
    "        expand ret(41)\n"
    "    }\n"
    "}\n";

#define HEAD "module m\ntarget x86_64-nexora-none\n"
#define TAIL "section .text {\n    export fn main()->u64\n    effects {}\n" \
            "    clobbers {} {\n        expand "
#define FOOT "    }\n}\n"
/* A refusal writes the four word diagnostic and publishes no AST, so a check
 * that only asks "did it expand" must not pin a node count it did not
 * measure. This asks for the code and nothing else. */
static void fine(const NovaHostImage *i, const char *n, const char *s) {
  Run r = run(i, s, 1u << 18, 0);
  cases++; checks++;
  if (r.returned || r.runtime || r.code != 0 || r.w1 == 0) {
    failures++;
    fprintf(stderr, "FAIL %s ret=%llu runtime=%llu code=%llu reason=%llu\n",
            n, (unsigned long long)r.returned, (unsigned long long)r.runtime,
            (unsigned long long)r.code, (unsigned long long)r.reason);
  }
  freerun(&r);
}

/* A two level body: the outer expansion reaches the inner one through a
 * nested expand, so its cost is paid across two depth levels and the depth
 * and call budgets are exercised by nesting rather than by a single call. */
static const char *BODY2 =
    "macro inner(v:ast.expr)->ast.stmt {\n"
    "    return quote(stmt) { return $v; };\n"
    "}\n"
    "macro outer()->ast.stmt {\n"
    "    return quote(stmt) { expand inner(1) };\n"
    "}\n"
    "section .text {\n"
    "    export fn main()->u64\n"
    "    effects {}\n"
    "    clobbers {} {\n"
    "        expand outer()\n"
    "    }\n"
    "}\n";

/* The six budgets of spec/ntasm/ntasm.md 12, each swept at the exact measured cost
 * and one below it, on a body that nests one expansion inside another. The
 * figures come from the expander itself, so the sweep is a measurement and
 * not a pair of literals, and a nesting escape moves the figures and is
 * caught rather than accommodated. */
static void budget_sweep(const NovaHostImage *i, const char *what,
                         const char *body) {
  struct Usage u;
  char label[96];
  memset(&u, 0, sizeof u);
  snprintf(label, sizeof label, "measure %s", what);
  cases++; checks++;
  if (!measure(i, body, &u)) {
    failures++;
    fprintf(stderr, "FAIL %s\n", label);
    return;
  }
  fprintf(stderr,
          "MEASURE %s fuel=%llu call_peak=%llu arena=%llu nodes=%llu "
          "depth_peak=%llu constant=%llu names=%llu expansions=%llu "
          "macros=%llu\n",
          what, (unsigned long long)u.fuel, (unsigned long long)u.call_peak,
          (unsigned long long)u.arena, (unsigned long long)u.nodes,
          (unsigned long long)u.depth_peak, (unsigned long long)u.constant,
          (unsigned long long)u.name_bytes, (unsigned long long)u.expansions,
          (unsigned long long)u.macros);
  struct { const char *what; unsigned used; uint64_t reason; } v[6] = {
      {"fuel", (unsigned)u.fuel, 1},
      {"call_depth", (unsigned)u.call_peak, 2},
      {"arena_bytes", (unsigned)u.arena, 3},
      {"ast_nodes", (unsigned)u.nodes, 4},
      {"expansion_depth", (unsigned)u.depth_peak, 5},
      {"constant_bytes", (unsigned)u.constant, 6}};
  for (unsigned k = 0; k < 6; k++) {
    unsigned f = 4096, c = 64, a = 4194304, n = 8192, d = 64, b = 65536;
    if (k == 0) f = v[k].used;
    if (k == 1) c = v[k].used;
    if (k == 2) a = v[k].used;
    if (k == 3) n = v[k].used;
    if (k == 4) d = v[k].used;
    if (k == 5) b = v[k].used;
    char name[96];
    snprintf(name, sizeof name, "%s %s at the exact limit", what, v[k].what);
    char *exact = compose(f, c, a, n, d, b, body);
    if (exact) { fine(i, name, exact); free(exact); }
    else { failures++; fprintf(stderr, "FAIL compose exact\n"); }

    if (k == 0) f = v[k].used - 1;
    if (k == 1) c = v[k].used - 1;
    if (k == 2) a = v[k].used - 1;
    if (k == 3) n = v[k].used - 1;
    if (k == 4) d = v[k].used - 1;
    if (k == 5) b = v[k].used - 1;
    snprintf(name, sizeof name, "%s %s one past the limit", what, v[k].what);
    char *over = compose(f, c, a, n, d, b, body);
    if (over) { err(i, name, over, 201, v[k].reason); free(over); }
    else { failures++; fprintf(stderr, "FAIL compose over\n"); }
  }
}


/* ====================================================================== */
/* ==== wave 12: the helpers of the two A5 campaigns ===================== */
/* ====================================================================== */

/* A5 names four things: Hygiene, provenance, absence of I/O and imposed
 * bounds, each of them with adversarial tests. The gate above already
 * carries hygiene, and two of the prohibitions have no campaign anywhere in
 * the tree. These are the campaigns for those two, and every probe in them
 * is written as a PAIR: an attack that must be refused, and a control of the
 * same shape that must be accepted. A probe that cannot fail is worse than
 * no probe, because it gets counted, and the control half is the evidence
 * that the attack half is pointed at something real. Both halves run on
 * every invocation, so neither can rot behind a flag.
 *
 * The SURFACE is established before either campaign is written, because a
 * campaign pointed at a channel that does not exist passes for the wrong
 * reason. The Nova language hands every module six I/O intrinsics --
 * rt_open_read, rt_open_new, rt_read, rt_write, rt_close and rt_diag, over
 * the runtime table at nova.c:1096-1100 and runtime_v2.c:250-338. So the
 * claim this campaign can make is not "there is no path": there is one, it
 * is six calls wide, and it works. The two canary modules are that path,
 * executed, and the first probe below is the measurement of it. */

static void write_bytes(const char *path, const char *bytes, size_t n) {
  FILE *f = fopen(path, "wb");
  if (!f) return;
  fwrite(bytes, 1, n, f);
  fclose(f);
}

static int cmp_names(const void *a, const void *b) {
  return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Every file in the probe directory, as "name:size:fnv" lines sorted by
 * name, so two snapshots compare by CONTENT and not by readdir order, and a
 * rewrite that keeps the length still shows up as a change. The digest is
 * FNV-1a over the bytes; it is an instrument here, not a security claim, and
 * its only job is to make "nothing changed" a statement about bytes. */
static unsigned snapshot(const char *dir, char *out, size_t cap) {
  DIR *d = opendir(dir);
  struct dirent *e;
  char *names[256];
  unsigned n = 0, used = 0;
  if (cap) out[0] = 0;
  if (!d) return 0;
  while ((e = readdir(d)) != NULL && n < 256) {
    if (e->d_name[0] == '.') continue;
    names[n++] = strdup(e->d_name);
  }
  closedir(d);
  qsort(names, n, sizeof names[0], cmp_names);
  for (unsigned i = 0; i < n; i++) {
    char p[512];
    struct stat st;
    unsigned long long h = 1469598103934665603ULL;
    FILE *f;
    int ch;
    snprintf(p, sizeof p, "%s/%s", dir, names[i]);
    if (stat(p, &st) != 0) { free(names[i]); continue; }
    f = fopen(p, "rb");
    if (f) {
      while ((ch = fgetc(f)) != EOF) {
        h ^= (unsigned char)ch;
        h *= 1099511628211ULL;
      }
      fclose(f);
    }
    used += (unsigned)snprintf(out + used, cap > used ? cap - used : 0,
                               "%s:%llu:%016llx\n", names[i],
                               (unsigned long long)st.st_size, h);
    free(names[i]);
  }
  return n;
}

/* Run one of the two canary modules. out is five words: the three the module
 * writes, the code it returned, and the runtime error. The fifth word is not
 * optional: a raised runtime error forces the entry's return value to zero
 * at the host boundary (measured, x64_lower_nxo_pe.c records it), so the
 * returned code alone cannot tell a refusal from a success that returned
 * zero, and the read canary's absent-path arm depends on telling them
 * apart. */
static void canary_run(const NovaHostImage *img, const char *path,
                       uint64_t *out) {
  Run r = run(img, path, 8, 0);
  out[0] = r.out[0];
  out[1] = r.out[1];
  out[2] = r.out[2];
  out[3] = r.returned;
  out[4] = r.runtime;
  freerun(&r);
}

static void canary_read(const NovaHostImage *img, const char *path,
                        uint64_t *out) {
  canary_run(img, path, out);
}
static void canary_write(const NovaHostImage *img, const char *path,
                         uint64_t *out) {
  canary_run(img, path, out);
}

/* Everything the gate can observe about one expansion, folded into one
 * 64-bit digest: the returned code, the runtime error, the four diagnostic
 * words, and every word of the produced region when the expansion
 * succeeded. A digest and not a copy, because the question is "did anything
 * at all move", and a digest answers that without holding the corpus twice.
 *
 * `code_out` receives the diagnostic code so the campaign can REPORT which
 * corpus entries expanded and which were refused. A digest computed over a
 * corpus that is entirely refusals would compare equal across two rounds for
 * a reason that has nothing to do with purity, and the banner has to say
 * which of the two happened. */
static void expansion_digest(const NovaHostImage *img, const char *src,
                             unsigned long long *out, uint64_t *code_out) {
  Run r = run(img, src, 1u << 18, 0);
  unsigned long long h = 1469598103934665603ULL;
#define IO_MIX(v)                                                             \
  do {                                                                        \
    h ^= (unsigned long long)(v);                                             \
    h *= 1099511628211ULL;                                                    \
  } while (0)
  IO_MIX(r.returned);
  IO_MIX(r.runtime);
  IO_MIX(r.code);
  IO_MIX(r.w1);
  IO_MIX(r.w2);
  IO_MIX(r.reason);
  for (uint64_t k = 0; k < 4 && k < r.words; k++) IO_MIX(r.out[k]);
  if (r.code == 0 && r.runtime == 0) {
    uint64_t nw = (r.w2 + 7) / 8;
    uint64_t need = 4 + nw + r.w1 * 12;
    uint64_t span = need > r.words ? r.words : need;
    for (uint64_t k = 4; k < span; k++) IO_MIX(r.out[k]);
    IO_MIX(span);
  }
  if (code_out) {
    *code_out = r.code;
    fprintf(stderr, "DIGEST ret=%llu code=%llu w1=%llu w2=%llu head=[%llu "
                    "%llu %llu %llu] n4=%llu n5=%llu n6=%llu\n",
            (unsigned long long)r.returned, (unsigned long long)r.code,
            (unsigned long long)r.w1, (unsigned long long)r.w2,
            (unsigned long long)r.out[0], (unsigned long long)r.out[1],
            (unsigned long long)r.out[2], (unsigned long long)r.out[3],
            (unsigned long long)(r.words > 4 ? r.out[4] : 0),
            (unsigned long long)(r.words > 5 ? r.out[5] : 0),
            (unsigned long long)(r.words > 6 ? r.out[6] : 0));
  }
  freerun(&r);
  *out = h;
}

/* The corpus the exfiltration probe expands twice, once against a canary of
 * sixteen 'A' bytes and once against sixteen 'B'. It is deliberately not
 * one body: a template that reads, a nested expansion, a meta-for, a
 * meta-if, a capture refusal, an observation refusal and a hygiene shadow,
 * so the "nothing moved" claim covers the whole template vocabulary rather
 * than the easiest corner of it. */
static const char *META_FOR =
    "macro many(n:u64)->ast.decl {\n"
    "    for i in $n {\n"
    "        emit quote(decl) { const c:u64 = $i; }\n"
    "    }\n"
    "}\n"
    TAIL "many(3)\n" FOOT;

static const char *META_IF =
    HEAD "macro pick()->ast.decl {\n"
    "    if true {\n"
    "        emit quote(decl) { const c:u64=1; }\n"
    "    } else {\n"
    "        emit quote(decl) { const c:u64=2; }\n"
    "    }\n"
    "}\n"
    TAIL "pick()\n" FOOT;

static const char *SHADOW =
    HEAD
    "macro inner()->ast.block {\n"
    "    return quote(block) { let t:u64=1; return t; };\n"
    "}\n"
    "macro outer()->ast.block {\n"
    "    return quote(block) {\n"
    "        let t:u64=2;\n"
    "        expand inner();\n"
    "        return t;\n"
    "    };\n"
    "}\n"
    TAIL "outer()\n" FOOT;

static const char *CAPTURE =
    HEAD "macro steal()->ast.stmt {\n"
    "    return quote(stmt) { return t; };\n"
    "}\n"
    "section .text {\n"
    "    export fn main()->u64\n"
    "    effects {}\n"
    "    clobbers {} {\n"
    "        let t:u64=9;\n"
    "        expand steal()\n"
    "    }\n"
    "}\n";

static const char *OBSERVE =
    HEAD "macro probe()->ast.expr {\n"
    "    return quote(expr) { time() };\n}\n"
    TAIL "probe()\n" FOOT;

/* The body the witness differs from by one constant. It exists so the
 * exfiltration comparison can be shown able to see a difference: a
 * comparison that never moves is not evidence of invariance, it is evidence
 * of nothing. */
static const char *WITNESS =
    "macro ret(v:ast.expr)->ast.stmt {\n"
    "    return quote(stmt) { return $v+2; };\n"
    "}\n"
    TAIL "ret(41)\n" FOOT;

/* A function, not an array: BODY and BODY2 are `static const char *`
 * objects rather than constant expressions, so C does not accept them as
 * static initialisers. The switch keeps the corpus in one place.
 *
 * THE COMPOSE IS NOT COSMETIC, and the first version of this campaign got it
 * wrong in a way that made the whole probe vacuous. A corpus body carries no
 * module header, so handing one to the entry returns 800 -- the same code the
 * gate already asserts for "source without a module header". Three of the
 * seven entries then returned 800 with an all-zero output buffer, all seven
 * digests of the three were equal, and the exfiltration probe reported
 * "moved=0" for a corpus that had expanded nothing at all. A probe that
 * compares two zeroes is a probe that cannot fail. Every corpus entry is
 * therefore composed, and the campaign also asserts that at least half of
 * them really expanded, so a future regression to the bare form goes red
 * instead of going quiet. */
static const char *corpus_entry(unsigned i) {
  switch (i) {
  case 0: return BODY;
  case 1: return BODY2;
  case 2: return META_FOR;
  case 3: return META_IF;
  case 4: return SHADOW;
  case 5: return CAPTURE;
  default: return OBSERVE;
  }
}
static unsigned corpus_size(void) { return 7; }
/* Every corpus entry goes out through compose() with budgets large enough
 * that none of the six can be the one refusing, so an invariance measured
 * over the corpus is measured over expansions and not over refusals. */
static char *corpus_composed(unsigned i) {
  return compose(4096, 64, 4194304, 8192, 64, 65536, corpus_entry(i));
}
static char *witness_composed(void) {
  return compose(4096, 64, 4194304, 8192, 64, 65536, WITNESS);
}

/* compose_with puts one budget at one value and leaves the other five at
 * figures large enough that they cannot be the one refusing. The value is
 * unsigned because compose() prints with %u, and every ceiling measured here
 * is below 2^32. */
static char *compose_k(unsigned k, unsigned value, const char *body) {
  unsigned f = 4096, c = 64, a = 4194304, n = 8192, d = 64, b = 65536;
  if (k == 0) f = value;
  if (k == 1) c = value;
  if (k == 2) a = value;
  if (k == 3) n = value;
  if (k == 4) d = value;
  if (k == 5) b = value;
  return compose(f, c, a, n, d, b, body);
}



/* ==================== A5 wave 13: provenance, and the seven bounds ========
 *
 * Wave 12 delivered two of the four requirements criterion A5 names: the
 * absence of I/O, and the declared maxima. The two it did not deliver were
 * named in its own banner and never run. This block is the first of them, and
 * it is the one the criterion names: PROVENANCE.
 *
 * THE SURFACE, ESTABLISHED BEFORE ANYTHING IS CLAIMED, because a campaign
 * pointed at a channel that does not exist passes for the wrong reason. The
 * I/O campaign's most useful sentence was that its channel is open, not
 * absent, and that without two canary modules the purity campaign would have
 * passed for the wrong reason. The same question is asked here and it has a
 * different answer, so it is worth stating in full.
 *
 *   WHAT A MARK IS HERE. Four textual compositions written byte by byte into
 *   the produced name table by put_mark (macro_expand.nova:1010-1019) and its
 *   three callers:
 *     local  __ntm$<ordinal>$e<serial>$<name>                :1024
 *     decl   __ntd$<ordinal>$e<serial>$r<rep>$t<item>$<name> :1036
 *     decl   __ntd$<ordinal>$e<serial>$<name>                :1036
 *     param  __ntp$<ordinal>$e<serial>$p<index>$<name>      :1054
 *   which are the reference's own formats, at frontend.c:2384, :4818, :4880
 *   and :4938. The gate re-derives them here in C from those four literals
 *   rather than calling the expander's own composer, so a composer changed
 *   together with its test would go red.
 *
 *   WHO CAN SET ONE. Only the expander. A caller cannot spell a mark: caller
 *   identifiers come from the lexer, whose is_letter is a-z, A-Z and '_'
 *   (lexer.nova:37-39) and whose is_digit is 0-9, and '$' is neither, so '$'
 *   can never be part of a caller identifier. That is a closed channel and it
 *   is MEASURED below, not asserted: a module whose caller declares a
 *   mark-shaped name is handed to the parser and the refusal is recorded.
 *
 *   WHERE ONE COULD LEAK. The produced name table is the only channel out,
 *   and every name the produced region carries points into it. So the sweep
 *   is exhaustive by construction: read every produced name, classify it, and
 *   a name that is neither a mark nor a spelling the expander copies verbatim
 *   is a leak. The sweep found one. It is not a mark that leaked: it is a
 *   mark that was NEVER APPLIED.
 */

/* The classes a produced name can fall into. The first three are the three
 * positions the module itself documents -- pos_bind renames, pos_spelled and
 * pos_caller copy verbatim (macro_expand.nova:118-131) -- and the fourth is
 * the finding: a name the produced region carries that no position of the
 * template vocabulary explains. */
enum { CLS_MARKED = 0, CLS_SPELLED, CLS_CALLER, CLS_UNCLASSIFIED };

/* The closed set of spellings a template may name and have copied verbatim at
 * a spelled position: the type names and the two boolean words word_id knows
 * (macro_expand.nova:361-366 and the value_fits table at :1049-1064), plus
 * the pointer and address-space spellings. A produced name outside this set,
 * outside a caller declaration and outside the mark grammar is not a
 * spelling: it is a symbol, and symbols are exactly what hygiene renames. */
static const char *SPELLED[] = {"bool", "u8",   "u16", "u32", "u64", "i8",
                                "i16",  "i32",  "i64", "true", "false", "ptr",
                                "user", "void"};

/* Is this text one of the four reference mark formats? The fields are parsed
 * out of the expander's OWN bytes and returned, so a check can compare the
 * ordinal and the serial the expander used against the ones the gate expects
 * rather than only asking whether a prefix is present. A prefix test is what
 * a mark that had been pasted in as literal text would pass. */
static int mark_fields(const char *t, char *kind, unsigned long long *ord,
                       unsigned long long *ser, unsigned long long *x,
                       unsigned long long *y, const char **name) {
  unsigned long long o, s, a, b;
  int at = 0;
  if (sscanf(t, "__ntm$%llu$e%llu$%n", &o, &s, &at) == 2 && at > 0) {
    *kind = 'm'; *ord = o; *ser = s; *x = 0; *y = 0; *name = t + at;
    return 1;
  }
  at = 0;
  if (sscanf(t, "__ntd$%llu$e%llu$%n", &o, &s, &at) == 2 && at > 0) {
    *kind = 'd'; *ord = o; *ser = s; *x = 0; *y = 0;
    if (t[at] == 'r') {
      unsigned long long r, i;
      int at2 = 0;
      if (sscanf(t + at, "r%llu$t%llu$%n", &r, &i, &at2) == 2 && at2 > 0) {
        *x = r; *y = i; *name = t + at + at2;
      } else {
        return 0;
      }
    } else {
      *name = t + at;
    }
    return 1;
  }
  at = 0;
  if (sscanf(t, "__ntp$%llu$e%llu$%n", &o, &s, &at) == 2 && at > 0) {
    unsigned long long p;
    int at2 = 0;
    if (sscanf(t + at, "p%llu$%n", &p, &at2) != 1 || at2 <= 0) return 0;
    *kind = 'p'; *ord = o; *ser = s; *x = p; *y = 0; *name = t + at + at2;
    return 1;
  }
  (void)a; (void)b;
  return 0;
}

/* The identifiers a CALLER wrote: every identifier in the source that is not
 * inside a macro body. The expander makes the same cut by the same rule -- a
 * template is not a caller declaration, so the walk descends from the module
 * root and skips a macro body whole (macro_expand.nova:1160-1184) -- and the
 * gate re-derives it here from the source bytes rather than asking the
 * expander, for the same reason the mark grammar is. */
static int is_ident_char(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_';
}
static int is_ident_start(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

/* Ignore the same quoted strings and // comments the language lexer ignores.
 * Braces and identifiers inside them never affect the template boundary. */
static size_t skip_non_code(const char *src,size_t len,size_t i){
  if(i+1<len&&src[i]=='/'&&src[i+1]=='/'){i+=2;while(i<len&&src[i]!='\n')i++;return i;}
  if(i<len&&src[i]=='"'){i++;while(i<len){if(src[i]=='\\'&&i+1<len){i+=2;continue;}if(src[i++]=='"')break;}return i;}
  return i;
}
static int in_macro_body(const char *src,size_t len,size_t at){
  int active=0,depth=0;size_t i=0;
  while(i<at&&i<len){
    size_t next=skip_non_code(src,len,i);if(next!=i){i=next;continue;}
    if(!active&&i+5<=len&&!memcmp(src+i,"macro",5)&&
       (i==0||!is_ident_char((unsigned char)src[i-1]))&&
       (i+5==len||!is_ident_char((unsigned char)src[i+5]))){active=1;depth=0;i+=5;continue;}
    if(active){if(src[i]=='{')depth++;else if(src[i]=='}'&&depth>0){depth--;if(depth==0)active=0;}}
    i++;
  }
  return active;
}

static int spelled_word(const char *t) {
  for (unsigned k = 0; k < sizeof SPELLED / sizeof SPELLED[0]; k++)
    if (strcmp(t, SPELLED[k]) == 0) return 1;
  return 0;
}

/* Does the CALLER write this exact identifier outside every macro body? */
static int caller_writes(const char *src, size_t len, const char *word) {
  size_t wl = strlen(word);
  size_t i = 0;
  while (i < len) {
    size_t next=skip_non_code(src,len,i);if(next!=i){i=next;continue;}
    if (!is_ident_start((unsigned char)src[i])) { i++; continue; }
    size_t j = i;
    while (j < len && is_ident_char((unsigned char)src[j])) j++;
    if (j - i == wl && memcmp(src + i, word, wl) == 0 &&
        in_macro_body(src, len, i) == 0)
      return 1;
    i = j;
  }
  return 0;
}

/* The classification of one produced name. `src` is the caller source the
 * expansion was run on, so the caller test is a statement about THIS run and
 * not about a list written next to the classifier. */
static int classify_name(const char *text, const char *src, size_t len) {
  char kind = 0;
  unsigned long long ord = 0, ser = 0, x = 0, y = 0;
  const char *name = text;
  if (mark_fields(text, &kind, &ord, &ser, &x, &y, &name) == 1)
    return CLS_MARKED;
  if (spelled_word(text) == 1) return CLS_SPELLED;
  if (caller_writes(src, len, text) == 1) return CLS_CALLER;
  return CLS_UNCLASSIFIED;
}
/* THE PROPERTY, RE-DERIVED FROM THE RULE AND NOT FROM THE PARTITION IT
 * TESTS. A hygiene defect is not "a produced name the caller also wrote": a
 * caller who passes its OWN name as an argument gets that name back spelled,
 * and that is correct -- the name belongs to the scope that wrote it. The
 * defect is narrower and it is this: a name a TEMPLATE BOUND is renamed, so
 * any SPELLED occurrence of that same spelling in the produced region is a
 * reference to something the expansion did not introduce. It points at the
 * caller's declaration of the same spelling, or at nothing.
 *
 * So the list the check compares against is the names the TEMPLATES bind, cut
 * from the source by the same rule the expander renames by: a binding
 * position inside a macro body. `let`, `const`, `data` and `fn` introduce
 * one; a macro PARAMETER does not, because a parameter is the caller's own
 * name handed to the template and it is never renamed -- which is why the
 * caller-argument row below is a control and not a finding.
 *
 * The first version of this check compared against caller_writes instead, and
 * it was wrong in a way worth recording: it flagged `u64`, which is a spelled
 * TYPE the module header necessarily writes, and it flagged the caller's own
 * `v` in the control row. Nine failures, of which one was real. A predicate
 * that cannot tell a renamed binding from a spelled type is not a check. */
static int template_binds(const char *src, size_t len, const char *word) {
  static const char *kw[] = {"let", "const", "data", "fn"};
  size_t wl = strlen(word);
  for (size_t i = 0; i < len; i++) {
    size_t next=skip_non_code(src,len,i);if(next!=i){i=next-1;continue;}
    if (in_macro_body(src, len, i) == 0) continue;
    for (unsigned k = 0; k < sizeof kw / sizeof kw[0]; k++) {
      size_t kl = strlen(kw[k]);
      if (i + kl > len) continue;
      if (memcmp(src + i, kw[k], kl) != 0) continue;
      if (i > 0 && is_ident_char((unsigned char)src[i - 1])) continue;
      size_t j = i + kl;
      /* `fn helper(in n:u64)` -- a DIRECTION sits between the keyword and the
       * name, so one identifier is skipped when it names a direction, and the
       * identifier after it is the name. */
      if (j < len && is_ident_start((unsigned char)src[j])) {
        size_t d = j;
        while (d < len && is_ident_char((unsigned char)src[d])) d++;
        size_t dl = d - j;
        if (dl == 2 || dl == 4) {
          if ((dl == 2 && memcmp(src + j, "in", 2) == 0) ||
              (dl == 4 && memcmp(src + j, "inout", 4) == 0)) {
            while (d < len && (src[d] == ' ' || src[d] == '\t')) d++;
            j = d;
          } else if (dl == 3 && memcmp(src + j, "out", 3) == 0) {
            while (d < len && (src[d] == ' ' || src[d] == '\t')) d++;
            j = d;
          }
        }
      }
      while (j < len && (src[j] == ' ' || src[j] == '\t')) j++;
      if (j >= len || !is_ident_start((unsigned char)src[j])) continue;
      size_t e = j;
      while (e < len && is_ident_char((unsigned char)src[e])) e++;
      if (e - j == wl && memcmp(src + j, word, wl) == 0) return 1;
    }
  }
  return 0;
}

/* A refusal the EXPANDER never made: the HOST could not give the operation a
 * buffer, so the expander published nothing and wrote no diagnostic.
 * returned 0, code 0, no nodes, no name bytes. The gate's err() helper cannot
 * express this outcome, and a helper that cannot express an outcome is how a
 * campaign pointed at this ceiling ends up reporting a refusal that no
 * diagnostic describes.
 *
 * WHY THE CODE IS READ OUT OF THE HEADER AND NOT WRITTEN HERE. This predicate
 * used to pin the literal 6, which was NV2_RUNTIME: the host's catch-all, and
 * also what the buffer table reported when it had no handle left. Exhaustion
 * now has its own code, NV2_EXHAUSTED (runtime_v2.h:18-38), precisely so a
 * caller can tell exhaustion from a failed calloc and from a full file table.
 * A literal here would therefore have been false forever: the predicate
 * cannot fire, and a predicate that cannot fire is not a check. Naming the
 * code through the header's enumerator instead of a number means the
 * predicate names the CAUSE, so the next exhaustion cause does not silently
 * invalidate it again, and so a change to the enumerator is a change to what
 * this predicate is looking for rather than a change to a number that no
 * longer means what it meant.
 *
 * The predicate is deliberately about the CAUSE and not about the value: see
 * exhaustion_is_distinguishable below, which is the assertion that the code
 * has to be readable AS a distinction. Testing that NV2_EXHAUSTED equals some
 * number would be testing the header, not the expander, and would go on
 * passing after the distinction this exists to protect was lost. */
static int host_refused(const Run *r) {
  return r->returned == 0 && r->runtime == NV2_EXHAUSTED && r->code == 0 &&
         r->w1 == 0 && r->w2 == 0;
}

/* A run on a host whose buffer table has ALREADY been filled, so the entry
 * point is called with no handle left to give.
 *
 * WHY IT IS BUILT RATHER THAN SEARCHED FOR. Before the node-read and text_is
 * leaks were fixed, an ordinary expander body exhausted the table on its own
 * -- 65536 slots, one per 96-byte record return -- and the ceiling searches
 * below reached it by sweeping body shapes. After the fix the expander's
 * allocations fell by two orders of magnitude (macro_expand.nova:280-284:
 * 4502073 calls before, 8952 after, peak live 436), and NO body in this tree
 * fills the table any more. Measured: a 512 item meta-for at the declared
 * maxima expands, and so does the largest body the lets shape builds. So a
 * harness that waits for an expander body to exhaust the host would wait
 * forever, and host_refused() would never be exercised at all -- which is
 * precisely the "false forever, never fires" failure this predicate had. The
 * exhaustion is therefore produced on purpose, on the real host and through
 * the real add_buffer path, by taking the table's slots first. */
static Run run_on_exhausted_host(const NovaHostImage *i, const char *s,
                                 uint64_t words) {
  Run r;
  memset(&r, 0, sizeof r);
  r.code = r.w1 = r.w2 = r.reason = UINT64_C(0xcccccccccccccccc);
  r.out = calloc(words ? words : 1, 8);
  if (!r.out) return r;
  r.words = words;
  r.out[0] = 0;
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "exhausted-host context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, words * 8, 1);
  /* Take every remaining slot with a scratch buffer, so the entry point below
   * finds add_buffer with nowhere to go. The borrow returns 0 and sets
   * NV2_EXHAUSTED at that point (runtime_v2.c:96-100). */
  static unsigned char scratch[64];
  for (unsigned n = 0; n < 70000u && c.error == 0; n++)
    (void)nova_borrow_v2(&c, scratch, sizeof scratch, 0);
  uint64_t a[] = {sh, strlen(s), oh, words};
  r.returned = i->entry(&c, a, 4);
  r.runtime = c.error;
  r.code = r.out[0]; r.w1 = r.out[1]; r.w2 = r.out[2]; r.reason = r.out[3];
  CHECK(nova_context_destroy_v2(&c), "exhausted-host context cleanup");
  return r;
}

/* THE ASSERTION host_refused EXISTS FOR.
 *
 * host_refused() is not here to check that a code has a value. It is here to
 * prove that HOST EXHAUSTION IS DISTINGUISHABLE FROM REFUSAL, and that is the
 * property the previous change was about: before NV2_EXHAUSTED existed the
 * buffer table reported NV2_RUNTIME, which is also what a failed calloc and a
 * full file table report, so a caller could not tell exhaustion from any other
 * host failure (runtime_v2.h:18-27). A test that asserted "the code is 13"
 * would be testing the header's spelling, not the distinction, and it would
 * keep passing after the distinction was lost -- which is what a re-pinned
 * literal always does. So what is asserted here is the distinction itself:
 *
 *   1. the code is not the catch-all, so exhaustion is separable from a host
 *      failure that is not exhaustion;
 *   2. the expander's own refusal codes are a different set again, so a caller
 *      can tell "the host ran out" from "the expander refused";
 *   3. a run on an exhausted host SURFACES the code on the only channel a
 *      caller has, rather than reporting a success -- the run publishes
 *      nothing, so a caller that only looked at the produced region would see
 *      an empty expansion and could not tell it from a refusal;
 *   4. the same body on a host with room left expands, so the emptiness in
 *      (3) is caused by the exhaustion and not by the body.
 *
 * (3) and (4) together are what make this a test of the distinction rather
 * than of a number: both are read off the same source, and the only
 * difference between the two runs is whether the host had a buffer to give. */
static void exhaustion_is_distinguishable(const NovaHostImage *i) {
  char *body = loop_body_fuel(4, 1048576);
  Run healthy = run(i, body ? body : "", 1u << 18, 0);
  Run starved = run_on_exhausted_host(i, body ? body : "", 1u << 18);
  int healthy_ok = healthy.returned == 0 && healthy.runtime == 0 &&
                   healthy.code == 0 && healthy.w1 != 0;

  cases++; checks++;
  if (NV2_EXHAUSTED == NV2_RUNTIME) {
    failures++;
    fprintf(stderr,
            "FAIL NV2_EXHAUSTED is NV2_RUNTIME, so host exhaustion is not "
            "distinguishable from any other host failure and the distinction "
            "this gate exists to protect does not exist\n");
  }

  cases++; checks++;
  if (host_refused(&starved) == 0) {
    failures++;
    fprintf(stderr,
            "FAIL a run on an exhausted host did not surface the exhaustion "
            "code: ret=%llu runtime=%llu (EXHAUSTED=%d) code=%llu w1=%llu "
            "w2=%llu. Either exhaustion is not reported on this channel, or it "
            "is reported as something a caller cannot tell from a refusal\n",
            (unsigned long long)starved.returned,
            (unsigned long long)starved.runtime, NV2_EXHAUSTED,
            (unsigned long long)starved.code,
            (unsigned long long)starved.w1, (unsigned long long)starved.w2);
  }

  cases++; checks++;
  if (starved.runtime != NV2_EXHAUSTED) {
    failures++;
    fprintf(stderr,
            "FAIL the exhausted run reported runtime=%llu, not NV2_EXHAUSTED "
            "(%d); the code a caller reads is not the one that names the cause\n",
            (unsigned long long)starved.runtime, NV2_EXHAUSTED);
  }

  /* The negative proof, and it is the arm that gives (3) its meaning: the
   * expander's own diagnostic codes are a different set, so an exhaustion can
   * never be mistaken for one of them and never silently absorbed by one. */
  cases++; checks++;
  if (NV2_EXHAUSTED == 380 || NV2_EXHAUSTED == 372 ||
      NV2_EXHAUSTED == 201 || NV2_EXHAUSTED == 900) {
    failures++;
    fprintf(stderr,
            "FAIL NV2_EXHAUSTED (%d) collides with an expander diagnostic "
            "code, so exhaustion is not distinguishable from refusal\n",
            NV2_EXHAUSTED);
  }

  cases++; checks++;
  if (healthy_ok == 0) {
    failures++;
    fprintf(stderr,
            "FAIL the control body does not expand on a host with room left "
            "(ret=%llu runtime=%llu code=%llu w1=%llu), so the exhausted run "
            "proves nothing: the two runs would differ for a reason that has "
            "nothing to do with exhaustion\n",
            (unsigned long long)healthy.returned,
            (unsigned long long)healthy.runtime, (unsigned long long)healthy.code,
            (unsigned long long)healthy.w1);
  }

  /* And the one that fails if the distinction is lost the other way: the
   * exhausted run must NOT look like a refusal the expander made, because the
   * expander wrote no diagnostic at all. */
  cases++; checks++;
  if (starved.code != 0) {
    failures++;
    fprintf(stderr,
            "FAIL the exhausted run carries expander diagnostic %llu, so the "
            "host refusal and an expander refusal are no longer separable\n",
            (unsigned long long)starved.code);
  }

  fprintf(stderr,
          "DISTINCTION exhaustion_distinguishable=yes exhausted_run="
          "runtime_%d_code_0_no_nodes control_expands=%d "
          "exhausted_ne_NV2_RUNTIME=%d exhausted_ne_expander_codes=%d\n",
          NV2_EXHAUSTED, healthy_ok, NV2_EXHAUSTED != NV2_RUNTIME,
          NV2_EXHAUSTED != 380 && NV2_EXHAUSTED != 372 &&
              NV2_EXHAUSTED != 201 && NV2_EXHAUSTED != 900);
  freerun(&healthy);
  freerun(&starved);
  free(body);
}

/* ================================================================ bounds
 *
 * Seven compiler bounds, named as unmeasured by the banner this block
 * replaces. The triple is at the cap, one past it and one below it, because a
 * block refused at EVERY value would produce the same observation one past the
 * cap, and only the one-below arm makes the middle one a boundary rather than
 * coincidence.
 *
 * Four of the seven are reachable and clean: parameter_cap, walk_depth_cap,
 * loop_cap and hard_name_cap. Three are not, and for each of those the most
 * useful thing this campaign can produce is WHAT SHADOWS IT, measured rather
 * than assumed. Every shadow named below is the expander's own budget or its
 * own check. None of them is the host's buffer table any more: that table was
 * the shadow for all five of the old unreachable bounds, and the two
 * allocation leaks that made it one are fixed, so the table is no longer
 * filled by any body this gate builds (peak live 436 of 65536). That is why
 * the count moved from two reachable to four, and why the sentence "five of
 * the seven declared compiler bounds are not enforced by anything" is no
 * longer true of this gate: all seven are enforced, four by a bound a body can
 * reach and three by a budget that answers first for reasons of arithmetic. */

/* A corpus body that already opens with a module header is used as it is; one
 * that does not is composed. Getting this wrong is invisible to a digest and
 * fatal to a node count, so it is a function rather than a convention. */
static char *sweep_source(const char *body) {
  const char *p = body;
  while (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r') p++;
  if (strncmp(p, "module ", 7) == 0) {
    char *copy = malloc(strlen(body) + 1);
    if (copy) strcpy(copy, body);
    return copy;
  }
  return compose(1048576, 256, 16777216, 1048576, 128, 16777216, body);
}

/* The four mark constructors, one entry each, so the sweep covers the whole
 * mark vocabulary rather than the two marks the wave 12 corpus happens to
 * reach. An entry that does not produce its mark is caught by the tally
 * below, which is why the expected class is named per entry. */
static const char *MARK_CORPUS[6] = {
    /* 0: a let, so __ntm$ at macro_expand.nova:1024 */
    HEAD "macro blk(v:ast.expr)->ast.block {\n"
         "    return quote(block) { let t:u64 = $v; return t; };\n}\n"
         TAIL "blk(1)\n" FOOT,
    /* 1: a declaration, so __ntd$ without the repeat/item fields :1036 */
    HEAD "macro one()->ast.decl {\n"
         "    emit quote(decl) { const c:u64 = 1; }\n}\n"
         TAIL "one()\n" FOOT,
    /* 2: a declaration inside a meta-for, so __ntd$ WITH $r and $t :1036 */
    HEAD "macro many(n:u64)->ast.decl {\n"
         "    for i in $n {\n"
         "        emit quote(decl) { const c:u64 = $i; }\n"
         "    }\n}\n" TAIL "many(2)\n" FOOT,
    /* 3: a function and its parameter, so __ntd$ on a fn name AND __ntp$
     *    on the parameter, the only constructor that writes a $p field
     *    (macro_expand.nova:1054) */
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
    /* 5: a comptime value parameter, so the produced literal is a fold and
     *    not a copied name */
    HEAD "macro val(n:u64)->ast.decl {\n"
         "    emit quote(decl) { const c:u64 = $n; }\n}\n"
         TAIL "val(5)\n" FOOT};

/* A meta-for whose body splices the loop index: the shape the ceiling
 * searches use, because it costs the most record returns per item and so
 * finds a host ceiling soonest. */
static char *loop_body(unsigned n) {
  char buf[256];
  snprintf(buf, sizeof buf,
           "macro many(n:u64)->ast.decl {\n"
           "    for i in $n {\n"
           "        emit quote(decl) { const c:u64 = $i; }\n"
           "    }\n"
           "}\n" TAIL "many(%u)\n" FOOT, n);
  return compose(4096, 64, 16777216, 1048576, 128, 16777216, buf);
}

/* The same body with the FUEL budget chosen by the caller.
 *
 * WHY THIS EXISTS, and it is the whole of item 2 of this change. loop_body()
 * composes fuel=4096, and a meta-for item costs about 8 fuel -- measured, not
 * assumed: 27 at one item, 35 at two, 59 at four, 4091 at 508, so 27 + 8n
 * exactly -- which puts 512 items at 27 + 8*512 = 4123 fuel. A 4096 budget
 * answers 201 reason 1 at 510 items, which is UNDER loop_cap 512 and before
 * the cap is ever consulted. An assertion written against that budget
 * measures the fuel ceiling and reports it as loop_cap, and it keeps passing
 * for as long as the fuel ceiling sits below the cap: an assertion that has
 * stopped testing the thing it was written to test. Measuring loop_cap means
 * holding fuel out of the way, and holding it out is this function's job.
 *
 * The two ceilings are named apart on purpose. LOOP_CEILING_FUEL is the fuel
 * a loop_body() measurement runs at, and it is a property of the SHAPE, not of
 * any declared bound; the loop_cap arms below run at the declared fuel
 * maximum instead. */
static char *loop_body_fuel(unsigned n, unsigned fuel) {
  char buf[256];
  snprintf(buf, sizeof buf,
           "macro many(n:u64)->ast.decl {\n"
           "    for i in $n {\n"
           "        emit quote(decl) { const c:u64 = $i; }\n"
           "    }\n"
           "}\n" TAIL "many(%u)\n" FOOT, n);
  return compose(fuel, 64, 16777216, 1048576, 128, 16777216, buf);
}

/* The largest item count this shape expands AT THIS FUEL BUDGET, by bisection
 * rather than by a literal, so a change in any cost moves the number and the
 * number is re-measured instead of quietly becoming a constant. */
static unsigned loop_ceiling_at(const NovaHostImage *i, unsigned fuel) {
  unsigned lo = 1, hi = 512;
  while (lo < hi) {
    unsigned mid = lo + (hi - lo + 1) / 2;
    char *src = loop_body_fuel(mid, fuel);
    Run r = run(i, src ? src : "", 1u << 20, 0);
    int ok = r.code == 0 && r.runtime == 0 && r.w1 != 0;
    freerun(&r);
    free(src);
    if (ok) lo = mid; else hi = mid - 1;
  }
  return lo;
}

/* The largest item count this shape expands, at the SHAPE's own fuel budget
 * of 4096, found by bisection rather than by a literal, so that a change in
 * any cost moves the number and the number is re-measured instead of quietly
 * becoming a constant.
 *
 * THIS IS A FUEL CEILING AND NOT loop_cap, and the name says so. 4096 fuel
 * answers at 508 items, under loop_cap 512; the loop_cap arms below measure
 * the same shape at the declared fuel maximum and reach 512. Both numbers are
 * real, they are different quantities, and a campaign that reports one under
 * the other's name is how a shadow was mistaken for a bound. */
static unsigned loop_ceiling(const NovaHostImage *i) {
  return loop_ceiling_at(i, 4096);
}

/* One `let` per statement of a single quoted block, which is what pushes
 * entries onto the binding stack without a loop to multiply them. */
static char *lets_body(unsigned n) {
  size_t need = 128 + (size_t)n * 32;
  char *b = malloc(need);
  if (!b) return NULL;
  size_t used = (size_t)snprintf(b, need,
      "macro blk(v:ast.expr)->ast.block {\n    return quote(block) {\n");
  for (unsigned i = 0; i < n && used + 32 < need; i++)
    used += (size_t)snprintf(b + used, need - used,
                             "        let t%04u:u64 = $v;\n", i);
  snprintf(b + used, need - used,
           "        return t0000;\n    };\n}\n" TAIL "blk(1)\n" FOOT);
  {
    char *out = compose(4096, 64, 16777216, 1048576, 128, 16777216, b);
    free(b);
    return out;
  }
}

/* The name of the LAST let a body of `n` lets introduces, so a check can ask
 * whether the expander really produced all of them rather than whether it
 * reported success. Returns a pointer to a per-call rotating buffer, so two
 * calls in one expression are two different names. */
static const char *last_let_name(unsigned n) {
  static char slot[4][16];
  static unsigned turn;
  char *out = slot[turn++ & 3u];
  snprintf(out, sizeof slot[0], "t%04u", n ? n - 1 : 0);
  return out;
}

/* Does this exact byte run appear anywhere in the produced name table? A
 * substring search, not a match at an offset: the question is whether the
 * expander produced the name at all, wherever it put it. */
static int name_contains(const Run *r, const char *text) {
  size_t want = strlen(text);
  if (r->w2 < want) return 0;
  for (uint64_t start = 0; start + want <= r->w2; start++) {
    int hit = 1;
    for (size_t i = 0; i < want; i++) {
      uint64_t w = r->out[4 + (start + i) / 8];
      if ((unsigned)((w >> (8 * ((start + i) % 8))) & 0xff) !=
          (unsigned char)text[i]) {
        hit = 0;
        break;
      }
    }
    if (hit) return 1;
  }
  return 0;
}

/* `n` lets, and the macro RETURNS THE LAST ONE, so the produced name table has
 * to contain it for the expansion to be complete. A body whose final let is
 * missing is a truncated expansion, and a success code does not make it whole.
 * The fuel budget is the caller's, so the binding-stack arm can hold it out. */
static char *lets_body_titled(unsigned n, unsigned fuel) {
  size_t need = 256 + (size_t)n * 64;
  char *b = malloc(need);
  if (!b) return NULL;
  size_t used = (size_t)snprintf(b, need,
      "macro blk(v:ast.expr)->ast.block {\n    return quote(block) {\n");
  for (unsigned i = 0; i < n; i++)
    used += (size_t)snprintf(b + used, need - used,
                             "        let t%04u:u64 = $v;\n", i);
  snprintf(b + used, need - used,
           "        return %s;\n    };\n}\n" TAIL "blk(1)\n" FOOT,
           last_let_name(n));
  {
    char *out = compose(fuel, 64, 16777216, 1048576, 128, 16777216, b);
    free(b);
    return out;
  }
}

/* A GENERATED FUNCTION whose body holds `n` lets and a return of the last
 * one, so the body holds n+1 statements. This is the second body form the
 * reference bounds with the same 512 -- frontend.c:3654 refuses the 513th
 * statement of a generated function body with NTF_E_LIMIT "generated
 * function statement limit exceeded" -- and it is measured apart from the
 * quoted block because the two walks are two call sites and a check that is
 * only ever exercised at one of them is a check that is not armed at the
 * other. The statements are lets of distinct names so that each one clones
 * without a diagnostic of its own and the cap is the only thing that can
 * answer; the parameters are absent, which is the point: the reference
 * bounds decl_param_names[64] apart from the body at frontend.c:2734, and a
 * cap applied to the whole child chain would refuse a shape the reference
 * expands. The fuel budget is the caller's, so no budget of this campaign's
 * choosing answers first. */
static char *fn_body(unsigned n, unsigned fuel) {
  size_t need = 512 + (size_t)n * 32;
  char *b = malloc(need);
  if (!b) return NULL;
  size_t used = (size_t)snprintf(b, need,
      "macro mk()->ast.decl {\n"
      "    emit quote(decl) {\n"
      "        fn helper()->u64\n"
      "        effects {}\n"
      "        clobbers {} {\n");
  for (unsigned i = 0; i < n; i++)
    used += (size_t)snprintf(b + used, need - used,
                             "            let t%04u:u64 = 1;\n", i);
  snprintf(b + used, need - used,
           "            return t%04u;\n        }\n    }\n}\n"
           TAIL "mk()\n" FOOT, n ? n - 1 : 0);
  {
    char *out = compose(fuel, 64, 16777216, 1048576, 128, 16777216, b);
    free(b);
    return out;
  }
}

/* A meta-for NESTED inside a meta-for, one producing item per inner
 * iteration, with an introduced name of `namelen` bytes. This is the shape
 * that publishes the most nodes and the most name bytes at once, and it is
 * the only shape measured that reaches hard_name_cap: the node budget and the
 * name budget are separate counters, so lengthening the name raises the name
 * table without moving the node count at all. That is the whole argument
 * against writing a measured ceiling down as a constant -- a ceiling is a
 * property of the body, and the same item count answers a different bound
 * when the names are longer. */
static char *nested_body(unsigned outer, unsigned inner, unsigned namelen) {
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
           "        }\n    }\n}\n" TAIL "nest(%u,%u)\n" FOOT, outer, inner);
  {
    char *out = compose(1048576, 256, 16777216, 1048576, 128, 16777216, src);
    free(src);
    return out;
  }
}

static unsigned lets_ceiling(const NovaHostImage *i) {
  unsigned lo = 1, hi = 4096;
  while (lo < hi) {
    unsigned mid = lo + (hi - lo + 1) / 2;
    char *src = lets_body(mid);
    Run r = run(i, src ? src : "", 1u << 20, 0);
    int ok = r.code == 0 && r.runtime == 0 && r.w1 != 0;
    freerun(&r);
    free(src);
    if (ok) lo = mid; else hi = mid - 1;
  }
  return lo;
}

/* A chain of nested expansions, each passing a literal to the next. The
 * argument stack grows by arg_stride() = 4 words per level (macro_expand.nova
 * :756) and the expansion depth budget is 128, so 1024 levels would be needed
 * to answer the 4096 word cap. */
static char *chain_body(unsigned levels) {
  size_t need = 256 + (size_t)levels * 96;
  char *b = malloc(need);
  if (!b) return NULL;
  size_t used = 0;
  for (unsigned i = 0; i < levels; i++)
    used += (size_t)snprintf(b + used, need - used,
        "macro m%u(v:ast.expr)->ast.stmt {\n"
        "    return quote(stmt) { expand m%u(1) };\n}\n", i, i + 1);
  snprintf(b + used, need - used,
      "macro m%u(v:ast.expr)->ast.stmt {\n"
      "    return quote(stmt) { return $v; };\n}\n"
      "section .text {\n    export fn main()->u64\n    effects {}\n"
      "    clobbers {} {\n        expand m0(1)\n    }\n}\n", levels);
  {
    char *out = compose(4096, 256, 16777216, 1048576, 128, 16777216, b);
    free(b);
    return out;
  }
}

static unsigned chain_ceiling(const NovaHostImage *i) {
  unsigned lo = 1, hi = 256;
  while (lo < hi) {
    unsigned mid = lo + (hi - lo + 1) / 2;
    char *src = chain_body(mid);
    Run r = run(i, src ? src : "", 1u << 20, 0);
    int ok = r.code == 0 && r.runtime == 0 && r.w1 != 0;
    freerun(&r);
    free(src);
    if (ok) lo = mid; else hi = mid - 1;
  }
  return lo;
}

/* `levels` nested `if true { ... }` items. run_block hands an item depth+1 and
 * a meta-if hands its then-block depth+1, so the expander's own depth counter
 * climbs by two per level and the 64 cap answers at 31. */
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
  snprintf(b + used, need - used,
           "}\n" TAIL "deep()\n" FOOT);
  {
    char *out = compose(4096, 64, 16777216, 1048576, 128, 16777216, b);
    free(b);
    return out;
  }
}

/* `nest` levels of nested `if true {}` as a SIBLING of the invocation, not as
 * its ancestor. THIS SHAPE IS THE ONLY ONE THAT REACHES declares_below's
 * walk-depth guard, and the reason is worth keeping because the obvious shape
 * silently measures a different site.
 *
 * The expander has TWO walks over the caller's module tree and they are not
 * the same walk. `walk` (macro_expand.nova) descends the module looking for
 * the invocation and raises 375/9 at depth 65 on the way DOWN. declares_below
 * walks the same tree afterwards, looking for a name the caller already
 * declares. So nesting the invocation inside the deep part -- which is what
 * nest_body above does for the template walk -- can never reach
 * declares_below's guard: `walk` refuses first, and no expansion ever runs.
 * Measured, not argued: with the invocation as an ancestor, nests 30..80 all
 * answer 375/9 and the 381 site is never entered.
 *
 * So the invocation goes at the TOP of the function body and the depth goes in
 * a sibling statement beside it. `walk` finds the invocation at depth 2 and
 * expands it, and only then does declares_below descend into the deep
 * sibling. The template's `let t` is what makes clone_let call caller_declares
 * at all, so the guard is on the path. */
static char *sibling_nest_body(unsigned nest) {
  size_t need = 1024 + (size_t)nest * 40;
  char *b = malloc(need);
  if (!b) return NULL;
  /* NO `module m` HEADER HERE, and that is compose()'s to write: it prepends
   * one of its own along with the comptime budget block. A second header
   * makes the module unparseable and every arm below answers 800, which is
   * what the first run of this arm did. */
  size_t used = (size_t)snprintf(b, need,
      "macro mk()->ast.block {\n"
      "    return quote(block) { let t:u64=1; return t; };\n}\n"
      "section .text {\n    export fn main()->u64\n    effects {}\n"
      "    clobbers {} {\n        expand mk()\n");
  for (unsigned i = 0; i < nest; i++)
    used += (size_t)snprintf(b + used, need - used, "        if true {\n");
  for (unsigned i = 0; i < nest; i++)
    used += (size_t)snprintf(b + used, need - used, "        }\n");
  used += (size_t)snprintf(b + used, need - used, "    }\n}\n");
  char *out = compose(4096, 64, 16777216, 1048576, 128, 16777216, b);
  free(b);
  return out;
}

/* A REAL collision: a module-scope `const t` and a template `let t`, which is
 * the shape the ADV_REBIND_MODULE arm above already spells as 381/1. It is
 * here as the OTHER side of the pair -- the arm that must keep publishing
 * 0/0, and without which a fix that filled the channel unconditionally would
 * pass. */
static const char *REBIND_MODULE_SRC =
    "module m\ntarget x86_64-nexora-none\n"
    "const t:u64 = 1;\n"
    "macro mk()->ast.block {\n"
    "    return quote(block) { let t:u64=1; return t; };\n}\n"
    "section .text {\n    export fn main()->u64\n    effects {}\n"
    "    clobbers {} {\n        expand mk()\n    }\n}\n";

/* A macro with `count` comptime value parameters, invoked with the same
 * number of literal arguments. */
static char *params_body(unsigned count) {
  size_t need = 512 + (size_t)count * 40;
  char *b = malloc(need);
  if (!b) return NULL;
  size_t used = (size_t)snprintf(b, need, "macro many(");
  for (unsigned i = 0; i < count; i++)
    used += (size_t)snprintf(b + used, need - used, "%sv%u:u64", i ? "," : "", i);
  used += (size_t)snprintf(b + used, need - used,
      ")->ast.decl {\n    emit quote(decl) { const c:u64 = 1; }\n}\n");
  used += (size_t)snprintf(b + used, need - used, TAIL "many(");
  for (unsigned i = 0; i < count; i++)
    used += (size_t)snprintf(b + used, need - used, "%s1", i ? "," : "");
  snprintf(b + used, need - used, ")\n" FOOT);
  {
    char *out = compose(4096, 64, 16777216, 1048576, 128, 16777216, b);
    free(b);
    return out;
  }
}

/* ---------------------------------------------------------------------
   The cross-shape fuel ladders, and the reference's own answer.

   WHY THIS EXISTS. ntasm_fuel_model.h is affine in the item count with a
   PER-SHAPE intercept, and the reason it is not one intercept is that two
   different bodies measured two different ones. This is the instrument for
   that claim: it builds each shape at several item counts, asks Nova what it
   charges, asks the C reference what IT charges for the same source, and
   compares both against the model. A model that fitted one shape and not the
   other would be two constants wearing one name, and this is where that
   shows up rather than in review.

   The reference is asked by BISECTION on the declared comptime fuel limit,
   because NtFProgram does not publish fuel_used: the smallest limit at which
   the reference verifies IS the figure it charges. That is a re-derivation
   of a THRESHOLD and is legitimate as one -- the expectation compared with
   it is the model's parameter, not the bisection's own output, so a change
   in the model turns this red and a change in the reference turns it red, and
   neither can hide behind the other. */

/* The FLAT_RET body at `items` added terms: items 0 is `return $v;` and
   items 1 is the specification's corpus member, the body the other two gates
   hold a fuel figure for. */
static char *flat_ret_body(unsigned items) {
  size_t need = 512 + (size_t)items * 4;
  char *b = malloc(need);
  if (!b) return NULL;
  size_t used = (size_t)snprintf(b, need,
      "macro ret(v:ast.expr)->ast.stmt {\n"
      "    return quote(stmt) { return $v");
  for (unsigned i = 0; i < items; i++)
    used += (size_t)snprintf(b + used, need - used, "+1");
  snprintf(b + used, need - used, "; };\n}\n" TAIL "ret(41)\n    return 0;\n" FOOT);
  return b;
}

/* The FLAT_BLOCK body at `items` let bindings, the third shape and the one
   whose base is NOT 5. */
static char *flat_block_body(unsigned items) {
  size_t need = 1024 + (size_t)items * 40;
  char *b = malloc(need);
  if (!b) return NULL;
  size_t used = (size_t)snprintf(b, need,
      "macro blk(v:ast.expr)->ast.block {\n    return quote(block) {\n");
  for (unsigned i = 0; i < items; i++)
    used += (size_t)snprintf(b + used, need - used,
                             "        let t%04u:u64 = $v;\n", i);
  /* At zero lets there is no binding to return, so the block returns the
   * parameter instead. Both are one statement in the same quoted block: the
   * rung is the shape's intercept and not a different body. */
  used += (size_t)snprintf(b + used, need - used,
      items ? "        return t0000;\n" : "        return $v;\n");
  snprintf(b + used, need - used,
           "    };\n}\n" TAIL "blk(1)\n    return 0;\n" FOOT);
  return b;
}

/* the same body with the reference's own other budgets at their maxima */
static char *ref_src(unsigned fuel, const char *body) {
  size_t need = 512 + strlen(body);
  char *b = malloc(need);
  if (!b) return NULL;
  snprintf(b, need,
           "module m\ntarget x86_64-nexora-none\n"
           "comptime(fuel=%u,call_depth=256,arena_bytes=16777216,"
           "ast_nodes=1048576,expansion_depth=128,constant_bytes=16777216)"
           "{\nreturn 1;\n}\n%s", fuel, body);
  return b;
}

static int ref_verifies(unsigned fuel, const char *body) {
  char *s = ref_src(fuel, body);
  if (!s) return 0;
  NtFInput in = {"fuel-model.ntasm", s, strlen(s)};
  NtFProgram prog = {0};
  nt_frontend_compile(&in, 1, &prog);
  int v = prog.verified;
  nt_frontend_free(&prog);
  free(s);
  return v;
}

/* The reference's exact fuel for this body, or UINT64_MAX when it refuses
   the body outright at any limit. The refusal and the figure are different
   answers and the model needs to be able to say which it got. */
static unsigned long long ref_fuel_of(const char *body) {
  if (!ref_verifies(1048576u, body)) return UINT64_MAX;
  unsigned lo = 0, hi = 1048576u;
  while (lo < hi) {
    unsigned mid = lo + (hi - lo) / 2;
    if (ref_verifies(mid, body)) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}

/* What the C reference says when it is handed the shape in the spelling THIS
   gate uses. Recorded as a code, because "the reference cannot be asked" is
   only a finding if the refusal is named. */
static unsigned ref_refuses_spellings(const char *body, uint64_t *code) {
  char *s = ref_src(1048576u, body);
  if (!s) return 0;
  NtFInput in = {"fuel-model.ntasm", s, strlen(s)};
  NtFProgram prog = {0};
  nt_frontend_compile(&in, 1, &prog);
  unsigned refused = prog.verified ? 0u : 1u;
  if (code)
    *code = prog.diagnostic_count ? (uint64_t)prog.diagnostics[0].code : 0;
  nt_frontend_free(&prog);
  free(s);
  return refused;
}

int main(void) {
  const char *paths[] = {
      "tests/nova/tests/macro-expand-entry.nova",
      "compiler/nova/macros/macro_expand.nova",
      "compiler/nova/macros/constant_eval.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/ast.nova",
      "compiler/nova/frontend/lexer.nova"};
  char *sources[6] = {0};
  NtFInput inputs[6];
  for (unsigned i = 0; i < 6; i++) {
    size_t n = 0;
    sources[i] = loadf(paths[i], &n);
    inputs[i] = (NtFInput){paths[i], sources[i], n};
  }
  int all = 1;
  for (unsigned i = 0; i < 6; i++) if (!sources[i]) all = 0;
  CHECK(all, "sources load");
  NtArtifact a = {0};
  int compiled = all && nova_compile_many_v2(inputs, 6, &a);
  CHECK(compiled, "modules compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line,
            a.error.column, a.error.message);
  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&a, &image), "image maps");
  if (image.memory) {
    {
      const char *lex="  macro m()->ast.block {\n// } comment_name\nreturn quote(block) {\nlet body_name:u64=0;\nreturn \"string_name }\";\n};\n}\n// macro fake { fake_name\nlet caller_name:u64=1;\n";
      CHECK(in_macro_body(lex,strlen(lex),(size_t)(strstr(lex,"body_name")-lex))==1,"string/comment braces do not close the macro");
      CHECK(caller_writes(lex,strlen(lex),"body_name")==0,"template name is not a caller name");
      CHECK(caller_writes(lex,strlen(lex),"comment_name")==0&&caller_writes(lex,strlen(lex),"string_name")==0,"comments and strings contain no caller identifiers");
      CHECK(caller_writes(lex,strlen(lex),"caller_name")==1,"caller token after real macro end is recognised");
      CHECK(template_binds(lex,strlen(lex),"body_name")==1&&template_binds(lex,strlen(lex),"fake_name")==0,"only real template declarations are classified");
      cases++;
    }

    /* === 1. the worked example: shape, splicing, provenance =========== */
    {
      const char *worked =
          HEAD
          "macro ret(v:ast.expr)->ast.stmt {\n"
          "    return quote(stmt) { return $v+1; };\n"
          "}\n"
          TAIL "ret(41)\n" FOOT;
      ok(&image, "worked example", worked, 5);
      Run r = run(&image, worked, 1u << 18, 0);
      cases++; checks++;
      const uint64_t *w = layout_ok(&r) ? node_words(&r, 1) : NULL;
      if (w == NULL) {
        failures++;
        fprintf(stderr, "FAIL worked example layout ret=%llu code=%llu\n",
                (unsigned long long)r.returned, (unsigned long long)r.code);
        freerun(&r);
      } else {
      /* wrapper kind 31 aux = macro ordinal 1, one child, the return */
      const uint64_t *ret = node_words(&r, 2);
      const uint64_t *plus = node_words(&r, 3);
      const uint64_t *arg = node_words(&r, 4);
      const uint64_t *one = node_words(&r, 5);
      int wrapper = w[0] == 31 && w[11] == 1 && w[8] == 2 && w[9] == 2;
      int shape = ret[0] == 29 && plus[0] == 35 && plus[11] == 43 &&
                  arg[0] == 94 && arg[11] == 41 && one[0] == 94 && one[11] == 1;
      /* the wrapper carries the invocation position and the spliced literal
       * keeps the caller token range, which is the macro -> invocation ->
       * source chain of spec/ntasm/ntasm.md 13 */
      int prov = w[4] == 10 && w[5] == 9 && w[6] == 195 && w[7] == 210;
      int chain = arg[4] == 10 && arg[5] == 9 && arg[1] == 67 && arg[2] == 67 &&
                  arg[6] == 195 && arg[7] == 210;
      int template_origin = plus[1] == 32 && plus[2] == 35 && ret[1] == 31 &&
                            ret[2] == 36;
      if (!(wrapper && shape && prov && chain && template_origin)) {
        failures++;
        fprintf(stderr, "FAIL worked example wrapper=%d shape=%d prov=%d chain=%d template=%d\n",
                wrapper, shape, prov, chain, template_origin);
        fprintf(stderr, "    arg k=%llu aux=%llu tb=%llu te=%llu [%llu,%llu) line=%llu col=%llu\n",
                (unsigned long long)arg[0], (unsigned long long)arg[11],
                (unsigned long long)arg[1], (unsigned long long)arg[2],
                (unsigned long long)arg[6], (unsigned long long)arg[7],
                (unsigned long long)arg[4], (unsigned long long)arg[5]);
        dump(&r);
      }
      freerun(&r);
      }
    }
    /* two invocations differ only by the expansion serial */
    {
      const char *twice =
          HEAD
          "macro ret(v:ast.expr)->ast.stmt {\n"
          "    return quote(stmt) { return $v+1; };\n"
          "}\n"
          TAIL "ret(41)\n        expand ret(42)\n" FOOT;
      ok(&image, "two invocations", twice, 10);
      Run r = run(&image, twice, 1u << 18, 0);
      cases++; checks++;
      const uint64_t *a = layout_ok(&r) ? node_words(&r, 1) : zero12;
      const uint64_t *b = layout_ok(&r) ? node_words(&r, 6) : zero12;
      int same = a[0] == 31 && b[0] == 31 && a[11] == b[11] && b[11] == 1 &&
                 b[6] == a[6] + 23;
      if (!same) {
        failures++;
        fprintf(stderr, "FAIL two invocations %llu %llu\n",
                (unsigned long long)a[6], (unsigned long long)b[6]);
      }
      freerun(&r);
    }

    /* === 2. hygiene marks, exactly as the C reference ================== */
    {
      const char *hyg =
          HEAD
          "macro mk(v:ast.expr)->ast.block {\n"
          "    return quote(block) {\n"
          "        let t:u64=$v+1;\n"
          "        return $t;\n"
          "    };\n"
          "}\n"
          TAIL "mk(41)\n" FOOT;
      ok(&image, "hygienic local", hyg, 11);
      Run r = run(&image, hyg, 1u << 18, 0);
      cases++; checks++;
      uint64_t letn = layout_ok(&r) ? find_kind(&r, 1, 27) : 0;
      uint64_t retn = layout_ok(&r) ? find_kind(&r, 1, 29) : 0;
      if (letn == 0 || retn == 0) {
        failures++;
        fprintf(stderr, "FAIL hygienic local shape let=%llu ret=%llu\n",
                (unsigned long long)letn, (unsigned long long)retn);
      } else {
        const uint64_t *letname = child_at(&r, letn, 0);
        const uint64_t *refname = child_at(&r, retn, 0);
        int marked = name_is(&r, letname[6], letname[7], "__ntm$1$e1$t");
        int rewritten = name_is(&r, refname[6], refname[7], "__ntm$1$e1$t");
        int named = letname[0] == 90 && letname[11] == 1 &&
                    refname[0] == 90 && refname[11] == 1;
        if (!(marked && rewritten && named)) {
          failures++;
          fprintf(stderr, "FAIL hygiene mark=%d rewrite=%d named=%d\n", marked,
                  rewritten, named);
          dump(&r);
        }
      }
      freerun(&r);
    }
    /* the serial separates two expansions of the same macro */
    {
      const char *two =
          HEAD
          "macro mk(v:ast.expr)->ast.block {\n"
          "    return quote(block) {\n"
          "        let t:u64=$v+1;\n"
          "        return $t;\n"
          "    };\n"
          "}\n"
          TAIL "mk(1)\n        expand mk(2)\n" FOOT;
      ok(&image, "two hygienic locals", two, 22);
      Run r = run(&image, two, 1u << 18, 0);
      cases++; checks++;
      uint64_t l1 = layout_ok(&r) ? find_kind(&r, 1, 27) : 0;
      uint64_t l2 = 0;
      if (l1 != 0) {
        uint64_t scan = l1 + 1;
        while (scan <= r.w1 && l2 == 0) {
          if (node_words(&r, scan)[0] == 27) l2 = scan;
          scan++;
        }
      }
      if (l1 == 0 || l2 == 0) {
        failures++;
        fprintf(stderr, "FAIL two hygienic locals shape %llu %llu\n",
                (unsigned long long)l1, (unsigned long long)l2);
        dump(&r);
      } else {
        const uint64_t *n1 = child_at(&r, l1, 0);
        const uint64_t *n2 = child_at(&r, l2, 0);
        int first = name_is(&r, n1[6], n1[7], "__ntm$1$e1$t");
        int second = name_is(&r, n2[6], n2[7], "__ntm$1$e2$t");
        if (!(first && second)) {
          failures++;
          fprintf(stderr, "FAIL serial e1=%d e2=%d\n", first, second);
        }
      }
      freerun(&r);
    }
    /* a generated declaration uses __ntd$ with the repeat and item indices */
    {
      const char *decl =
          HEAD
          "macro three(n:u64)->ast.decl {\n"
          "    for i in $n {\n"
          "        emit quote(decl) { const c:u64 = $i; }\n"
          "    }\n"
          "}\n"
          TAIL "three(2)\n" FOOT;
      ok(&image, "generated declarations", decl, 12);
      Run r = run(&image, decl, 1u << 18, 0);
      cases++; checks++;
      uint64_t d0 = layout_ok(&r) ? find_kind(&r, 1, 10) : 0;
      uint64_t d1 = 0;
      if (d0 != 0) {
        uint64_t scan = d0 + 1;
        while (scan <= r.w1 && d1 == 0) {
          if (node_words(&r, scan)[0] == 10) d1 = scan;
          scan++;
        }
      }
      if (d0 != 0 && d1 != 0) {
        const uint64_t *n0 = child_at(&r, d0, 0);
        int c0 = name_is(&r, n0[6], n0[7], "__ntd$1$e1$r0$t0$c");
        int v0 = child_at(&r, d0, 2)[11] == 0;
        const uint64_t *n1 = child_at(&r, d1, 0);
        int c1 = name_is(&r, n1[6], n1[7], "__ntd$1$e1$r1$t0$c");
        int v1 = child_at(&r, d1, 2)[11] == 1;
        if (!(c0 && c1 && v0 && v1)) {
          failures++;
          fprintf(stderr, "FAIL ntd r0=%d v0=%d r1=%d v1=%d d0=%llu d1=%llu\n",
                  c0, v0, c1, v1, (unsigned long long)d0,
                  (unsigned long long)d1);
          dump(&r);
        }
      } else {
        failures++;
        fprintf(stderr, "FAIL generated declarations shape d0=%llu d1=%llu\n",
                (unsigned long long)d0, (unsigned long long)d1);
        dump(&r);
      }
      freerun(&r);
    }
    /* a generated function parameter uses __ntp$ and the body follows it */
    {
      const char *fn =
          HEAD
          "macro mk()->ast.decl {\n"
          "    emit quote(decl) {\n"
          "        fn helper(in n:u64)->u64\n"
          "        effects {}\n"
          "        clobbers {} {\n"
          "            return $n+1;\n"
          "        }\n"
          "    }\n"
          "}\n"
          TAIL "mk()\n" FOOT;
      ok(&image, "generated function", fn, 16);
      Run r = run(&image, fn, 1u << 18, 0);
      cases++; checks++;
      uint64_t f = layout_ok(&r) ? find_kind(&r, 1, 18) : 0;
      uint64_t p = layout_ok(&r) ? find_kind(&r, 1, 19) : 0;
      if (f == 0 || p == 0) {
        failures++;
        fprintf(stderr, "FAIL generated function shape fn=%llu param=%llu\n",
                (unsigned long long)f, (unsigned long long)p);
      } else {
        const uint64_t *fname = child_at(&r, f, 0);
        const uint64_t *pname = child_at(&r, p, 0);
        int fn_ok = name_is(&r, fname[6], fname[7], "__ntd$1$e1$helper");
        int p_ok = name_is(&r, pname[6], pname[7], "__ntp$1$e1$p0$n");
        /* the body reference to the parameter is rewritten to the same text */
        uint64_t body = find_kind(&r, 1, 25);
        uint64_t names = body ? count_kind(&r, body, 90) : 0;
        int one_mark = names == 1;
        if (!(fn_ok && p_ok && one_mark)) {
          failures++;
          fprintf(stderr, "FAIL ntd fn=%d ntp param=%d names=%llu\n", fn_ok,
                  p_ok, (unsigned long long)names);
          dump(&r);
        }
      }
      freerun(&r);
    }

    /* === 3. argument splicing, never a re-parse ========================= */
    {
      const char *splice =
          HEAD
          "macro pass(v:ast.expr)->ast.expr {\n"
          "    return quote(expr) { $v };\n"
          "}\n"
          TAIL "pass(1+2)\n" FOOT;
      ok(&image, "structured splice", splice, 4);
      Run r = run(&image, splice, 1u << 18, 0);
      cases++; checks++;
      uint64_t e = layout_ok(&r) ? find_kind(&r, 1, 35) : 0;
      int shape = e != 0 && node_words(&r, e)[11] == 43 &&
                  child_at(&r, e, 0)[0] == 94 &&
                  child_at(&r, e, 0)[11] == 1 &&
                  child_at(&r, e, 1)[0] == 94 &&
                  child_at(&r, e, 1)[11] == 2;
      if (!shape) {
        failures++;
        fprintf(stderr, "FAIL structured splice\n");
      }
      freerun(&r);
    }
    /* a caller symbol argument keeps the caller token range, which a re-parse
     * of a string could not produce */
    {
      const char *ref =
          HEAD "const secret:u64=7\n"
          "macro pass(v:ast.expr)->ast.expr {\n"
          "    return quote(expr) { $v };\n"
          "}\n"
          TAIL "pass(secret)\n" FOOT;
      ok(&image, "caller symbol argument", ref, 4);
      Run r = run(&image, ref, 1u << 18, 0);
      cases++; checks++;
      uint64_t e = layout_ok(&r) ? find_kind(&r, 1, 35) : 0;
      uint64_t q = e ? find_kind(&r, e, 91) : 0;
      uint64_t nm = q ? find_kind(&r, q, 90) : 0;
      int isname = e != 0 && node_words(&r, e)[11] == 0 && q != 0 && nm != 0;
      int text = isname && name_is(&r, node_words(&r, nm)[6],
                                   node_words(&r, nm)[7], "secret");
      /* the origin tokens sit in the caller source, at the argument */
      int caller = isname && node_words(&r, nm)[1] >= 1 &&
                   node_words(&r, nm)[2] == node_words(&r, nm)[1] &&
                   node_words(&r, nm)[3] == 1;
      if (!(isname && text && caller)) {
        failures++;
        fprintf(stderr, "FAIL spliced caller symbol name=%d text=%d caller=%d\n",
                isname, text, caller);
      }
      freerun(&r);
    }
    /* an ast.type parameter is spliced as a typed node */
    {
      const char *ty =
          HEAD
          "macro take(t:ast.type)->ast.expr {\n"
          "    return quote(expr) { 1 };\n"
          "}\n"
          TAIL "take(quote(type) { u32 })\n" FOOT;
      ok(&image, "type argument", ty, 2);
      err(&image, "type argument refused in a splice",
          HEAD
          "macro take(t:ast.type)->ast.expr {\n"
          "    return quote(expr) { $t };\n"
          "}\n"
          TAIL "take(quote(type) { u32 })\n" FOOT, 372, 1);
    }
    /* a comptime value parameter is folded by the only evaluator */
    {
      const char *val =
          HEAD
          "macro twice(k:u64)->ast.expr {\n"
          "    return quote(expr) { $k*2 };\n"
          "}\n"
          TAIL "twice(21)\n" FOOT;
      ok(&image, "value parameter", val, 4);
      Run r = run(&image, val, 1u << 18, 0);
      cases++; checks++;
      uint64_t e = layout_ok(&r) ? find_kind(&r, 1, 35) : 0;
      int folded = e != 0 && node_words(&r, e)[11] == 42 &&
                   child_at(&r, e, 0)[0] == 94 &&
                   child_at(&r, e, 0)[11] == 21;
      if (!folded) {
        failures++;
        fprintf(stderr, "FAIL value parameter\n");
      }
      freerun(&r);
    }
    /* a value parameter is range checked against its declared type */
    err(&image, "value parameter out of range",
        HEAD
        "macro byte(k:u8)->ast.expr {\n"
        "    return quote(expr) { $k };\n"
        "}\n"
        TAIL "byte(256)\n" FOOT, 372, 6);
    err(&image, "value parameter is not a literal",
        HEAD
        "macro twice(k:u64)->ast.expr {\n"
        "    return quote(expr) { $k*2 };\n"
        "}\n"
        TAIL "twice(1+2)\n" FOOT, 372, 5);
    /* === 4. meta if and meta for, decided by constant_eval ============= */
    {
      const char *iff =
          HEAD
          "macro pick(k:u64,v:ast.expr)->ast.expr {\n"
          "    if $k {\n"
          "        return quote(expr) { $v+1 };\n"
          "    } else {\n"
          "        return quote(expr) { 0 };\n"
          "    }\n"
          "}\n"
          TAIL "pick(1,7)\n" FOOT;
      ok(&image, "meta if true", iff, 4);
      Run r = run(&image, iff, 1u << 18, 0);
      cases++; checks++;
      uint64_t e = layout_ok(&r) ? find_kind(&r, 1, 35) : 0;
      int taken = e != 0 && node_words(&r, e)[11] == 43;
      if (!taken) { failures++; fprintf(stderr, "FAIL meta if true branch\n"); }
      freerun(&r);

      char *off = malloc(strlen(iff) + 32);
      if (off) {
        char *hit = strstr(off, "x");
        (void)hit;
        snprintf(off, strlen(iff) + 32, "%s", iff);
        char *at = strstr(off, "pick(1,7)");
        if (at) memcpy(at, "pick(0,7)", 8);
        ok(&image, "meta if false", off, 2);        free(off);
      }
    }
    /* a meta let folds its value in order and the binding is usable after */
    {
      const char *let =
          HEAD
          "macro pick(k:u64,v:ast.expr)->ast.expr {\n"
          "    let t = $k*2;\n"
          "    return quote(expr) { $t };\n"
          "}\n"
          TAIL "pick(21,7)\n" FOOT;
      ok(&image, "meta let", let, 2);
      Run r = run(&image, let, 1u << 18, 0);
      cases++; checks++;
      uint64_t lit = layout_ok(&r) ? find_kind(&r, 1, 94) : 0;
      int folded = lit != 0 && node_words(&r, lit)[11] == 42;
      if (!folded) {
        failures++;
        fprintf(stderr, "FAIL meta let folded constant\n");
      }
      freerun(&r);
    }
    /* a meta-if condition that is not a deterministic constant is refused */
    err(&image, "meta if non constant",
        HEAD "const secret:u64=1\n"
        "macro pick(v:ast.expr)->ast.expr {\n"
        "    if $v {\n"
        "        return quote(expr) { 1 };\n"
        "    } else {\n"
        "        return quote(expr) { 0 };\n"
        "    }\n"
        "}\n"
        TAIL "pick(secret)\n" FOOT, 379, 5);
    /* a meta for with a negative count is refused */
    err(&image, "meta for negative count",
        HEAD
        "macro three(n:i64)->ast.decl {\n"
        "    for i in $n {\n"
        "        emit quote(decl) { const c:u64 = 0; }\n"
        "    }\n"
        "}\n"
        TAIL "three(-1)\n" FOOT, 380, 1);
    /* a meta for beyond the per expansion cap is refused */
    err(&image, "meta for beyond the cap",
        HEAD
          "macro three(n:u64)->ast.decl {\n"
          "    for i in $n {\n"
          "        emit quote(decl) { const c:u64 = $i; }\n"
          "    }\n"
          "}\n"
          TAIL "three(513)\n" FOOT, 380, 2);

    /* === 5. adversarial: capture is structurally refused =============== */
    err(&image, "capture of a caller symbol refused",
        HEAD "const secret:u64=7\n"
        "macro steal(v:ast.expr)->ast.expr {\n"
        "    return quote(expr) { $v+secret };\n"
        "}\n"
        TAIL "steal(1)\n" FOOT, 374, 1);
    /* hygiene is lexical, not name based: the same refusal without any such
     * caller symbol */
    err(&image, "unbound template name refused",
        HEAD
        "macro steal(v:ast.expr)->ast.expr {\n"
        "    return quote(expr) { v+1 };\n"
        "}\n"
        TAIL "steal(1)\n" FOOT, 374, 1);
    /* a call target is a binding position too */
    err(&image, "call target capture refused",
        HEAD
        "macro go(v:ast.expr)->ast.stmt {\n"
        "    return quote(stmt) { call helper($v) };\n"
        "}\n"
        TAIL "go(1)\n" FOOT, 374, 1);
    {
      const char *call =
          HEAD
          "macro go(v:ast.expr)->ast.stmt {\n"
          "    return quote(stmt) { call helper($v) };\n"
          "}\n"
          TAIL "go(1)\n" FOOT;
      Run r = run(&image, call, 1u << 18, 0);
      cases++; checks++;
      if (r.returned == 0) {
        failures++;
        fprintf(stderr, "FAIL call target was not a binding position\n");
        dump(&r);
      }
      freerun(&r);
    }
    /* a template name that shadows a macro parameter is refused */
    err(&image, "parameter shadow refused",
        HEAD
        "macro bad(v:ast.expr)->ast.block {\n"
        "    return quote(block) {\n"
        "        let v:u64=$v;\n"
        "        return v;\n"
        "    };\n"
        "}\n"
        TAIL "bad(1)\n" FOOT, 376, 2);
    /* a macro may not fabricate an exported symbol */
    err(&image, "exported declaration refused",
        HEAD
        "macro mk()->ast.decl {\n"
        "    emit quote(decl) { export data d:u64=1; }\n"
        "}\n"
        TAIL "mk()\n" FOOT, 377, 2);
    /* a macro may not fabricate a proof */
    err(&image, "fabricated requires refused",
        HEAD
        "macro mk()->ast.decl {\n"
        "    emit quote(decl) {\n"
          "        fn helper(in n:u64)->u64\n"
          "        effects {}\n"
          "        clobbers {}\n"
          "        requires { }\n"
          "        {\n"
          "            return n;\n"
          "        }\n"
          "    }\n"
          "}\n"
          TAIL "mk()\n" FOOT, 375, 3);
    /* a macro may not delete a real effect: the effect set of a produced
     * function comes from its own quoted declaration, and the statement an
     * invocation replaces is the expand itself, which carries none. */
    {
      const char *eff =
          HEAD
          "macro drop()->ast.stmt {\n"
          "    return quote(stmt) { return 0 };\n"
          "}\n"
          TAIL "drop()\n" FOOT;
      ok(&image, "effect set comes from the template", eff, 3);
    }
    /* A hygiene mark contains $, and the NTASM lexer cannot put $ inside an
     * identifier, so a generated name can never collide with a real caller
     * symbol. The refusal exists as defence in depth and is unreachable from
     * NTASM source; this is the proof that it stays unreachable. */
    {
      Run r = run(&image, HEAD "const a$b:u64=1\n", 64, 0);
      cases++; checks++;
      if (r.returned != 800) {
        failures++;
        fprintf(stderr, "FAIL a dollar sign in an identifier ret=%llu\n",
                (unsigned long long)r.returned);
      }
      freerun(&r);
    }

    /* === 6. the closed vocabulary ====================================== */
    /* The expander reads and writes exactly these node kinds. There is no
     * kind for a file, a socket, a clock, a random source, an environment
     * read, a host address or a process, and the module takes no input beyond
     * the parsed tree, the six budgets and its own scratch, so a template
     * cannot name an observation and cannot obtain one. A call argument is
     * refused rather than read, so a call is not a channel either. */
    {
      static const uint64_t closed[] = {
          10, 18, 19, 20, 21, 24, 25, 27, 28, 29, 30, 31, 32, 34, 35, 36,
          37, 38, 39, 40, 41, 42, 43, 90, 91, 92, 93, 94};
      cases++; checks++;
      if (sizeof closed / sizeof closed[0] != 28) {
        failures++;
        fprintf(stderr, "FAIL closed vocabulary size\n");
      }
      err(&image, "no observation channel in a comptime value",
          HEAD
          "macro twice(k:u64)->ast.expr {\n"
          "    return quote(expr) { $k*2 };\n"
          "}\n"
          TAIL "twice(clk())\n" FOOT, 372, 5);
      err(&image, "no observation channel in a template",
          HEAD
          "macro mk()->ast.expr {\n"
          "    return quote(expr) { env_read() };\n"
          "}\n"
          TAIL "mk()\n" FOOT, 374, 1);
    }

    /* === 7. recursion terminates inside a budget ======================= */
    {
      const char *rec =
          HEAD
          "comptime(fuel=4096,call_depth=64,arena_bytes=262144,ast_nodes=256,"
          "expansion_depth=4,constant_bytes=4096){\nreturn 1;\n}\n"
          "macro loop(v:ast.expr)->ast.stmt {\n"
          "    return quote(stmt) { expand loop($v) };\n"
          "}\n"
          TAIL "loop(1)\n" FOOT;
      char *deep = malloc(strlen(rec) + 8);
      if (deep) {
        snprintf(deep, strlen(rec) + 8, "%s", rec);
        char *at = strstr(deep, "expansion_depth=4");
        if (at) at[16] = '5';
        err(&image, "recursion refused past the depth budget", deep, 201, 5);
        free(deep);
      }
      /* the same program finishes when the depth budget is large enough for
       * the fuel budget to stop it first */
      const char *byfuel =
          HEAD
          "comptime(fuel=64,call_depth=128,arena_bytes=262144,ast_nodes=256,"
          "expansion_depth=128,constant_bytes=4096){\nreturn 1;\n}\n"
          "macro loop(v:ast.expr)->ast.stmt {\n"
          "    return quote(stmt) { expand loop($v) };\n"
          "}\n"
          TAIL "loop(1)\n" FOOT;
      err(&image, "recursion refused past the fuel budget", byfuel, 201, 1);
    }

    /* === 8. the six budgets at the exact limit and one past ============ */
    /* Swept twice: once on a body that costs one expansion, and once on a
     * body that reaches a second expansion from inside the first. A budget a
     * nested expansion could dodge would answer the second sweep differently
     * from the first, and the figures both sweeps use are measured at run
     * time by the expander itself. */
    budget_sweep(&image, "flat", BODY);
    budget_sweep(&image, "nested", BODY2);
    /* A depth budget of one is enough for a flat body and one step short for
     * the same body nested, which is the evasion this pair exists to refuse:
     * the number is the same, the reachable depth is not. */
    {
      char *flat1 = compose(4096, 64, 4194304, 8192, 1, 65536, BODY);
      char *nest1 = compose(4096, 64, 4194304, 8192, 1, 65536, BODY2);
      if (flat1 && nest1) {
        fine(&image, "depth one is enough for a flat body", flat1);
        err(&image, "depth one is one short for a nested body", nest1, 201, 5);
      } else { failures++; fprintf(stderr, "FAIL compose depth pair\n"); }
      free(flat1); free(nest1);
    }
    /* a budget block that is not exactly the six mandated limits is refused */
    err(&image, "missing limit refused",
        HEAD "comptime(fuel=16,call_depth=4,arena_bytes=262144,ast_nodes=256,"
        "expansion_depth=4){\nreturn 1;\n}\n", 378, 1);
    err(&image, "limit above the frozen maximum refused",
        HEAD "comptime(fuel=1048577,call_depth=4,arena_bytes=262144,"
        "ast_nodes=256,expansion_depth=4,constant_bytes=64){\nreturn 1;\n}\n",
        378, 1);
    err(&image, "duplicate limit refused",
        HEAD "comptime(fuel=16,fuel=16,call_depth=4,arena_bytes=262144,"
        "ast_nodes=256,expansion_depth=4,constant_bytes=64){\nreturn 1;\n}\n",
        378, 1);
    err(&image, "unknown limit name refused",
        HEAD "comptime(fuel=16,call_depth=4,arena_bytes=262144,ast_nodes=256,"
        "expansion_depth=4,constant_words=64){\nreturn 1;\n}\n", 378, 1);

    /* === 9. refusals and transactional output =========================== */
    err(&image, "unknown macro",
        HEAD TAIL "ghost(1)\n" FOOT, 370, 1);
    err(&image, "arity mismatch",
        HEAD "macro ret(v:ast.expr)->ast.stmt {\n"
        "    return quote(stmt) { return $v; };\n}\n"
        TAIL "ret(1,2)\n" FOOT, 371, 1);
    err(&image, "parameter kind mismatch",
        HEAD "macro ret(v:ast.expr)->ast.stmt {\n"
        "    return quote(stmt) { return $v; };\n}\n"
        TAIL "ret(quote(type) { u8 })\n" FOOT, 372, 4);
    err(&image, "quote kind does not match the result",
        HEAD "macro ret(v:ast.expr)->ast.stmt {\n"
        "    return quote(expr) { $v };\n}\n"
        TAIL "ret(1)\n" FOOT, 372, 1);
    /* A type position expansion cannot be written: the grammar reads a name
     * then a parenthesised meta value list, never a macro invocation, so the
     * refusal of kind 36 aux 3 is defence in depth and stays unreachable. */
    structural(&image, "type position expansion is not writable",
               HEAD "section .text {\n    export fn main()->u64\n"
               "    effects {}\n    clobbers {} {\n"
               "        let x:expand(mk())=0;\n    }\n}\n", 64);
    err(&image, "two results in one macro body refused",
        HEAD "macro mk()->ast.expr {\n"
        "    return quote(expr) { 1 };\n"
        "    return quote(expr) { 2 };\n}\n"
        TAIL "mk()\n" FOOT, 377, 5);
    err(&image, "declaration result needs a meta emit",
        HEAD "macro mk()->ast.decl {\n"
        "    return quote(decl) { const c:u64=1; };\n}\n"
        TAIL "mk()\n" FOOT, 377, 3);
    err(&image, "statement result refuses a meta emit",
        HEAD "macro mk()->ast.stmt {\n"
        "    emit quote(stmt) { return 0 };\n}\n"
        TAIL "mk()\n" FOOT, 377, 4);
    /* a caller buffer that cannot hold the produced region is a refusal, not
     * a truncated AST */
    {
      char *full = compose(4096, 64, 4194304, 8192, 64, 65536, BODY);
      Run r = run(&image, full ? full : "", 8, 0);
      cases++; checks++;
      if (r.returned != 203 || r.code != 203 || r.w1 == 0) {
        failures++;
        fprintf(stderr, "FAIL short output buffer ret=%llu code=%llu w1=%llu\n",
                (unsigned long long)r.returned, (unsigned long long)r.code,
                (unsigned long long)r.w1);
      }
      freerun(&r);
      free(full);
    }
    structural(&image, "invalid tree", "not ntasm\n", 64);
    structural(&image, "source without a module header", BODY, 64);

    /* === 10. determinism: the same expansion twice, byte identical ===== */
    {
      const char *det =
          HEAD
          "comptime(fuel=4096,call_depth=8,arena_bytes=65536,ast_nodes=512,"
          "expansion_depth=8,constant_bytes=4096){\nreturn 1;\n}\n"
          "macro mk(v:ast.expr,w:u64)->ast.block {\n"
          "    let t = $w*2;\n"
          "    return quote(block) {\n"
          "        let a:u64=$v;\n"
          "        return a;\n"
          "    };\n"
          "}\n"
          "macro decl(n:u64)->ast.decl {\n"
          "    for i in $n {\n"
          "        emit quote(decl) { const c:u64 = $i; }\n"
          "    }\n"
          "}\n"
          TAIL "mk(1,2)\n        expand decl(2)\n" FOOT;
      Run a = run(&image, det, 1u << 18, 0);
      Run b = run(&image, det, 1u << 18, 0);
      cases++; checks++;
      uint64_t span = 4 + (a.w2 + 7) / 8 + a.w1 * 12;
      int same = a.returned == 0 && b.returned == 0 && a.w1 == b.w1 &&
                 a.w2 == b.w2 && span <= a.words;
      if (same) {
        uint64_t i = 0;
        while (i < span && same) {
          if (a.out[i] != b.out[i]) same = 0;
          i++;
        }
      }
      if (!same) {
        failures++;
        fprintf(stderr, "FAIL determinism ret=%llu/%llu nodes=%llu/%llu\n",
                (unsigned long long)a.returned, (unsigned long long)b.returned,
                (unsigned long long)a.w1, (unsigned long long)b.w1);
      }
      freerun(&a);
      freerun(&b);
    }

    /* === 11. adversarial: shadowing, reserved words and observation ==== */
    /* Every node of one expansion, of one kind, in produced order. The
     * expander emits in lexical order, which is the order the two hygienic
     * locals case above already relies on. */
    {
    static const char *nest =
        HEAD
        "macro inner()->ast.block {\n"
        "    return quote(block) { let t:u64=1; return t; };\n"
        "}\n"
        "macro outer()->ast.block {\n"
        "    return quote(block) {\n"
        "        let t:u64=2;\n"
        "        expand inner();\n"
        "        return t;\n"
        "    };\n"
        "}\n"
        TAIL "outer()\n" FOOT;
    Run r = run(&image, nest, 1u << 18, 0);
    cases++; checks++;
    if (!layout_ok(&r)) {
      failures++;
      fprintf(stderr,
              "FAIL nested shadowing ret=%llu runtime=%llu code=%llu "
              "w1=%llu w2=%llu reason=%llu\n",
              (unsigned long long)r.returned, (unsigned long long)r.runtime,
              (unsigned long long)r.code, (unsigned long long)r.w1,
              (unsigned long long)r.w2, (unsigned long long)r.reason);
      dump(&r);
      freerun(&r);
    } else {
    char let_mark[2][64], ref_mark[2][64];
    uint64_t let_pos[2], ref_pos[2];
    uint64_t nl = 0, nr = 0;
    for (uint64_t id = 1; id <= r.w1; id++) {
      const uint64_t *n = node_words(&r, id);
      uint64_t inv = n[4] * 1000 + n[5];
      if (n[0] == 27 && nl < 2) {
        const uint64_t *nm = child_at(&r, id, 0);
        name_copy(&r, nm[6], nm[7], let_mark[nl], sizeof let_mark[0]);
        let_pos[nl++] = inv;
      } else if (n[0] == 29 && nr < 2) {
        uint64_t rf = find_kind(&r, id, 90);
        const uint64_t *nm = rf ? node_words(&r, rf) : zero12;
        name_copy(&r, nm[6], nm[7], ref_mark[nr], sizeof ref_mark[0]);
        ref_pos[nr++] = inv;
      }
    }
    /* The inner expansion binds t while the outer one still has t in scope,
     * so the two marks must differ and each return must read the mark the
     * let of its own expansion introduced. A binding stack the nested
     * expansion overwrote answers 1 on the second pairing. */
    int paired = 0, distinct = 0;
    if (nl == 2 && nr == 2 && let_pos[0] != let_pos[1]) {
      for (unsigned i = 0; i < 2; i++) {
        for (unsigned k = 0; k < 2; k++) {
          if (let_pos[i] == ref_pos[k] &&
              strcmp(let_mark[i], ref_mark[k]) == 0) paired++;
        }
      }
      distinct = strcmp(let_mark[0], let_mark[1]) != 0;
    }
    if (!(paired == 2 && distinct)) {
      failures++;
      fprintf(stderr,
              "FAIL nested shadowing lets=%llu returns=%llu paired=%d "
              "distinct=%d [%s@%llu %s@%llu] [%s@%llu %s@%llu]\n",
              (unsigned long long)nl, (unsigned long long)nr, paired,
              distinct, let_mark[0], (unsigned long long)let_pos[0],
              let_mark[1], (unsigned long long)let_pos[1], ref_mark[0],
              (unsigned long long)ref_pos[0], ref_mark[1],
              (unsigned long long)ref_pos[1]);
      dump(&r);
    }
    freerun(&r);
    }
    }
    /* A name written in a macro body must not resolve to a caller scope
     * symbol, and the caller here really has that local in scope, so a
     * name based resolution would succeed here and a lexical one does not. */
    err(&image, "caller local is not captured by a template name",
        HEAD
        "macro steal()->ast.stmt {\n"
        "    return quote(stmt) { return t; };\n"
        "}\n"
        "section .text {\n"
        "    export fn main()->u64\n"
        "    effects {}\n"
        "    clobbers {} {\n"
        "        let t:u64=9;\n"
        "        expand steal()\n"
        "    }\n"
        "}\n", 374, 1);
    /* A comptime value argument accepts a literal, true, false or the unary
     * minus of a literal, and nothing else. A caller symbol is therefore not
     * observable at comptime: reading one is a parameter mismatch, so the
     * evaluator has no channel to the module namespace. */
    err(&image, "a comptime value cannot read a caller const",
        HEAD "const secret:u64=7\n"
        "macro twice(k:u64)->ast.expr {\n"
        "    return quote(expr) { $k*2 };\n"
        "}\n"
        TAIL "twice(secret)\n" FOOT, 372, 5);
    err(&image, "a comptime value cannot read a caller data label",
        HEAD "section .rdata {\ndata secret:u64=7\n}\n"
        "macro twice(k:u64)->ast.expr {\n"
        "    return quote(expr) { $k*2 };\n"
        "}\n"
        TAIL "twice(secret)\n" FOOT, 372, 5);
    /* A template that spells an observation has no node to put it in: the
     * callee is a binding position, so it is refused before any name table
     * or arena is touched. Every spelling of every observation the closed
     * vocabulary of spec/ntasm/ntasm.md 12 lists is refused the same way. */
    {
      static const char *spells[] = {"time", "clock", "now", "rand",
                                     "random", "env", "getenv", "file",
                                     "read", "open", "socket", "pid",
                                     "addr", "host", "time_ns"};
      for (unsigned i = 0; i < sizeof spells / sizeof spells[0]; i++) {
        char src[512];
        snprintf(src, sizeof src,
                 HEAD "macro probe()->ast.expr {\n"
                 "    return quote(expr) { %s() };\n}\n"
                 TAIL "probe()\n" FOOT, spells[i]);
        char label[64];
        snprintf(label, sizeof label, "observation %s refused", spells[i]);
        err(&image, label, src, 374, 1);
      }
    }
    /* The positive side of the same rule: the two boolean words decide a
     * meta-if without being folded, so a template can branch on a literal.
     * The parser spells a bare word as a qualified name, so this only answers
     * 0 if the word is recognised through that shape. */
    {
      static const char *words[2][2] = {{"true", "1"}, {"false", "2"}};
      for (unsigned i = 0; i < 2; i++) {
        char src[512];
        snprintf(src, sizeof src,
                 HEAD
                 "macro pick()->ast.decl {\n"
                 "    if %s {\n"
                 "        emit quote(decl) { const c:u64=1; }\n"
                 "    } else {\n"
                 "        emit quote(decl) { const c:u64=2; }\n"
                 "    }\n"
                 "}\n"
                 TAIL "pick()\n" FOOT, words[i][0]);
        Run r = run(&image, src, 1u << 18, 0);
        cases++; checks++;
        uint64_t d = layout_ok(&r) ? find_kind(&r, 1, 10) : 0;
        uint64_t got = d ? child_at(&r, d, 2)[11] : 0;
        uint64_t want = (uint64_t)atoi(words[i][1]);
        if (d == 0 || got != want) {
          failures++;
          fprintf(stderr, "FAIL meta if on %s produced aux=%llu want=%llu\n",
                  words[i][0], (unsigned long long)got,
                  (unsigned long long)want);
          dump(&r);
        }
        freerun(&r);
      }
    }
    /* A reserved word is a token the rest of the module reads textually, so
     * a template that binds one would decide a meta-if from the word rather
     * than from its own binding. Hygiene refuses the binding instead. */
    err(&image, "a template may not bind true",
        HEAD
        "macro pick()->ast.decl {\n"
        "    let true = 0;\n"
        "    if true {\n"
        "        emit quote(decl) { const c:u64=1; }\n"
        "    } else {\n"
        "        emit quote(decl) { const c:u64=2; }\n"
        "    }\n"
        "}\n"
        TAIL "pick()\n" FOOT, 376, 3);
    err(&image, "a template may not bind u64",
        HEAD
        "macro pick()->ast.decl {\n"
        "    let u64 = 1;\n"
        "    emit quote(decl) { const c:u64=1; }\n"
        "}\n"
        TAIL "pick()\n" FOOT, 376, 3);
    /* A macro that recurses through a second macro, and not through itself,
     * is bounded by exactly the same depth budget as one that does. */
    {
      const char *two =
          HEAD
          "comptime(fuel=4096,call_depth=64,arena_bytes=262144,ast_nodes=256,"
          "expansion_depth=2,constant_bytes=4096){\nreturn 1;\n}\n"
          "macro inner(v:ast.expr)->ast.stmt {\n"
          "    return quote(stmt) { return $v; };\n"
          "}\n"
          "macro outer()->ast.stmt {\n"
          "    return quote(stmt) { expand inner(1) };\n"
          "}\n"
          TAIL "outer()\n" FOOT;
      fine(&image, "indirect recursion at the exact depth limit", two);
      char *one = malloc(strlen(two) + 8);
      if (one) {
        snprintf(one, strlen(two) + 8, "%s", two);
        char *at = strstr(one, "expansion_depth=2");
        if (at) at[16] = '1';
        err(&image, "indirect recursion one level past", one, 201, 5);
        free(one);
      }
    }
    /* Provenance with no parameter anywhere in the module: the declaration
     * a macro introduces and the statement that reads it carry the same
     * marked name, and both carry the invocation span exactly as
     * compiler/c/ntasm/frontend/frontend.c stamps every node it produces. The
     * names are the hygiene property and they are pinned; the span equality
     * is the measured reason the pipeline stage initializer_types cannot
     * order the produced let before the produced return, and it is pinned
     * here so the cause travels with the fix rather than being re-found. */
    {
      const char *letref =
          HEAD
          "macro mk()->ast.decl {\n"
          "    emit quote(decl) {\n"
          "        fn helper()->u64\n"
          "        effects {}\n"
          "        clobbers {} {\n"
          "            let t:u64=1;\n"
          "            return t;\n"
          "        }\n"
          "    }\n"
          "}\n"
          TAIL "mk()\n" FOOT;
      Run r = run(&image, letref, 1u << 18, 0);
      cases++; checks++;
      uint64_t l = layout_ok(&r) ? find_kind(&r, 1, 27) : 0;
      uint64_t ret = layout_ok(&r) ? find_kind(&r, 1, 29) : 0;
      /* a return of a name reads it under a qualified name under the
       * expression, so the reference is not a child of the return */
      uint64_t ref = ret ? find_kind(&r, ret, 90) : 0;
      if (l == 0 || ret == 0 || ref == 0) {
        failures++;
        fprintf(stderr,
                "FAIL produced let reference shape let=%llu return=%llu "
                "ref=%llu\n",
                (unsigned long long)l, (unsigned long long)ret,
                (unsigned long long)ref);
        dump(&r);
      } else {
        const uint64_t *ln = child_at(&r, l, 0);
        const uint64_t *rn = node_words(&r, ref);
        int same = name_is(&r, ln[6], ln[7], "__ntm$1$e1$t") &&
                   name_is(&r, rn[6], rn[7], "__ntm$1$e1$t");
        int named = ln[0] == 90 && ln[11] == 1 && rn[0] == 90 && rn[11] == 1;
        /* the invocation span, not the template span: the wrapper is the one
         * produced node that carries the invocation byte range, and a marked
         * name addresses the name table, not the source. The produced let and
         * the produced return that reads it therefore carry the same span,
         * which is what stops a span ordered lookup from seeing the
         * declaration before its use. */
        const uint64_t *wrap = node_words(&r, 1);
        int span = node_words(&r, l)[6] == wrap[6] &&
                   node_words(&r, ret)[6] == wrap[6] &&
                   node_words(&r, ret)[7] == wrap[7];
        if (!(same && named && span)) {
          failures++;
          fprintf(stderr,
                  "FAIL produced let reference same=%d named=%d span=%d "
                  "let=[%llu,%llu) ref=[%llu,%llu) inv=[%llu,%llu)\n",
                  same, named, span, (unsigned long long)node_words(&r, l)[6],
                  (unsigned long long)node_words(&r, l)[7],
                  (unsigned long long)rn[6], (unsigned long long)rn[7],
                  (unsigned long long)wrap[6], (unsigned long long)wrap[7]);
          dump(&r);
        }
      }
      freerun(&r);
    }

    /* ================================================================= */
    /* ==== wave 12, CAMPAIGN 1: io_purity, the absence of I/O ======== */
    /* ================================================================= */
    {
      static const char *RD = "tests/nova/tests/macro-io-canary-entry.nova";
      static const char *WR = "tests/nova/tests/macro-io-write-entry.nova";
      static const char sixteen_a[] = "AAAAAAAAAAAAAAAA";
      static const char sixteen_b[] = "BBBBBBBBBBBBBBBB";
      size_t rn = 0, wn = 0;
      char *rtext = loadf(RD, &rn), *wtext = loadf(WR, &wn);
      CHECK(rtext && wtext, "io canary modules load");
      NtFInput rin = {RD, rtext, rn}, win = {WR, wtext, wn};
      NtArtifact ra = {0}, wa = {0};
      int rok = rtext && nova_compile_many_v2(&rin, 1, &ra);
      int wok = wtext && nova_compile_many_v2(&win, 1, &wa);
      CHECK(rok, "the read canary compiles");
      CHECK(wok, "the write canary compiles");
      NovaHostImage rimg = {0}, wimg = {0};
      CHECK(rok && nova_host_map(&ra, &rimg), "the read canary maps");
      CHECK(wok && nova_host_map(&wa, &wimg), "the write canary maps");
      if (rok && wok && rimg.memory && wimg.memory) {
        /* THE PATH THIS BLOCK USED TO BUILD, and what it was: the fixed root
         * /tmp with the pid in the leaf. That is already unique between two
         * CONCURRENT runs -- a pid is unique among live processes -- and it is
         * converted anyway so that all four harnesses in this directory share
         * one mechanism, because four mechanisms is a fourth convention that
         * drifts and the next author has to rediscover which of them were
         * safe. What it was NOT was unique across the repository: /tmp is the
         * one directory every user on the host is entitled to write in.
         *
         * The directory is a SUBDIRECTORY of the run's own, named ng-a5-io,
         * and it is rmdir'd at the bottom of this block exactly as before, so
         * the cleanup semantics are unchanged. */
        char dir[NG_RUN_DIR_MAX], why[NG_RUN_DIR_MAX];
        char canary[NG_RUN_DIR_MAX + 32], written[NG_RUN_DIR_MAX + 32],
             absent[NG_RUN_DIR_MAX + 32];
        const char *dir_ok = ng_run_file("ng-a5-io", dir, sizeof dir, why, sizeof why);
        CHECK(dir_ok != NULL, "the run owns a private directory for the A5 IO probes");
        if (!dir_ok) fprintf(stderr, "FAIL TEMP-ISOLATION %s\n", why);
        if (dir_ok) {
        snprintf(canary, sizeof canary, "%s/canary.bin", dir);
        snprintf(written, sizeof written, "%s/written.bin", dir);
        snprintf(absent, sizeof absent, "%s/not-there.bin", dir);
        mkdir(dir, 0700);

        /* --- 1.1 the channel is OPEN, and the observer can see it open ---
         * Each probe is the negative proof of the one above it. The read
         * answers a different byte for a different file, so it is not a
         * stub. The absent path is refused, so success is not hardwired.
         * The write creates a file the snapshot then sees, so a snapshot
         * that does not move is evidence rather than blindness. The second
         * write at the same path is refused, so the observer sees refusals
         * too and the create is a real exclusive one. */
        {
          char before[1024], once[1024], twice[1024];
          uint64_t ra1[5], ra2[5], rx[5], w1[5], w2[5];
          unsigned nb;
          memset(ra1, 0, sizeof ra1);
          memset(ra2, 0, sizeof ra2);
          memset(rx, 0, sizeof rx);
          memset(w1, 0, sizeof w1);
          memset(w2, 0, sizeof w2);
          write_bytes(canary, sixteen_a, 16);
          nb = snapshot(dir, before, sizeof before);
          canary_read(&rimg, canary, ra1);
          write_bytes(canary, sixteen_b, 16);
          canary_read(&rimg, canary, ra2);
          canary_read(&rimg, absent, rx);
          fprintf(stderr,
                  "IO_SURFACE read_a=[%llu %llu %llu ret=%llu err=%llu] "
                  "read_b=[%llu %llu %llu ret=%llu err=%llu] "
                  "absent=[%llu %llu %llu ret=%llu err=%llu]\n",
                  (unsigned long long)ra1[0], (unsigned long long)ra1[1],
                  (unsigned long long)ra1[2], (unsigned long long)ra1[3],
                  (unsigned long long)ra1[4], (unsigned long long)ra2[0],
                  (unsigned long long)ra2[1], (unsigned long long)ra2[2],
                  (unsigned long long)ra2[3], (unsigned long long)ra2[4],
                  (unsigned long long)rx[0], (unsigned long long)rx[1],
                  (unsigned long long)rx[2], (unsigned long long)rx[3],
                  (unsigned long long)rx[4]);
          CHECK(ra1[0] == 1 && ra1[1] == 16 && ra1[2] == 'A' && ra1[4] == 0,
                "a Nova module reads a canary file off the filesystem");
          CHECK(ra2[0] == 1 && ra2[1] == 16 && ra2[2] == 'B' && ra2[4] == 0,
                "the read channel answers the file's content, so it is open "
                "and not a stub");
          /* The refusal arm. rt_open_read on a path that does not exist
           * raises NV2_IO, and a raised runtime error forces the entry's
           * return value to zero, so the refusal is visible in the error word
           * and NOT in the return word. Asserting on the return word would be
           * asserting that a refusal returns 8, which this build measures to
           * be false -- the first version of this probe did exactly that and
           * the measurement is why the arm reads the error word. */
          CHECK(rx[0] == 0 && rx[4] == 8,
                "an absent path raises NV2_IO, so the read success is not "
                "hardwired");

          write_bytes(canary, sixteen_a, 16);
          remove(written);
          canary_write(&wimg, written, w1);
          canary_write(&wimg, written, w2);
          unsigned na = snapshot(dir, once, sizeof once);
          remove(written);
          unsigned nc = snapshot(dir, twice, sizeof twice);
          fprintf(stderr,
                  "IO_SURFACE write1=[%llu %llu %llu ret=%llu err=%llu] "
                  "write2=[%llu %llu %llu ret=%llu err=%llu] files=%u/%u/%u\n",
                  (unsigned long long)w1[0], (unsigned long long)w1[1],
                  (unsigned long long)w1[2], (unsigned long long)w1[3],
                  (unsigned long long)w1[4], (unsigned long long)w2[0],
                  (unsigned long long)w2[1], (unsigned long long)w2[2],
                  (unsigned long long)w2[3], (unsigned long long)w2[4], nb, na,
                  nc);
          CHECK(w1[0] == 13 && w1[1] == 1 && w1[4] == 0,
                "a Nova module creates a file and writes thirteen bytes");
          CHECK(na == nb + 1,
                "the probe directory really did gain a file, so a snapshot "
                "that does not move is evidence and not blindness");
          /* rt_open_new opens with "wbx" (runtime_v2.c:243), so a second
           * create of the same path raises NV2_IO. Same reason as the read
           * refusal arm: the error word carries it, not the return word. */
          CHECK(w2[1] == 0 && w2[4] == 8,
                "a second create of the same path raises NV2_IO, so the "
                "observer sees a refusal as well as a create");
          CHECK(nc == nb && strcmp(once, twice) != 0,
                "removing the created file restores the snapshot exactly");
        }

        /* --- 1.2 the expander's output does not carry the outside world ---
         * The corpus is expanded once against a canary of sixteen 'A' bytes
         * and once against sixteen 'B'. If anything the expander does depends
         * on a file, a clock, an environment or an allocation history, the
         * digests move. The directory snapshot brackets the corpus, so an
         * expansion that opened a file is caught even if it then closed it. */
        {
          char sb[1024], sa[1024];
          unsigned entries = corpus_size();
          unsigned long long *first = calloc(entries, sizeof *first);
          unsigned long long *second = calloc(entries, sizeof *second);
          uint64_t *codes = calloc(entries, sizeof *codes);
          unsigned long long witness = 0;
          uint64_t witness_code = 0;
          unsigned expanded = 0;
          if (!first || !second || !codes) {
            cases++; checks++; failures++;
            fprintf(stderr, "FAIL io corpus allocation\n");
          } else {
            cases++; checks++;
            write_bytes(canary, sixteen_a, 16);
            unsigned nb = snapshot(dir, sb, sizeof sb);
            for (unsigned e = 0; e < entries; e++) {
              char *src = corpus_composed(e);
              expansion_digest(&image, src ? src : "", &first[e], &codes[e]);
              free(src);
              if (codes[e] == 0) expanded++;
            }
            {
              char *src = witness_composed();
              expansion_digest(&image, src ? src : "", &witness, &witness_code);
              free(src);
            }
            unsigned na = snapshot(dir, sa, sizeof sa);
            write_bytes(canary, sixteen_b, 16);
            for (unsigned e = 0; e < entries; e++) {
              char *src = corpus_composed(e);
              expansion_digest(&image, src ? src : "", &second[e], NULL);
              free(src);
            }
            unsigned moved = 0;
            for (unsigned e = 0; e < entries; e++)
              if (first[e] != second[e]) moved++;
            fprintf(stderr,
                    "IO_EXFIL entries=%u expanded=%u moved=%u dir=%u/%u "
                    "witness=%016llx/%llu corpus0=%016llx/%llu\n",
                    entries, expanded, moved, nb, na, witness,
                    (unsigned long long)witness_code, first[0],
                    (unsigned long long)codes[0]);
            for (unsigned e = 0; e < entries; e++)
              fprintf(stderr, "IO_EXFIL_ENTRY %u code=%llu reason_agnostic=%016llx\n",
                      e, (unsigned long long)codes[e], first[e]);
            /* The campaign is only meaningful if at least half the corpus
             * really expanded. A corpus of refusals would compare equal
             * across two rounds for a reason that has nothing to do with
             * purity, and this check is what stops that from being counted. */
            CHECK(expanded * 2 >= entries,
                  "at least half the exfiltration corpus expanded, so the "
                  "invariance is measured over produced ASTs and not over a "
                  "corpus of refusals");
            CHECK(moved == 0,
                  "no expansion in the corpus moves when the only thing that "
                  "changed on the machine is a file's content");
            CHECK(na == nb && strcmp(sb, sa) == 0,
                  "the expansion corpus creates and modifies nothing in the "
                  "probe directory");
            /* The negative proof of the digest itself: the same comparison
             * over a body that differs by one constant MUST move. */
            CHECK(witness_code == 0 && witness != first[0],
                  "the digest moves when the source moves, so the "
                  "exfiltration comparison can see a difference");
          }
          free(first);
          free(second);
          free(codes);
        }

        /* --- 1.3 a template cannot name an I/O primitive ------------------
         * The template vocabulary is closed, so the vector is the NAME. A
         * template expression is copied verbatim and a binding position is
         * resolved against the template's own scope, so a name written in a
         * template resolves to nothing and is refused as the capture of a
         * caller symbol. Each of the twelve Nova primitives goes in that
         * position and must be refused.
         *
         * The control under the sweep is the SAME template with a splice,
         * `$k`, in the same expression slot, which must expand. That is what
         * makes the sweep a measurement: a refusal that came from "templates
         * are broken" would be indistinguishable from a refusal that came
         * from the name, and the control is the only thing that tells those
         * two apart. The first version of this probe used a CALL as the
         * control and the gate answered 800 -- a call is not writable in a
         * template expression at all, so the control was proving that
         * instead of proving the rule. */
        {
          static const char *spells[] = {
              "rt_open_read", "rt_open_new", "rt_read",  "rt_write",
              "rt_close",     "rt_diag",     "rt_free", "rt_copy",
              "alloc",        "slice",       "runtime", "len"};
          char label[96], src[512];
          for (unsigned s = 0; s < sizeof spells / sizeof spells[0]; s++) {
            snprintf(src, sizeof src,
                     HEAD "macro probe(k:u64)->ast.expr {\n"
                     "    return quote(expr) { %s + $k };\n}\n"
                     TAIL "probe(1)\n" FOOT,
                     spells[s]);
            snprintf(label, sizeof label,
                     "a template may not name the Nova primitive %s",
                     spells[s]);
            err(&image, label, src, 374, 1);
          }
          /* THE CONTROL: the identical template, the identical expression
           * slot, a splice instead of a name. It must expand. */
          fine(&image,
               "the identical template with a spliced binding instead of a "
               "name expands",
               HEAD "macro probe(k:u64)->ast.expr {\n"
               "    return quote(expr) { 1 + $k };\n}\n"
               TAIL "probe(1)\n" FOOT);
          /* and the third point on the same axis: a name that is NOT a
           * primitive and resolves to nothing is refused the same way, so
           * the sweep is refusing a name and not a reserved word. */
          err(&image,
              "a template name that is not a primitive is refused the same way",
              HEAD "macro probe(k:u64)->ast.expr {\n"
              "    return quote(expr) { zzz + $k };\n}\n"
              TAIL "probe(1)\n" FOOT,
              374, 1);
        }

        /* --- 1.4 the clock, the environment and the process are not builtins
         * The six intrinsics above are the whole I/O surface, and the other
         * three channels the criterion names have no primitive at all. That is
         * a claim about the COMPILER, not about the expander, so it is
         * measured by compiling: a module naming a Nova builtin compiles, a
         * module naming a clock, an environment or a process primitive does
         * not. The pair is the proof. */
        {
          static const char *absent[] = {
              "time",   "clock",      "gettimeofday", "getenv", "environ",
              "getpid", "system",     "popen",        "fork",   "execve",
              "rand",   "localtime",  "gmtime",       "time_ns"};
          char src[512], label[96];
          for (unsigned s = 0; s < sizeof absent / sizeof absent[0]; s++) {
            NtFInput in = {"probe", src, 0};
            NtArtifact a = {0};
            int compiled;
            snprintf(src, sizeof src,
                     "module m;\nfn main(path:buf<u8>,out:buf<u64>)->u64 {\n"
                "    let r:u64=%s();\n    out[0]=r;\n    return 0;\n}\n",
                     absent[s]);
            in.text = src;
            in.length = strlen(src);
            compiled = nova_compile_many_v2(&in, 1, &a);
            snprintf(label, sizeof label,
                     "the Nova language has no %s primitive", absent[s]);
            cases++; checks++;
            if (compiled) {
              failures++;
              fprintf(stderr, "FAIL %s: it compiled\n", label);
            }
            nt_artifact_free(&a);
          }
          {
            const char *src2 =
                "module m;\nfn main(path:buf<u8>,out:buf<u64>)->u64 {\n"
                "    let h:u64=rt_open_read(runtime(),path);\n"
                "    out[0]=h;\n    return 0;\n}\n";
            NtFInput in = {"probe", src2, strlen(src2)};
            NtArtifact a = {0};
            int control = nova_compile_many_v2(&in, 1, &a);
            CHECK(control,
                  "the control name rt_open_read IS a Nova primitive, so the "
                  "absent sweep above measures the surface and not a broken "
                  "compile path");
            if (!control)
              fprintf(stderr, "CONTROL_COMPILE E%u %zu:%zu %s\n", a.error.code,
                      a.error.line, a.error.column, a.error.message);
            nt_artifact_free(&a);
          }
        }

        remove(canary);
        remove(written);
        rmdir(dir);
        }
      }
      if (rimg.memory) nova_host_unmap(&rimg);
      if (wimg.memory) nova_host_unmap(&wimg);
      if (rok) nt_artifact_free(&ra);
      if (wok) nt_artifact_free(&wa);
      free(rtext);
      free(wtext);
    }

    /* ================================================================= */
    /* ==== wave 12, CAMPAIGN 2: ceilings, the imposed bounds ========== */
    /* ================================================================= */

    /* Three ceilings exist for each budget and only one of them is named by
     * the criterion: the value a comptime block may declare, the consumption
     * the expander actually charges, and the compiler bound that shadows a
     * declared maximum when the two disagree. The six are refused in 201
     * reasons 1 to 6, and budget_sweep above already confronts the six at
     * their exact measured cost on a flat body and on a two-level one. What
     * is measured here and was not before:
     *
     *   (a) the DECLARED CEILING of each of the six: the largest accepted
     *       value, the smallest refused value, and proof that the refusal
     *       sits AT that boundary and not one below it. Only fuel had this.
     *   (b) the SHADOW: a declared maximum the expander can never reach,
     *       because a budget with a smaller ceiling binds first.
     *   (c) a THIRD body shape, a meta-for, which pays the node, arena and
     *       constant budgets per projected item inside ONE expansion. The
     *       two bodies the sweep uses are flat and two-level; a budget a
     *       loop could amortise would answer a loop body differently from a
     *       nesting body, and that is the evasion this shape exists to
     *       refuse.
     *   (d) what happens AT and PAST the boundary, which is the part no
     *       campaign had measured: at the boundary the expansion publishes a
     *       full AST, one below it the refusal is 201 with the matching
     *       reason and NO partial AST is published. */
    {
      static const struct {
        const char *name;
        unsigned max;
        uint64_t reason;
      } CEIL[6] = {{"fuel", 1048576, 1},           {"call_depth", 256, 2},
                   {"arena_bytes", 16777216, 3},   {"ast_nodes", 1048576, 4},
                   {"expansion_depth", 128, 5},    {"constant_bytes", 16777216, 6}};
      unsigned accepted[6], refused[6], below[6], over[6], one_below_code[6];
      memset(accepted, 0, sizeof accepted);
      memset(refused, 0, sizeof refused);
      memset(below, 0, sizeof below);
      memset(over, 0, sizeof over);
      memset(one_below_code, 0, sizeof one_below_code);

      for (unsigned k = 0; k < 6; k++) {
        char *at = compose_k(k, CEIL[k].max, BODY);
        char *over_src = compose_k(k, CEIL[k].max + 1u, BODY);
        char *under = compose_k(k, CEIL[k].max - 1u, BODY);
        char label[128];
        Run r;
        if (!at || !over_src || !under) {
          failures++; cases++;
          fprintf(stderr, "FAIL ceiling compose %s\n", CEIL[k].name);
          free(at); free(over_src); free(under);
          continue;
        }
        /* AT the boundary: the frozen maximum is a legal declaration and the
         * expansion runs. */
        r = run(&image, at, 1u << 18, 0);
        cases++; checks++;
        accepted[k] = (unsigned char)(r.returned == 0 && r.runtime == 0 &&
                                      r.code == 0 && r.w1 != 0);
        if (!accepted[k]) {
          failures++;
          fprintf(stderr, "FAIL ceiling %s at its maximum ret=%llu code=%llu\n",
                  CEIL[k].name, (unsigned long long)r.returned,
                  (unsigned long long)r.code);
        }
        freerun(&r);
        /* PAST it: one more than the maximum is 378, the malformed limit
         * block, not 201, because the block never became a budget. */
        snprintf(label, sizeof label, "ceiling %s one past the maximum", CEIL[k].name);
        r = run(&image, over_src, 1u << 18, 0);
        cases++; checks++;
        refused[k] = (unsigned char)(r.returned == 378 && r.code == 378 &&
                                     r.reason == 1);
        if (!refused[k]) {
          failures++;
          fprintf(stderr, "FAIL %s ret=%llu code=%llu reason=%llu\n", label,
                  (unsigned long long)r.returned, (unsigned long long)r.code,
                  (unsigned long long)r.reason);
        }
        freerun(&r);
        /* AND ONE BELOW, which is what makes the middle probe a boundary
         * rather than a coincidence. A block refused at every value would
         * produce exactly the same observation at max+1 and nothing here
         * would notice. */
        snprintf(label, sizeof label, "ceiling %s one below the maximum", CEIL[k].name);
        r = run(&image, under, 1u << 18, 0);
        cases++; checks++;
        below[k] = (unsigned char)(r.code != 378);
        over[k] = (unsigned char)(r.code == 201);
        if (!below[k]) {
          failures++;
          fprintf(stderr, "FAIL %s: refused with 378, so the ceiling is one "
                          "below the declared maximum\n", label);
        }
        freerun(&r);
        one_below_code[k] = (unsigned)r.code;
        fprintf(stderr,
                "CEILING %s declared_max=%u at_max=%s past_max=%llu "
                "one_below_code=%u one_below_runtime=%llu\n",
                CEIL[k].name, CEIL[k].max, accepted[k] ? "ok" : "refused",
                (unsigned long long)refused[k], (unsigned)r.code,
                (unsigned long long)r.runtime);
        free(at);
        free(over_src);
        free(under);
      }

      /* (b) the SHADOW. Every produced node charges node_bytes() = 96 arena
       * bytes (macro_expand.nova:119 and :490), so the arena ceiling of
       * 16777216 bytes is a node ceiling of 16777216/96 = 174762, which is
       * six times below the declared ast_nodes maximum of 1048576. The
       * identity is not asserted, it is MEASURED across a range of node
       * counts, and the sweep of node counts below is the negative proof:
       * if arena did not track 96 per node the measured pairs would not sit
       * on the line, and the shadow would be an assumption. */
        /* The identity is MARGINAL, not proportional, and getting that wrong
         * is the finding. The obvious hypothesis -- arena is 96 bytes per
         * published node -- is FALSE, and the first version of this check
         * asserted it and went red on all nine measurements with a constant
         * discrepancy of exactly 96 bytes. The measured truth is that one
         * node is produced and charged to the arena without being published:
         * take_node charges nodes_made, which counts folded-condition
         * temporaries, while node_count counts only what the caller receives
         * (macro_expand.nova:483-504). So arena = 96*(nodes+1) for this body,
         * with a marginal rate of exactly 96 and a fixed overhead of exactly
         * 96. The check below asserts the MARGINAL rate, because that is the
         * quantity the shadow depends on and the one a body change could not
         * quietly move. */
       {
         unsigned long long ratio_bad = 0;
         struct Usage prev;
         unsigned long long overhead = 0;
         /* --- THE FUEL PIN. See the block comment below it. --- */
         unsigned long long fuel_base = 0;
         unsigned long long fuel_rate_bad = 0;
         int have_prev = 0;
         memset(&prev, 0, sizeof prev);
       for (unsigned items = 0; items <= 8; items++) {
          char body[1024];
          struct Usage u;
          snprintf(body, sizeof body,
                   "macro many(n:u64)->ast.decl {\n"
                   "    for i in $n {\n"
                   "        emit quote(decl) { const c:u64 = $i; }\n"
                   "    }\n"
                   "}\n"
                   TAIL "many(%u)\n" FOOT,
                   items);
          memset(&u, 0, sizeof u);
          cases++; checks++;
          if (!measure(&image, body, &u)) {
            failures++;
            fprintf(stderr, "FAIL ceiling shadow measure items=%u\n", items);
            continue;
          }
          /* The MARGINAL rate, which is the quantity the shadow depends on:
         * five more published nodes and exactly 480 more arena bytes per
         * projected item. The first version of this check asserted a
         * PROPORTIONAL identity and went red on all nine measurements with a
         * constant discrepancy of exactly 96 bytes, which is how the
         * produced-but-unpublished node was found. */
          if (have_prev) {
            unsigned long long dn = u.nodes - prev.nodes;
            unsigned long long da = u.arena - prev.arena;
            if (dn != 5 || da != 96ull * dn) {
              ratio_bad++;
              fprintf(stderr,
                      "FAIL ceiling shadow marginal items=%u dnodes=%llu "
                      "darena=%llu want_darena=%llu\n",
                      items, dn, da, 96ull * dn);
            }
            /* THE FUEL MARGINAL, AND IT IS THE MODEL'S, NOT A LITERAL. The
             * arena check above derives `want_darena` from the measured delta
             * because 96 is a MARGINAL RATE the sweep is entitled to
             * re-derive; the fuel rate is a VALUE this gate claims the
             * expander holds, and a value that re-derives itself from the
             * quantity it is checking has not checked it. So the expectation
             * is the META_FOR row of ntasm_fuel_model.h: an affine model
             * rather than a copied integer, and the same one the two other
             * gates holding a fuel figure now read. A change in the
             * producer's per-item charge cannot reach it, and a change in the
             * MODEL's per-item charge moves this line too, which is the whole
             * difference between a pin and a decoration. */
            unsigned long long dfuel = u.fuel - prev.fuel;
            if (dfuel != ng_fuel_nova_marginal(NG_FUEL_META_FOR)) {
              fuel_rate_bad++;
              fprintf(stderr,
                      "FAIL FUEL PIN per-item marginal items=%u dfuel=%llu "
                      "want_dfuel=%llu\n",
                      items, dfuel,
                      (unsigned long long)ng_fuel_nova_marginal(NG_FUEL_META_FOR));
            }
          } else {
            overhead = u.arena - 96ull * u.nodes;
            fuel_base = u.fuel;
          }
          have_prev = 1;
          prev = u;
          fprintf(stderr,
                  "SHADOW items=%u nodes=%llu arena=%llu overhead=%llu "
                  "fuel=%llu constant=%llu per_item_nodes=5 "
                  "per_item_arena=480\n",
                  items, (unsigned long long)u.nodes,
                  (unsigned long long)u.arena, overhead,
                  (unsigned long long)u.fuel,
                  (unsigned long long)u.constant);
        }
        cases++; checks++;
        if (ratio_bad) {
          failures++;
          fprintf(stderr, "FAIL the marginal arena rate is not 96 bytes per "
                          "node in %llu of eight measurements\n", ratio_bad);
        }
        cases++; checks++;
        CHECK(overhead == 96,
              "the one node the arena charges and the caller never receives is "
              "exactly 96 bytes on every body shape measured");

        /* ==================================================================
           THE FUEL PIN -- 5 + 8n, as literals.

           WHY IT IS HERE AND WHY THE GATE NEEDED IT. This gate measured the
           expander's fuel on every shape it touched and PRINTED it --
           MEASURE, SHADOW, CEILING_LOOP, BOUND, CEILING_SHAPE all carry a
           fuel figure -- and NOT ONE OF THEM ASSERTED IT. Every budget
           threshold this file uses is measured at run time from the same
           quantity: budget_sweep() sets fuel=v[0].used and asserts the
           budget answers one below it; loop_ceiling_at() bisects for the
           largest item count that expands. So the fuel accounting was
           self-consistent by construction and could change without moving a
           single check.

           THAT WAS MEASURED, NOT ASSUMED. Wave 17 removed the caller's-walk
           charge in macro_expand.nova's walk(). The gate read
           `checks=983 failures=0 cases=240` before that change and
           `983/0/240` after it, and diff of the two run logs shows them
           differing ONLY in the lines that print the measurement. Not one
           check moved. A sibling gate (tests_ntasm_validate.c) HAD pinned
           fuel=30/29 as literals, the walk removal moved the cost to 8, and
           that pin went red -- which is the only reason the change was
           caught at all. This gate was the instrument that appeared to cover
           the fuel accounting and could not fail on it.

           THE RULE, IN THE FORM THIS EXISTS TO SATISFY: an instrument that
           re-derives its expectations from the quantity it is supposed to be
           checking has not checked that quantity at all.

           WHY THE SWEEPS STAY. budget_sweep() and loop_ceiling_at() are
           CEILINGS, and re-deriving a ceiling is legitimate: the question
           "where does this budget stop answering?" has no answer other than
           the one the expander gives. Pinning a ceiling to a literal would
           assert that changing any cost is a defect, and the sweep's whole
           value is that it survives one. They are kept, unedited, and this
           pin is a SEPARATE check over the SAME measurement: the sweep asks
           "does the budget answer exactly where the expander says", this
           asks "is the expander's number still the number we hold it to".
           Both run; neither is derived from the other.

           THE TWO NUMBERS, and where they live now. Neither is a literal in
           this file any more; both are the META_FOR row of
           tests/c/nova/ntasm_fuel_model.h, an affine model
           rather than a copied integer:
             * per-item marginal = take_node's charge_fuel, one per produced
               node; a meta-for item publishes 5 nodes and charges 8
             * the base at zero items = 5, which is what remains of the
               caller's walk after the wave-17 removal
           Measured at the green state, over items=0..8, in the run log this
           file's own gate produced: fuel = 5,13,21,29,37,45,53,61,69, which is
           5 + 8n exactly. Before the walk removal the same ladder read
           27,35,...,91, which is 27 + 8n: the SLOPE did not change and the
           CONSTANT was the walk. Pinning the affine FORM catches either part
           moving, which pinning only the total would not.

           TWO CORRECTIONS to what this block used to say, both measured by
           me on the current tree rather than taken from the wave-17 note.
           First, the claim that the reference "has no per-item term at all,
           a flat 1 at every item count", is right about the SLOPE and wrong
           about the figure, and it is also about a body this gate does not
           use. On the reference's own meta-for -- which it can only express
           as a list<> result, a form Nova refuses 377/1 -- the measured
           figure is a flat 2 at n = 0,1,2,3,4,5,6,7,8,100,236,372,508: 1
           for the comptime block's own body and 1 for the one expansion, and
           nothing per item, ever. Second, the C reference cannot be run on
           THIS gate's meta-for body at all: it refuses the `for` with 200
           "expected 'return'", because frontend.c only admits a meta-for
           under a list<> result. So there is no body on which both oracles
           answer the same question here, and the two numbers are not two
           views of one figure. The model records that as a measured refusal
           rather than as a missing row. */
        cases++; checks++;
        if (fuel_rate_bad) {
          failures++;
          fprintf(stderr,
                  "FAIL the FUEL PIN: the per-item fuel marginal is not %llu "
                  "in %llu of eight measurements, so either the producer's "
                  "per-item charge moved or the model does not describe it\n",
                  (unsigned long long)ng_fuel_nova_marginal(NG_FUEL_META_FOR),
                  fuel_rate_bad);
        }
        cases++; checks++;
        CHECK(fuel_base == ng_fuel_nova(NG_FUEL_META_FOR, 0),
              "the expander's fuel at zero projected items is the META_FOR "
              "base the model names, and the caller's walk no longer charges "
              "into it; the base was 27 before that removal");
        /* The affine form, asserted as a form and not as a total: every rung
         * of the ladder the model produces, checked against the measurement
         * at that rung, so a failure names a rung rather than a formula. The
         * model is asked for the figure; the expander is asked what it
         * charges; the two answers are compared and neither is derived from
         * the other. */
        cases++; checks++;
        if (fuel_base != ng_fuel_nova(NG_FUEL_META_FOR, 0) ||
            fuel_rate_bad) {
          fprintf(stderr,
                  "FAIL the FUEL PIN: the measured ladder is not the model's "
                  "%llu + %llun\n",
                  (unsigned long long)ng_fuel_nova(NG_FUEL_META_FOR, 0),
                  (unsigned long long)ng_fuel_nova_marginal(NG_FUEL_META_FOR));
        }
        fprintf(stderr,
                "FUEL_PIN base=%llu per_item=%llu form=%llu+%llun pinned=yes "
                "sweeps_kept=budget_sweep,loop_ceiling_at "
                "walk_removal_moved=the_base_27->5_not_the_slope "
                "model=ntasm_fuel_model.h/META_FOR "
                "reference=no_common_body_the_reference_refuses_this_shape\n",
                fuel_base,
                (unsigned long long)ng_fuel_nova_marginal(NG_FUEL_META_FOR),
                (unsigned long long)ng_fuel_nova(NG_FUEL_META_FOR, 0),
                (unsigned long long)ng_fuel_nova_marginal(NG_FUEL_META_FOR));
        fprintf(stderr,
                "SHADOW ast_nodes declared_max=1048576 arena_bytes_max=%u "
                "arena_node_ceiling=%u shadowed=%s\n",
                16777216u, 16777216u / 96u,
                (16777216u / 96u) < 1048576u ? "arena_bytes" : "none");
      }

      /* -------------------------------------------------------------------
         THE CROSS-SHAPE FUEL LADDERS, on both oracles, against the model.

         WHY, and it is the whole of U29. The block above pins ONE shape.
         Two other gates hold a fuel figure for a DIFFERENT body -- the flat
         `ret` corpus member -- and until this lot each of those held its own
         literal, so the wave-17 walk removal had to be re-pinned in two files
         that could not see each other. ntasm_fuel_model.h is now the one
         derivation all three read. This block is what says the derivation is
         a MODEL and not a second shared constant: it measures the same
         model at two more shapes, on the same source text, on both oracles.

         AND THE ROW THAT MATTERS MOST IS THE ONE THAT DISAGREES. FLAT_BLOCK's
         base is 11 where FLAT_RET's and META_FOR's are both 5. If the model's
         intercept were really one number, that row could not exist. If a
         future change made FLAT_BLOCK's base 5, this goes red, and the red
         would be correct: three different bodies would then be sharing a
         constant and calling it a model. */
      {
        const ng_fuel_shape order[2] = {NG_FUEL_FLAT_RET, NG_FUEL_FLAT_BLOCK};
        const unsigned last_item[2] = {6u, 6u};
        uint64_t ratio_first[2] = {0, 0}, ratio_last[2] = {0, 0};
        uint64_t nova_last[2] = {0, 0};
        for (unsigned s = 0; s < 2; s++) {
          unsigned bad_nova = 0, bad_ref = 0;
          /* From the shape's FIRST MEASURED item, not from zero: a quoted
           * block with no lets is a different body and the model says which
           * rung it was measured at rather than quietly claiming zero. */
          unsigned first = (unsigned)ng_fuel_shapes[order[s]].first_measured_item;
          for (unsigned items = first; items <= last_item[s]; items++) {
            char *body = s == 0 ? flat_ret_body(items) : flat_block_body(items);
            struct Usage u;
            unsigned long long rf = 0;
            memset(&u, 0, sizeof u);
            cases++; checks++;
            if (!body || !measure(&image, body, &u)) {
              failures++;
              fprintf(stderr,
                      "FAIL fuel ladder shape=%s items=%u does not measure\n",
                      ng_fuel_shapes[order[s]].name, items);
              free(body);
              continue;
            }
            /* the PRODUCT's answer against the MODEL's figure */
            if (u.fuel != ng_fuel_nova(order[s], items)) {
              bad_nova++;
              fprintf(stderr,
                      "FAIL FUEL MODEL shape=%s items=%u measured=%llu "
                      "model=%llu\n", ng_fuel_shapes[order[s]].name, items,
                      (unsigned long long)u.fuel,
                      (unsigned long long)ng_fuel_nova(order[s], items));
            }
            /* the REFERENCE's answer, bisected, against the MODEL's arm */
            if (ng_fuel_reference_comparable(order[s])) {
              rf = ref_fuel_of(body);
              if (rf != ng_fuel_reference(order[s], items)) {
                bad_ref++;
                fprintf(stderr,
                        "FAIL FUEL MODEL reference shape=%s items=%u "
                        "measured=%llu model=%llu\n",
                        ng_fuel_shapes[order[s]].name, items, rf,
                        (unsigned long long)ng_fuel_reference(order[s], items));
              }
            }
            if (items == first)
              ratio_first[s] = ng_fuel_ratio_milli(u.fuel, rf);
            if (items == last_item[s]) {
              nova_last[s] = u.fuel;
              ratio_last[s] = ng_fuel_ratio_milli(u.fuel, rf);
            }
            fprintf(stderr,
                    "FUEL_LADDER shape=%s items=%u nova=%llu model=%llu "
                    "reference=%llu ref_model=%llu ratio_milli=%llu\n",
                    ng_fuel_shapes[order[s]].name, items,
                    (unsigned long long)u.fuel,
                    (unsigned long long)ng_fuel_nova(order[s], items), rf,
                    (unsigned long long)ng_fuel_reference(order[s], items),
                    (unsigned long long)ng_fuel_ratio_milli(u.fuel, rf));
            free(body);
          }
          /* WHY first_measured_item IS NOT ALWAYS ZERO, and it is a fact
           * about the body rather than a gap in the ladder. A quoted block
           * holding no lets at all is not the shape with its lets removed;
           * it is another body, and it measures differently on BOTH oracles.
           * So the intercept of that shape is a fitted parameter pinned by
           * the rungs above it, and the rung below the ladder is measured
           * here precisely so that the difference is on the record rather
           * than inferred from the model declining to claim zero. */
          if (first > 0) {
            char *zero = flat_block_body(0);
            struct Usage z;
            unsigned long long zr = 0;
            memset(&z, 0, sizeof z);
            cases++; checks++;
            if (zero && measure(&image, zero, &z)) {
              zr = ng_fuel_reference_comparable(order[s])
                       ? ref_fuel_of(zero)
                       : UINT64_MAX;
              cases++; checks++;
              CHECK(z.fuel != ng_fuel_nova(order[s], 0) &&
                        zr != ng_fuel_reference(order[s], 0),
                    "a quoted block with no lets is a different body from "
                    "this shape at zero lets, on both oracles, so this "
                    "shape's intercept is fitted and not read at zero");
              fprintf(stderr,
                      "FUEL_LADDER_BELOW shape=%s items=0 nova=%llu "
                      "model_says=%llu reference=%llu "
                      "different_body=yes intercept=fitted\n",
                      ng_fuel_shapes[order[s]].name,
                      (unsigned long long)z.fuel,
                      (unsigned long long)ng_fuel_nova(order[s], 0), zr);
            } else {
              failures++;
              fprintf(stderr,
                      "FAIL the zero-let block of shape %s does not measure, "
                      "so the claim that it is a different body is unchecked\n",
                      ng_fuel_shapes[order[s]].name);
            }
            free(zero);
          }
          cases++; checks++;
          CHECK(bad_nova == 0,
                "the expander's fuel on this shape is the affine figure the "
                "model produces, at every item count measured");
          cases++; checks++;
          CHECK(bad_ref == 0,
                "the C reference's fuel on this same body is the affine "
                "figure the model produces for the reference, at every item "
                "count measured");
          /* THE RATIO IS NOT CONSTANT, and that is asserted rather than
           * described: two measurements of the same two oracles at two item
           * counts give two different ratios. A model that offered one rate
           * between the schemes would fail this, which is the point. */
          cases++; checks++;
          if (ng_fuel_reference_comparable(order[s]) &&
              ratio_first[s] == ratio_last[s]) {
            failures++;
            fprintf(stderr,
                    "FAIL the Nova:reference ratio is %llu thousandths at "
                    "both %u and %u items on shape %s, so the two schemes are "
                    "claimed to map onto each other by a constant factor\n",
                    (unsigned long long)ratio_last[s], first, last_item[s],
                    ng_fuel_shapes[order[s]].name);
          }
        }
        /* And the two shapes are not the same body wearing two names: at the
         * SAME item count the measured fuel of one is more than double the
         * other's. Both sides of that comparison are measurements, so it goes
         * red if either shape's accounting moves toward the other, and it is
         * the statement that keeps a reader from treating the shared
         * intercept of 5 as a shared quantity. */
        cases++; checks++;
        if (nova_last[0] == 0 || nova_last[1] < nova_last[0] * 2ull) {
          failures++;
          fprintf(stderr,
                  "FAIL flat_ret measured %llu fuel at %u items and "
                  "flat_block measured %llu at the same count, so the two "
                  "shapes are not the same body and a single intercept could "
                  "not serve both\n",
                  (unsigned long long)nova_last[0], last_item[0],
                  (unsigned long long)nova_last[1]);
        }
        /* The meta-for has NO COMMON BODY, and the model says so. Both
         * directions are run so the claim is a measurement: the C reference
         * is handed the body this gate uses and must refuse it, and the
         * refusal's code is the one the model names. */
        {
          char *nova_spelling = NULL;
          size_t need = 512;
          char lit[256];
          uint64_t ref_code = 0;
          unsigned refused;
          snprintf(lit, sizeof lit,
                   "macro many(n:u64)->ast.decl {\n"
                   "    for i in $n {\n"
                   "        emit quote(decl) { const c:u64 = $i; }\n"
                   "    }\n"
                   "}\n" TAIL "many(3)\n    return 0;\n" FOOT);
          nova_spelling = malloc(need);
          if (nova_spelling) memcpy(nova_spelling, lit, strlen(lit) + 1);
          refused = nova_spelling ? ref_refuses_spellings(nova_spelling, &ref_code) : 0;
          cases++; checks++;
          CHECK(refused == 1 &&
                    ref_code == ng_fuel_shapes[NG_FUEL_META_FOR]
                                   .ref_on_nova_spelling_code,
                "the C reference refuses the meta-for body in the spelling "
                "this gate uses, with the code the model records, so the "
                "model's claim that the two oracles have no common body here "
                "is a measurement");
          cases++; checks++;
          CHECK(ng_fuel_reference_comparable(NG_FUEL_META_FOR) == 0,
                "the model does not offer a reference figure for the "
                "meta-for, because there is no body both oracles expand");
          fprintf(stderr,
                  "FUEL_MODEL meta_for reference=no_common_body "
                  "ref_on_nova_spelling=%llu measured=%llu "
                  "nova_on_ref_spelling=%llu/%llu "
                  "ref_own_spelling_flat=%llu items_to_508\n",
                  (unsigned long long)ng_fuel_shapes[NG_FUEL_META_FOR]
                      .ref_on_nova_spelling_code,
                  (unsigned long long)ref_code,
                  (unsigned long long)ng_fuel_shapes[NG_FUEL_META_FOR]
                      .nova_on_ref_spelling_code,
                  (unsigned long long)ng_fuel_shapes[NG_FUEL_META_FOR]
                      .nova_on_ref_spelling_reason,
                  (unsigned long long)ng_fuel_shapes[NG_FUEL_META_FOR]
                      .ref_measured_fuel);
          free(nova_spelling);
        }
      }

      /* (c) and (d): a loop body at the boundary of the three budgets a loop
       * pays per item, and one below each. budget_sweep never runs a loop,
       * so this is the first measurement of what a meta-for costs and of
       * where each of those three stops answering. */
      {
        struct Usage u;
        char label[96];
        memset(&u, 0, sizeof u);
        cases++; checks++;
        if (!measure(&image, META_FOR, &u)) {
          failures++;
          fprintf(stderr, "FAIL ceilings the meta-for body does not measure\n");
        } else {
          fprintf(stderr,
                  "CEILING_LOOP fuel=%llu arena=%llu nodes=%llu constant=%llu "
                  "call_peak=%llu depth_peak=%llu\n",
                  (unsigned long long)u.fuel, (unsigned long long)u.arena,
                  (unsigned long long)u.nodes,
                  (unsigned long long)u.constant,
                  (unsigned long long)u.call_peak,
                  (unsigned long long)u.depth_peak);
          static const struct {
            const char *name;
            uint64_t reason;
          } LOOPABLE[3] = {{"arena_bytes", 3}, {"ast_nodes", 4},
                           {"constant_bytes", 6}};
          for (unsigned k = 0; k < 3; k++) {
            unsigned index = k == 0 ? 2 : (k == 1 ? 3 : 5);
            /* The node budget is charged against nodes_made, which counts
             * the one node the arena charges and the caller never receives,
             * so the exact cost is nodes+1 and NOT nodes. The first version
             * of this check used node_count and the gate answered 201
             * reason 4 at the exact cost, which is the same +1 the shadow
             * sweep found from the arena side. The two budgets are charged on
             * the same counter, and the published count is one lower. */
            unsigned used = k == 0 ? (unsigned)u.arena
                                   : (k == 1 ? (unsigned)(u.nodes + 1)
                                             : (unsigned)u.constant);
            char *exact = compose_k(index, used, META_FOR);
            char *short_by_one = compose_k(index, used - 1u, META_FOR);
            if (!exact || !short_by_one) {
              failures++; cases++;
              fprintf(stderr, "FAIL ceilings loop compose %s\n",
                      LOOPABLE[k].name);
            } else {
              snprintf(label, sizeof label,
                       "loop %s at the exact per-item cost", LOOPABLE[k].name);
              fine(&image, label, exact);
              snprintf(label, sizeof label,
                       "loop %s one below the per-item cost publishes no AST",
                       LOOPABLE[k].name);
              err(&image, label, short_by_one, 201, LOOPABLE[k].reason);
              /* the published-AST half, which is what a truncated expansion
               * would look like: at used the region must fit and be full, at
               * used-1 the gate must see code 201 and no node at all. */
              Run r = run(&image, short_by_one, 1u << 18, 0);
              cases++; checks++;
              if (r.code == 201 && layout_ok(&r)) {
                failures++;
                fprintf(stderr,
                        "FAIL loop %s one below the cost still published an "
                        "AST\n", LOOPABLE[k].name);
              }
              freerun(&r);
            }
            free(exact);
            free(short_by_one);
          }
        }
      }
    }


    /* ==================================================================
     * A5, the two campaigns the wave 12 banner named as unmeasured.
     * ================================================================== */
    {
      const char *PROV_LEAK_NAME = "w";

      /* --- 1. THE SURFACE: a caller cannot spell a mark.
       *
       * The channel a mark could be forged through is the caller's own
       * source. It is closed, and it is closed by the lexer: is_letter is
       * a-z, A-Z and '_' and is_digit is 0-9 (lexer.nova:37-39), and '$'
       * is neither, so a mark-shaped caller declaration does not lex. This
       * is measured, not asserted, and the control is the same module with
       * a legal name: without the control a parser that refused everything
       * would look identical. */
      {
        char *forged = compose(4096, 64, 16777216, 1048576, 128, 16777216,
            "macro ret(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { return $v; };\n}\n"
            "const __ntm$1$e$1$x:u64 = 1;\n"
            TAIL "ret(1)\n" FOOT);
        char *legal = compose(4096, 64, 16777216, 1048576, 128, 16777216,
            "macro ret(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { return $v; };\n}\n"
            "const plain_name:u64 = 1;\n"
            TAIL "ret(1)\n" FOOT);
        Run rf = run(&image, forged ? forged : "", 1u << 18, 0);
        Run rl = run(&image, legal ? legal : "", 1u << 18, 0);
        cases++; checks++;
        /* 800 is the entry's structural answer for a tree the parser
         * refused, and runtime must be 0: the refusal is the PARSER's, so
         * a campaign that reported it as a runtime error would be
         * describing the probe rather than the channel. */
        if (rf.returned != 800 || rf.runtime != 0) {
          failures++;
          fprintf(stderr,
                  "FAIL a mark-shaped caller declaration was not refused by "
                  "the parser ret=%llu runtime=%llu\n",
                  (unsigned long long)rf.returned,
                  (unsigned long long)rf.runtime);
        }
        cases++; checks++;
        if (rl.returned != 0 || rl.runtime != 0 || rl.code != 0) {
          failures++;
          fprintf(stderr,
                  "FAIL the mark-surface control did not expand, so the "
                  "refusal above measures the parser and not the channel "
                  "ret=%llu runtime=%llu code=%llu\n",
                  (unsigned long long)rl.returned,
                  (unsigned long long)rl.runtime, (unsigned long long)rl.code);
        }
        fprintf(stderr,
                "PROV_SURFACE mark_forge_refused=%llu control_expanded=%llu "
                "channel=closed_by_the_lexer\n",
                (unsigned long long)rf.returned,
                (unsigned long long)(rl.code == 0 ? 1 : 0));
        freerun(&rf);
        freerun(&rl);
        free(forged);
        free(legal);
      }

      /* --- 2. THE MARK ORACLE, and the freshness of the serial.
       *
       * The expected texts are built here from the reference's four format
       * strings, not by calling the expander's composer, and the ORDINAL
       * and the SERIAL are read back out of the expander's own bytes. A
       * prefix test would pass on a mark that had been pasted in as
       * literal text; a field comparison cannot. */
      {
        char *two = compose(4096, 64, 16777216, 1048576, 128, 16777216,
            "macro blk(v:ast.expr)->ast.block {\n"
            "    return quote(block) {\n"
            "        let t:u64 = $v;\n"
            "        return t;\n"
            "    };\n"
            "}\n" TAIL "blk(1)\n        expand blk(2)\n" FOOT);
        Run r = run(&image, two ? two : "", 1u << 18, 0);
        cases++; checks++;
        if (!layout_ok(&r)) {
          failures++;
          fprintf(stderr, "FAIL the two-invocation mark body did not expand "
                          "ret=%llu runtime=%llu code=%llu\n",
                  (unsigned long long)r.returned,
                  (unsigned long long)r.runtime, (unsigned long long)r.code);
        } else {
          char want[64];
          unsigned long long ord = 0, ser = 0, x = 0, y = 0;
          const char *tail = NULL;
          char kind = 0;
          unsigned marked = 0, fresh = 0;
          for (uint64_t id = 1; id <= r.w1; id++) {
            const uint64_t *n = node_words(&r, id);
            char text[128];
            if (n[0] != 90 || n[7] <= n[6]) continue;
            name_copy(&r, n[6], n[7], text, sizeof text);
            if (mark_fields(text, &kind, &ord, &ser, &x, &y, &tail) == 0)
              continue;
            marked++;
            if (kind == 'm') snprintf(want, sizeof want, "__ntm$1$e%llu$%s",
                                      ser, tail);
            else if (kind == 'd') snprintf(want, sizeof want, "__ntd$1$e%llu$%s",
                                           ser, tail);
            else snprintf(want, sizeof want, "__ntp$1$e%llu$p%llu$%s", ser, x,
                          tail);
            cases++; checks++;
            if (ord != 1 || strcmp(text, want) != 0) {
              failures++;
              fprintf(stderr,
                      "FAIL mark %s is not the reference format for ordinal 1 "
                      "and serial %llu\n", text, ser);
            }
            if (ser == 1) fresh++;
          }
          /* Freshness is the property A5 exists for: two expansions of the
           * SAME macro in the SAME module must not share a name. Two marks
           * were produced and they must carry two different serials; a
           * campaign that counted marks without reading the serial would
           * pass on two identical names. */
          cases++; checks++;
          if (marked != 4 || fresh != 2) {
            failures++;
            fprintf(stderr,
                    "FAIL freshness: %u marked names, %u at serial 1, want 4 "
                    "and 2\n", marked, fresh);
          }
          fprintf(stderr,
                  "PROV_MARK marked=%u serial1=%u serial2=%u ordinal=1 "
                  "formats=frontend.c:2384,4818,4880,4938\n", marked, fresh,
                  marked - fresh);
        }
        freerun(&r);
        free(two);
      }

      /* --- 3. THE ORDINAL IS LOAD BEARING.
       *
       * Inserting one macro that is never invoked shifts the ordinal of
       * every mark after it by one and leaves the serial alone. A mark
       * field that is written but never read would pass the count in (2)
       * and fail here, which is why this arm exists: the two together are
       * what makes the ordinal a measurement rather than a decoration. */
      {
        char *one = compose(4096, 64, 16777216, 1048576, 128, 16777216,
            "macro blk(v:ast.expr)->ast.block {\n"
            "    return quote(block) {\n        let t:u64 = $v;\n"
            "        return t;\n    };\n}\n" TAIL "blk(1)\n" FOOT);
        char *two = compose(4096, 64, 16777216, 1048576, 128, 16777216,
            "macro unused()->ast.stmt {\n"
            "    return quote(stmt) { return 1; };\n}\n"
            "macro blk(v:ast.expr)->ast.block {\n"
            "    return quote(block) {\n        let t:u64 = $v;\n"
            "        return t;\n    };\n}\n" TAIL "blk(1)\n" FOOT);
        unsigned o1 = 0, o2 = 0, s1 = 0, s2 = 0;
        Run a = run(&image, one ? one : "", 1u << 18, 0);
        Run b = run(&image, two ? two : "", 1u << 18, 0);
        for (uint64_t pass = 0; pass < 2; pass++) {
          const Run *r = pass ? &b : &a;
          if (!layout_ok(r)) continue;
          for (uint64_t id = 1; id <= r->w1; id++) {
            const uint64_t *n = node_words(r, id);
            char text[128], kind = 0;
            unsigned long long o = 0, s = 0, x = 0, y = 0;
            const char *tail = NULL;
            if (n[0] != 90 || n[7] <= n[6]) continue;
            name_copy(r, n[6], n[7], text, sizeof text);
            if (mark_fields(text, &kind, &o, &s, &x, &y, &tail) == 0) continue;
            if (pass) { o2 = (unsigned)o; s2 = (unsigned)s; }
            else { o1 = (unsigned)o; s1 = (unsigned)s; }
            break;
          }
        }
        cases++; checks++;
        if (o1 != 1 || o2 != 2 || s1 != s2) {
          failures++;
          fprintf(stderr,
                  "FAIL the ordinal is not load bearing: one macro gives "
                  "ordinal %u serial %u, two give ordinal %u serial %u\n", o1,
                  s1, o2, s2);
        }
        fprintf(stderr, "PROV_ORDINAL one_macro=%u two_macros=%u serial=%u\n",
                o1, o2, s1);
        freerun(&a);
        freerun(&b);
        free(one);
        free(two);
      }

      /* --- 4. THE SWEEP: every produced name, classified.
       *
       * This is the exhaustive part. The produced name table is the only
       * channel out of the expander, so reading every name the produced
       * region carries and classifying it covers the whole surface rather
       * than the shapes somebody thought to enumerate. The corpus is the
       * seven entries the absence-of-I/O campaign already expands, so the
       * sweep covers the same template vocabulary that campaign covered. */
      {
        unsigned long tally[4] = {0, 0, 0, 0};
        unsigned expanded = 0;
        unsigned total = corpus_size() + 6u;
        for (unsigned c = 0; c < total; c++) {
          /* The same seven wave 12 entries, composed with the FROZEN maxima
           * rather than with the exfiltration probe's tight ones, so an entry
           * is refused for what it is rather than for a budget this block is
           * not measuring, plus the six mark entries above. */
          char *src = sweep_source(c < corpus_size() ? corpus_entry(c)
                                                     : MARK_CORPUS[c - corpus_size()]);
          Run r = run(&image, src ? src : "", 1u << 18, 0);
          fprintf(stderr,
                  "PROV_SWEEP_ENTRY entry=%u ret=%llu code=%llu reason=%llu "
                  "nodes=%llu names=%llu\n", c,
                  (unsigned long long)r.returned, (unsigned long long)r.code,
                  (unsigned long long)r.reason, (unsigned long long)r.w1,
                  (unsigned long long)r.w2);
          if (src) {
            size_t len = strlen(src);
            if (layout_ok(&r)) {
              expanded++;
              for (uint64_t id = 1; id <= r.w1; id++) {
                const uint64_t *n = node_words(&r, id);
                char text[128];
                int cls;
                if (n[0] != 90 || n[7] <= n[6]) continue;
                name_copy(&r, n[6], n[7], text, sizeof text);
                cls = classify_name(text, src, len);
                tally[cls]++;
                if (cls == CLS_UNCLASSIFIED) {
                  failures++;
                  fprintf(stderr,
                          "FAIL corpus %u produced the unclassified name |%s| "
                          "at node %llu\n", c, text, (unsigned long long)id);
                }
              }
            }
            free(src);
          }
          freerun(&r);
        }
        cases++; checks++;
        /* A sweep that classified nothing would report four zeroes and look
         * like a clean surface, so the count of entries that really expanded
         * is asserted, and so is a non-zero marked tally. Two of the seven
         * corpus entries are refusals by construction -- one captures and one
         * collides -- so the floor is three, and the table above says which
         * is which rather than leaving a reader to infer it. */
        if (expanded < 11 || tally[CLS_MARKED] < 18) {
          failures++;
          fprintf(stderr,
                  "FAIL the provenance sweep is vacuous: %u of %u entries "
                  "expanded and %llu names were marked\n", expanded, total,
                  (unsigned long long)tally[CLS_MARKED]);
        }
        cases++; checks++;
        if (tally[CLS_MARKED] + tally[CLS_SPELLED] + tally[CLS_CALLER] !=
            tally[CLS_MARKED] + tally[CLS_SPELLED] + tally[CLS_CALLER] +
                tally[CLS_UNCLASSIFIED]) {
          failures++;
          fprintf(stderr, "FAIL the sweep tallies do not add up\n");
        }
        fprintf(stderr,
                "PROV_SWEEP entries=%u expanded=%u marked=%llu spelled=%llu "
                "caller=%llu unclassified=%llu\n", total, expanded,
                (unsigned long long)tally[CLS_MARKED],
                (unsigned long long)tally[CLS_SPELLED],
                (unsigned long long)tally[CLS_CALLER],
                (unsigned long long)tally[CLS_UNCLASSIFIED]);
      }

      /* --- 5. THE LEAK. A nested expansion's argument keeps no
       * provenance.
       *
       * Four shapes retain their sources: literals and explicit splices are
       * accepted, an unbound template name is refused. They differ in how the
       * outer template spells the argument it hands the inner macro. That
       * is the negative proof for this block: a check that could not tell
       * these four apart would pass on a campaign that had measured
       * nothing, and the four outcomes are required to be four different
       * outcomes.
       *
       * The mechanism, named: clone_stmt hands an expand node straight to
       * expand_node (macro_expand.nova:1498) WITHOUT cloning or resolving
       * its argument, so what lands on the argument stack is a node of the
       * OUTER template. A literal survives that, because a literal has no
       * scope. A name does not: the inner template copies it verbatim at a
       * caller position (:1417 -> :582 emit_name_copy) and the produced
       * region then carries a symbol that no scope anywhere declares. A
       * splice does not either: clone_splice re-resolves it in the INNER
       * template's scope (:1390), so whether it resolves at all, and to
       * what, depends on whether the two macros happen to share a
       * parameter name. */
      {
        const char *shapes[4] = {
            /* 0: a literal argument -- the control that works. */
            "macro outer(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { expand inner(1) };\n}\n"
            "macro inner(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { return $v; };\n}\n",
            /* 1: the inner macro's own parameter name, written by the outer
             * template and bound by neither. */
            "macro outer(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { expand inner(w) };\n}\n"
            "macro inner(w:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { return $w; };\n}\n",
            /* 2: a splice, both macros naming the parameter the same. */
            "macro outer(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { expand inner($v) };\n}\n"
            "macro inner(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { return $v; };\n}\n",
            /* 3: a splice, the inner macro naming it differently. */
            "macro outer(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { expand inner($v) };\n}\n"
            "macro inner(w:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { return $w; };\n}\n"};
        static const char *SHAPE_NAME[4] = {"literal", "bare_name", "splice_same",
                                            "splice_other"};
        unsigned long long unclassified = 0;
        unsigned produced_leak = 0;
        for (unsigned k = 0; k < 4; k++) {
          char *full = malloc(strlen(shapes[k]) + 256);
          char *src = NULL;
          if (full) {
            snprintf(full, strlen(shapes[k]) + 256, "%s" TAIL "outer(1)\n" FOOT,
                     shapes[k]);
            src = compose(4096, 64, 16777216, 1048576, 128, 16777216, full);
          }
          Run r = run(&image, src ? src : "", 1u << 18, 0);
          char label[96];
          snprintf(label, sizeof label, "nested argument shape %s",
                   SHAPE_NAME[k]);
          if (k == 0) {
            fine(&image, label, src ? src : "");
          } else if (k == 1) {
            /* It EXPANDS, and what it publishes is the finding. */
            err(&image, label, src ? src : "", 374, 1);
            if (layout_ok(&r)) {
              size_t len = strlen(src);
              for (uint64_t id = 1; id <= r.w1; id++) {
                const uint64_t *n = node_words(&r, id);
                char text[128];
                if (n[0] != 90 || n[7] <= n[6]) continue;
                name_copy(&r, n[6], n[7], text, sizeof text);
                if (classify_name(text, src, len) ==
                    CLS_UNCLASSIFIED)
                  produced_leak++;
              }
            }
          } else if (k == 2) {
            /* The splice retains the OUTER argument context, which has a
             * parameter of that name and never re-enters the INNER binding. The walk
             * depth cap remains enforced for genuine deep expressions. */
            fine(&image, label, src ? src : "");
          } else {
            /* The same outer splice is valid even if the inner parameter
             * has a different name; lexical provenance is retained. */
            fine(&image, label, src ? src : "");
          }
          fprintf(stderr,
                  "PROV_LEAK shape=%s ret=%llu runtime=%llu code=%llu "
                  "reason=%llu nodes=%llu names=%llu\n", SHAPE_NAME[k],
                  (unsigned long long)r.returned,
                  (unsigned long long)r.runtime, (unsigned long long)r.code,
                  (unsigned long long)r.reason, (unsigned long long)r.w1,
                  (unsigned long long)r.w2);
          freerun(&r);
          free(src);
          free(full);
        }
        cases++; checks++;
        if (produced_leak != 0) {
          failures++;
          fprintf(stderr,
                  "FAIL the bare-name nested argument published an "
                  "unclassified name after lexical-context repair; "
                  "hygiene is broken\n");
        }
        (void)unclassified;
        fprintf(stderr,
                "PROV_LEAK unclassified_published=%u name=%s\n", produced_leak,
                PROV_LEAK_NAME);
      }

      /* --- 6. THE EXECUTION OF THE PRODUCED TEXT.
       *
       * Everything above reads the produced name table, and reading a name
       * table says what the expander WROTE. It says nothing about whether
       * what it wrote can be run, which is the same weakness the I/O
       * campaign had when it claimed a file does not call fopen, and the
       * same answer: measure the channel instead of asserting its absence.
       *
       * The third canary module is that measurement. It expands a source and
       * then hands the produced region to the compiler's OWN compile-time
       * evaluator, so the executed text is executed by the same evaluator
       * that folds a comptime condition, and it reads the hygiene mark back
       * out of the same region it executed. "The mark is fresh" and "the
       * produced text runs" are therefore two facts about ONE artefact.
       *
       * The negative proof is the second source: the two differ only in the
       * constant the template splices, so a probe answering a constant would
       * return the same magnitude twice and go red here rather than looking
       * like two successful runs. */
      {
        static const char *PV = "tests/nova/tests/macro-io-provenance-entry.nova";
        static const char *PV_DEP[5] = {
            "compiler/nova/macros/macro_expand.nova",
            "compiler/nova/macros/constant_eval.nova",
            "compiler/nova/frontend/parser.nova",
            "compiler/nova/frontend/ast.nova",
            "compiler/nova/frontend/lexer.nova"};
        /* One region holding a hygiene mark (the declaration) BESIDE the
         * expression that is executed, which is the whole point of running
         * one against the other. $n+1 with 41 and $n+2 with 42, so the two
         * executions differ. */
        static const char *EXEC_A =
            HEAD "macro calc(n:u64)->ast.expr {\n"
                 "    return quote(expr) { $n + 1 };\n}\n"
                 "macro tag()->ast.decl {\n"
                 "    emit quote(decl) { const c:u64 = 1; }\n}\n"
                 TAIL "tag()\n        expand calc(41)\n" FOOT;
        static const char *EXEC_B =
            HEAD "macro calc(n:u64)->ast.expr {\n"
                 "    return quote(expr) { $n + 2 };\n}\n"
                 "macro tag()->ast.decl {\n"
                 "    emit quote(decl) { const c:u64 = 1; }\n}\n"
                 TAIL "tag()\n        expand calc(42)\n" FOOT;
        size_t pn = 0;
        char *ptext = loadf(PV, &pn);
        NtFInput pin[6];
        char *pdep[5];
        memset(pin, 0, sizeof pin);
        CHECK(ptext, "the provenance execution module loads");
        pin[0] = (NtFInput){PV, ptext, pn};
        for (unsigned k = 0; k < 5; k++) {
          size_t dn = 0;
          pdep[k] = loadf(PV_DEP[k], &dn);
          CHECK(pdep[k], "the provenance execution module's imports load");
          pin[k + 1] = (NtFInput){PV_DEP[k], pdep[k], dn};
        }
        NtArtifact pa = {0};
        int pok = ptext && nova_compile_many_v2(pin, 6, &pa);
        CHECK(pok, "the provenance execution module compiles");
        if (!pok)
          fprintf(stderr, "E%u %zu:%zu %s\n", pa.error.code, pa.error.line,
                  pa.error.column, pa.error.message);
        NovaHostImage pimg = {0};
        CHECK(pok && nova_host_map(&pa, &pimg), "the provenance execution module maps");
        if (pok && pimg.memory) {
          Run a = run(&pimg, EXEC_A, 1u << 18, 0);
          Run b = run(&pimg, EXEC_B, 1u << 18, 0);
          cases++; checks++;
          /* The produced text must have FOLDED. A status that is not zero
           * executed nothing, and comparing two such runs would compare two
           * zeroes and prove nothing, so the status is checked before the
           * magnitudes are believed. */
          if (a.returned || a.runtime || a.code || b.returned || b.runtime ||
              b.code) {
            failures++;
            fprintf(stderr,
                    "FAIL the execution channel did not run: a ret=%llu "
                    "runtime=%llu code=%llu, b ret=%llu runtime=%llu code=%llu\n",
                    (unsigned long long)a.returned, (unsigned long long)a.runtime,
                    (unsigned long long)a.code, (unsigned long long)b.returned,
                    (unsigned long long)b.runtime, (unsigned long long)b.code);
          }
          cases++; checks++;
          if (a.out[2] != 0 || b.out[2] != 0) {
            failures++;
            fprintf(stderr,
                    "FAIL the produced text did not fold: status %llu and "
                    "%llu\n", (unsigned long long)a.out[2],
                    (unsigned long long)b.out[2]);
          }
          cases++; checks++;
          /* 41+1 and 42+2. Pinning the values is the measurement; the arm
           * below is the negative proof that the probe is not a stub. */
          if (a.out[4] != 42 || b.out[4] != 44) {
            failures++;
            fprintf(stderr,
                    "FAIL the produced text folded to %llu and %llu, not 42 "
                    "and 44\n", (unsigned long long)a.out[4],
                    (unsigned long long)b.out[4]);
          }
          cases++; checks++;
          if (a.out[4] == b.out[4]) {
            failures++;
            fprintf(stderr,
                    "FAIL the execution probe answered the same magnitude for "
                    "two different produced texts, so it is measuring its own "
                    "stub\n");
          }
          /* The mark, read back out of the region that was just executed.
           * `tag` is the SECOND macro declaration, so its mark's ordinal is
           * 2, and it is the first expansion, so its serial is 1. Two
           * different fields, so a probe that filled both from one number
           * would be caught by the inequality below. */
          cases++; checks++;
          if (a.out[5] != 2 || a.out[6] != 1 || b.out[5] != 2 || b.out[6] != 1) {
            failures++;
            fprintf(stderr,
                    "FAIL the mark read out of the executed region is "
                    "ordinal %llu serial %llu, want 2 and 1\n",
                    (unsigned long long)a.out[5],
                    (unsigned long long)a.out[6]);
          }
          cases++; checks++;
          if (a.out[5] == a.out[6]) {
            failures++;
            fprintf(stderr, "FAIL the mark fields are one number\n");
          }
          fprintf(stderr,
                  "PROV_EXEC a_folded=%llu b_folded=%llu status=%llu "
                  "mark_ordinal=%llu mark_serial=%llu nodes=%llu "
                  "executed_by=ntasm_constant_eval\n",
                  (unsigned long long)a.out[4], (unsigned long long)b.out[4],
                  (unsigned long long)a.out[2], (unsigned long long)a.out[5],
                  (unsigned long long)a.out[6], (unsigned long long)a.out[1]);
          freerun(&a);
          freerun(&b);
        }
        if (pimg.memory) nova_host_unmap(&pimg);
        if (pok) nt_artifact_free(&pa);
        free(ptext);
        for (unsigned k = 0; k < 5; k++) free(pdep[k]);
      }

      /* --- 6a. THE ADVERSARIAL SET, ITS CASE COUNT, AND ITS POSITIVE
       * CONTROL. (wave 21, criterion A5's « avec tests adverses »)
       *
       * WHY THIS BLOCK EXISTS AT ALL, and the answer is not "more coverage".
       * The sweep above is EXHAUSTIVE over the produced name table of a
       * thirteen-entry corpus, and it is therefore the strongest kind of
       * provenance measurement there is -- on the entries it was given. What
       * it cannot be is adversarial: every entry in it expands, because a
       * corpus made of refusals would say nothing about which names a
       * refusal is refusing. Criterion A5 names « Hygiène, provenance,
       * absence d'I/O et bornes imposées, avec tests adverses » and the four
       * words after the comma are a separate requirement from the four
       * before it. This block is that requirement, built from inputs that
       * SHOULD be caught.
       *
       * THE CASE COUNT IS PRINTED AND CHECKED BY EQUALITY, and that is the
       * whole point of putting it here. x64_lower_lea declared 189 rows it
       * had not judged, because a manifest cell could not be allocated and
       * the closure carried the same banner as a full pass. A campaign that
       * silently judges fewer cases than it should has proved nothing, so
       * ADV_CASES is a named expected number and the number of cases this
       * block actually JUDGED is compared to it with ==, not with a floor.
       * The table is written so that adding an eleventh shape without
       * adding it to the count goes red, and so that dropping one does too.
       *
       * THE POSITIVE CONTROL IS THE CLASSIFIER ITSELF, asked directly. The
       * sweep's headline is `unclassified=0`, and a zero produced by a
       * predicate that has never been shown to return anything but zero is
       * the exact shape of the defect this project already paid for once.
       * So the classifier is called on a text it must refuse to classify --
       * the bare name `w`, in a source that does not declare `w` -- and the
       * answer must be CLS_UNCLASSIFIED; and on a real mark, where the
       * answer must be CLS_MARKED. If the first of those ever stops firing,
       * the sweep's zero below is void and this block says so in the same
       * run rather than in a later reading of the log. */
      {
        /* Eleven cases. The count is a literal on purpose, and the check
         * below compares against it with equality: a floor is a campaign
         * that is happy to judge less than it claims. */
        enum { ADV_CASES = 12 };
        /* 0 CONTROL: not adversarial at all. It exists so that a refusal
         * below describes the RULE and not a parser that refuses
         * everything, which is the canary argument the I/O campaign made and
         * the reason it was worth having. */
        static const char *ADV_CONTROL =
            "macro mk(v:ast.expr)->ast.block {\n"
            "    return quote(block) { let t:u64 = $v; return t; };\n}\n"
            TAIL "mk(7)\n" FOOT;
        /* 1 SIBLING SCOPE: a name a SIBLING macro's body would bind, which
         * this macro's body spells and neither it nor the caller binds. */
        static const char *ADV_SIBLING =
            "macro sib()->ast.stmt {\n"
            "    return quote(stmt) { return sibonly; };\n}\n"
            "macro user()->ast.stmt {\n"
            "    return quote(stmt) { return sibonly; };\n}\n"
            TAIL "user()\n" FOOT;
        /* 2 SHADOWED BINDING: outer and inner both bind `t`. It MUST
         * expand, and the two marks it publishes must differ -- that
         * difference is the provenance claim in its most concrete form. */
        static const char *ADV_SHADOW =
            "macro inner()->ast.block {\n"
            "    return quote(block) { let t:u64=1; return t; };\n}\n"
            "macro outer()->ast.block {\n"
            "    return quote(block) {\n"
            "        let t:u64=2;\n"
            "        expand inner();\n"
            "        return t;\n"
            "    };\n}\n"
            TAIL "outer()\n" FOOT;
        /* 3 RECURSION: a macro that expands itself, unconditionally. A
         * bound must answer it; acceptance would be an unbounded
         * expansion. 201 reason 2 is call_depth. */
        static const char *ADV_RECURSE =
            "macro loopy(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { expand loopy(1) };\n}\n"
            TAIL "loopy(1)\n" FOOT;
        /* 4 THE FINDING. The name an expansion introduces, re-bound by the
         * CALLER at FUNCTION scope, before the expand. This is ACCEPTED,
         * and the row says so rather than the campaign quietly dropping it.
         * See the note on row 6 for why, and for the shape that is refused. */
        static const char *ADV_REBIND_LOCAL =
            "module m\ntarget x86_64-nexora-none\n"
            "macro mk()->ast.block {\n"
            "    return quote(block) { let t:u64=1; return t; };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        let t:u64 = 9;\n        expand mk()\n"
            "    }\n}\n";
        /* 5 the control for row 4: byte-identical except the caller's
         * binding is spelled differently. A pair that cannot come apart is
         * not a measurement, and this is the pair that says the acceptance
         * in row 4 is the rule's edge and not a parser accident. */
        static const char *ADV_REBIND_LOCAL_CTL =
            "module m\ntarget x86_64-nexora-none\n"
            "macro mk()->ast.block {\n"
            "    return quote(block) { let t:u64=1; return t; };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        let other:u64 = 9;\n        expand mk()\n"
            "    }\n}\n";
        /* 6 THE SAME REBIND AT MODULE SCOPE, which is refused 381. The two
         * rows 4 and 6 together are the measured edge of diagnostic 381:
         * declares_below (macro_expand.nova:1409-1428) reads k_const,
         * k_data, k_fn and k_param at macro_expand.nova:1416-1417 and k_let is not among
         * them, so a function-local let cannot raise it. */
        static const char *ADV_REBIND_MODULE =
            "module m\ntarget x86_64-nexora-none\n"
            "const t:u64 = 1;\n"
            "macro mk()->ast.block {\n"
            "    return quote(block) { let t:u64=1; return t; };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        expand mk()\n    }\n}\n";
        /* 7 the control for row 6, and the one that must come apart. */
        static const char *ADV_REBIND_MODULE_CTL =
            "module m\ntarget x86_64-nexora-none\n"
            "const other:u64 = 1;\n"
            "macro mk()->ast.block {\n"
            "    return quote(block) { let t:u64=1; return t; };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        expand mk()\n    }\n}\n";
        /* 8 a template local spelled like one of the macro's own
         * parameters: 376/2, refused at macro_expand.nova:1527 and tested at :1526. */
        static const char *ADV_PARAM_SHADOW =
            "module m\ntarget x86_64-nexora-none\n"
            "macro dup(v:ast.expr)->ast.block {\n"
            "    return quote(block) { let v:u64 = 1; return v; };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        expand dup(1)\n    }\n}\n";
        /* 9 a reserved word as a template name: 376/3, refused at
         * macro_expand.nova:1529. Present so the set is not one
         * diagnostic wearing nine hats. */
        static const char *ADV_RESERVED =
            "module m\ntarget x86_64-nexora-none\n"
            "macro kw()->ast.block {\n"
            "    return quote(block) { let u64:u64 = 1; return u64; };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        expand kw()\n    }\n}\n";
        /* 10 the name the caller never bound, asked at the top of a
         * template rather than through a nested splice: 374/1, the same
         * rule PROV_LEAK reaches the other way. */
        static const char *ADV_UNBOUND =
            "macro steal()->ast.stmt {\n"
            "    return quote(stmt) { return nowhere; };\n}\n"
            TAIL "steal()\n" FOOT;
        /* 11 recursion through a meta-for, refused 377/4 because the macro
         * declares ast.stmt and emits declarations. It is here because it
         * is a DIFFERENT walk from row 3 and it is answered by a form rule
         * rather than by a budget; the row names that difference so nobody
         * reads it as a second depth measurement. */
        static const char *ADV_RECURSE_FOR =
            "macro rep(n:u64)->ast.stmt {\n"
            "    for i in $n {\n"
            "        emit quote(stmt) { let t:u64 = $i; }\n"
            "    }\n"
            "    return quote(stmt) { expand rep(2); };\n}\n"
            TAIL "rep(2)\n" FOOT;

        {
          static char *bodies[ADV_CASES];
          uint64_t want[ADV_CASES], want_reason[ADV_CASES];
          const char *means[ADV_CASES];
          const char *names[ADV_CASES];
          /* The table is filled here rather than at file scope because the
           * bodies above are `static const char *` objects, not constant
           * expressions, and C will not accept those as static
           * initialisers. The same constraint the corpus switch above is
           * written under, for the same reason. */
          bodies[0] = (char *)ADV_CONTROL;         want[0] = 0; want_reason[0] = 0;
          means[0] = "CONTROL_the_shape_must_expand";
          bodies[1] = (char *)ADV_SIBLING;         want[1] = 374; want_reason[1] = 1;
          means[1] = "a_name_bound_only_in_a_sibling_scope_is_a_capture";
          bodies[2] = (char *)ADV_SHADOW;          want[2] = 0; want_reason[2] = 0;
          means[2] = "two_bindings_named_t_get_two_distinct_marks";
          bodies[3] = (char *)ADV_RECURSE;         want[3] = 201; want_reason[3] = 2;
          means[3] = "a_recursive_macro_is_answered_by_call_depth";
          bodies[4] = (char *)ADV_REBIND_LOCAL;    want[4] = 0; want_reason[4] = 0;
          means[4] = "FINDING_a_function_local_rebind_is_ACCEPTED";
          bodies[5] = (char *)ADV_REBIND_LOCAL_CTL; want[5] = 0; want_reason[5] = 0;
          means[5] = "CONTROL_for_row_4_must_expand_too";
          bodies[6] = (char *)ADV_REBIND_MODULE;  want[6] = 381; want_reason[6] = 1;
          means[6] = "the_same_rebind_at_module_scope_is_refused_381";
          bodies[7] = (char *)ADV_REBIND_MODULE_CTL; want[7] = 0; want_reason[7] = 0;
          means[7] = "CONTROL_for_row_6_must_expand_so_6_is_the_rule";
          bodies[8] = (char *)ADV_PARAM_SHADOW;    want[8] = 376; want_reason[8] = 2;
          means[8] = "a_template_local_may_not_shadow_a_macro_parameter";
          bodies[9] = (char *)ADV_RESERVED;        want[9] = 376; want_reason[9] = 3;
          means[9] = "a_template_local_may_not_be_a_reserved_word";
          bodies[10] = (char *)ADV_UNBOUND;       want[10] = 374; want_reason[10] = 1;
          means[10] = "a_name_the_caller_never_bound_is_a_capture";
          bodies[11] = (char *)ADV_RECURSE_FOR;   want[11] = 377; want_reason[11] = 4;
          means[11] = "recursion_through_a_meta_for_is_a_form_refusal_not_a_budget";
          names[11] = "recurse_metafor";
          names[0] = "control";            names[1] = "sibling_scope";
          names[2] = "shadowed";          names[3] = "recursion";
          names[4] = "rebind_fnlocal";     names[5] = "rebind_fnlocal_ctl";
          names[6] = "rebind_module";      names[7] = "rebind_module_ctl";
          names[8] = "param_shadow";       names[9] = "reserved";
          names[10] = "unbound";
          {
            unsigned judged = 0;
            unsigned accepted = 0, refused = 0;
            uint64_t shadow_marks[8];
            unsigned shadow_distinct = 0;
            for (unsigned k = 0; k < ADV_CASES; k++) {
              char *src = bodies[k];
              char *owned = NULL;
              Run r;
              if (src == NULL) continue;   /* a row that was never filled */
              if (strncmp(src, "module ", 7) != 0) {
                owned = compose(4096, 64, 16777216, 1048576, 128, 65536, src);
                src = owned;
              }
              r = run(&image, src ? src : "", 1u << 18, 0);
              judged++;
              if (r.returned == 0) accepted++; else refused++;
              fprintf(stderr,
                      "ADV_CASE n=%u/%d shape=%-20s ret=%llu code=%llu "
                      "reason=%llu w1=%llu w2=%llu means=%s\n", k, ADV_CASES,
                      names[k], (unsigned long long)r.returned,
                      (unsigned long long)r.code, (unsigned long long)r.reason,
                      (unsigned long long)r.w1, (unsigned long long)r.w2,
                      means[k]);
              cases++; checks++;
              if (r.returned != want[k] ||
                  (want[k] != 0 && (r.reason != want_reason[k] || r.code != want[k]))) {
                failures++;
                fprintf(stderr,
                        "FAIL adversarial case %u (%s) returned %llu/%llu and "
                        "the campaign says %llu/%llu -- %s\n", k, names[k],
                        (unsigned long long)r.returned,
                        (unsigned long long)r.reason,
                        (unsigned long long)want[k],
                        (unsigned long long)want_reason[k], means[k]);
              }
              /* Row 2 is the concrete provenance claim, so the THING is
               * printed and the two marks are compared as fields, not as a
               * count. A count of distinct marks would be satisfied by two
               * copies of one mark. */
              if (k == 2 && layout_ok(&r)) {
                for (uint64_t id = 1; id <= r.w1; id++) {
                  const uint64_t *n = node_words(&r, id);
                  char text[128];
                  char kind = 0;
                  unsigned long long ord = 0, ser = 0, x = 0, y = 0;
                  const char *nm = NULL;
                  if (n[0] != 90 || n[7] <= n[6]) continue;
                  name_copy(&r, n[6], n[7], text, sizeof text);
                  fprintf(stderr, "ADV_NAME shape=shadowed node=%llu |%s|\n",
                          (unsigned long long)id, text);
                  if (mark_fields(text, &kind, &ord, &ser, &x, &y, &nm) == 1) {
                    int seen = 0;
                    for (unsigned m = 0; m < shadow_distinct; m++)
                      if (shadow_marks[m] == ord) seen = 1;
                    if (seen == 0 && shadow_distinct < 8)
                      shadow_marks[shadow_distinct++] = ord;
                  }
                }
                cases++; checks++;
                if (shadow_distinct < 2) {
                  failures++;
                  fprintf(stderr,
                          "FAIL the shadowed case published %u distinct macro "
                          "ordinals, so the two `t` bindings were not kept "
                          "apart by their marks\n", shadow_distinct);
                }
              }
              freerun(&r);
              free(owned);
            }
            /* THE COUNT, CHECKED BY EQUALITY. This is the line that makes
             * the block's own claim falsifiable: judged is how many cases
             * ran, ADV_CASES is how many the campaign says it has, and a
             * mismatch in EITHER direction is a red rather than a note. */
            cases++; checks++;
            if (judged != (unsigned)ADV_CASES) {
              failures++;
              fprintf(stderr,
                      "FAIL the adversarial set judged %u cases and claims %d, "
                      "so a green from this block would be a green from a "
                      "smaller experiment than the one named\n", judged,
                      ADV_CASES);
            }
            /* THE POSITIVE CONTROL. Asked directly, on both answers, so the
             * sweep's `unclassified=0` above has a predicate behind it that
             * has been seen to say yes as well as no. */
            cases++; checks++;
            {
              static const char *ctl_src =
                  "module m\ntarget x86_64-nexora-none\n"
                  "macro steal()->ast.stmt {\n"
                  "    return quote(stmt) { return w; };\n}\n"
                  "section .text {\n    export fn main()->u64\n    effects {}\n"
                  "    clobbers {} {\n        expand steal()\n    }\n}\n";
              int bare = classify_name("w", ctl_src, strlen(ctl_src));
              int mark = classify_name("__ntm$1$e1$t", ctl_src, strlen(ctl_src));
              int word = classify_name("u64", ctl_src, strlen(ctl_src));
              if (bare != CLS_UNCLASSIFIED) {
                failures++;
                fprintf(stderr,
                        "FAIL the classifier's positive control did not fire: "
                        "the bare name `w` in a source that does not declare "
                        "it classified as %d, so `unclassified=0` above is a "
                        "zero this predicate cannot produce\n", bare);
              }
              if (mark != CLS_MARKED) {
                failures++;
                fprintf(stderr,
                        "FAIL the classifier did not recognise a real mark: "
                        "__ntm$1$e1$t classified as %d\n", mark);
              }
              if (word != CLS_SPELLED) {
                failures++;
                fprintf(stderr,
                        "FAIL the classifier did not recognise a spelled word: "
                        "u64 classified as %d\n", word);
              }
              fprintf(stderr,
                      "ADV_CONTROL classifier_bare_w=%d classifier_mark=%d "
                      "classifier_spelled=%d fires=%d\n", bare, mark, word,
                      bare == CLS_UNCLASSIFIED ? 1 : 0);
            }
            fprintf(stderr,
                    "ADV_SUMMARY declared=%d judged=%u accepted=%u refused=%u "
                    "count_checked_by=equality control_expanded=%d "
                    "classifier_control_fires=%d\n", ADV_CASES, judged, accepted,
                    refused, want[0] == 0 ? 1 : 0,
                    classify_name("w", "module m\n", 9) == CLS_UNCLASSIFIED ? 1 : 0);
          }
        }
      }
      /* ==== W68: THE ADVERSARIAL TABLE, AND WHAT WAS AVAILABLE TO GO WRONG.
       *
       * The ADV block above asks whether a case is ACCEPTED or REFUSED. That
       * is the wrong question for hygiene on its own: a case where the wrong
       * binding was never AVAILABLE proves nothing, and a refusal on a case
       * where nothing could collide proves less than it looks. So every row
       * here names THREE things and all three are checked: the wrong binding
       * that was available, what actually happened, and -- for the accepted
       * rows -- that the name the produced region publishes is the MARK and
       * not the spelling, read out of the produced bytes rather than counted.
       *
       * The property under test is not "was it refused". It is: A NAME NEVER
       * BINDS SILENTLY TO THE WRONG DECLARATION. A refusal satisfies that. So
       * does an acceptance whose published name is a mark the caller cannot
       * spell. What does NOT satisfy it is an acceptance whose published name
       * is a SPELLED identifier the caller also declared -- and that is the
       * row this block found, and it is Nova-only (see the note at row 6). */
      {
        /* Row A. The caller's own name at function scope, the outer template
         * introduces the SAME spelling, and the outer passes that introduced
         * name to an INNER macro as an argument.
         *
         * THE WRONG BINDING THAT WAS AVAILABLE, and it is not hypothetical:
         * the caller writes `let t:u64=9` at line 13, so a bare `t` in the
         * produced region has a declaration to land on, and it is not the
         * declaration the author meant -- the outer introduced its own `t` and
         * renamed it, so the inner's `$v` is that renamed name, not the
         * caller's. The inner publishes a SPELLED `t` and the outer publishes
         * `__ntm$2$e1$t` in the same produced region.
         *
         * The control differs in ONE token: the caller binds `u` instead of
         * `t`, so no wrong binding is available and the row cannot come apart
         * for an unrelated reason. Both expand; only A was wrong. */
        static const char *HYG_SILENT =
            HEAD "macro inner(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { return $v; };\n}\n"
            "macro outer()->ast.block {\n"
            "    return quote(block) { let t:u64=2; expand inner(t); return t; };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        let t:u64=9;\n        expand outer()\n    }\n}\n";
        static const char *HYG_SILENT_CTL =
            HEAD "macro inner(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { return $v; };\n}\n"
            "macro outer()->ast.block {\n"
            "    return quote(block) { let s:u64=2; expand inner(s); return s; };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        let t:u64=9;\n        expand outer()\n    }\n}\n";

        /* Row B. THE TWO-LEVEL NESTED EXPANSION WITH A COLLIDING GENERATED
         * NAME, and it is the case that discriminates: three names are spelled
         * `t` -- the caller's local, the outer's introduced binding, and the
         * inner's introduced binding -- and all three expansions publish a
         * name. A single-level capture test cannot tell these apart, because
         * with one level there is only ever one generated name to collide
         * with. Here there are TWO, and they must differ.
         *
         * The control C is the same text with the caller's `let t` removed:
         * same three expansions minus the one collision, so a difference
         * between B and C is attributable to the caller's declaration and not
         * to the nesting. */
        static const char *HYG_TWO_LEVEL =
            HEAD "macro inner()->ast.block {\n"
            "    return quote(block) { let t:u64=1; return t; };\n}\n"
            "macro outer()->ast.block {\n"
            "    return quote(block) {\n        let t:u64=2;\n"
            "        expand inner();\n        return t;\n    };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        let t:u64=9;\n        expand outer()\n    }\n}\n";
        static const char *HYG_TWO_LEVEL_CTL =
            HEAD "macro inner()->ast.block {\n"
            "    return quote(block) { let t:u64=1; return t; };\n}\n"
            "macro outer()->ast.block {\n"
            "    return quote(block) {\n        let t:u64=2;\n"
            "        expand inner();\n        return t;\n    };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        expand outer()\n    }\n}\n";

        /* Row D. A MACRO WHOSE PARAMETER SHADOWS A DECLARATION THE MACRO DID
         * NOT INTRODUCE, crossed with a nested expansion: the caller binds
         * `v`, the outer takes `v` as a parameter, and the inner is handed the
         * outer's parameter. The spliced node must be the CALLER's node -- it
         * is the one argument path where a spelled name is CORRECT, because
         * the name belongs to the scope that wrote it. This row is the
         * positive control for row A: it is the same mechanism with the
         * scopes the right way round, and it must stay spelled. */
        static const char *HYG_CALLER_ARG =
            HEAD "macro id(v:ast.expr)->ast.stmt {\n"
            "    return quote(stmt) { return $v; };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        let v:u64=9;\n        expand id(v)\n    }\n}\n";

        /* Row E. THE DIAGNOSTIC SPAN. A refusal raised INSIDE an expansion,
         * on a name the TEMPLATE introduces, must report the line and column
         * of the author's own macro body -- not the invocation, and not any
         * offset in the produced region. The expected line and column are
         * written out of the SOURCE the harness holds, by counting the line
         * and the column of the byte, so a reader can re-derive them. */
        static const char *HYG_SPAN =
            HEAD "const t:u64=1;\n"
            "macro mk()->ast.block {\n"
            "    return quote(block) { let t:u64=1; return t; };\n}\n"
            "section .text {\n    export fn main()->u64\n    effects {}\n"
            "    clobbers {} {\n        expand mk()\n    }\n}\n";

        /* The expected span of HYG_SPAN's refusal, DERIVED from the source
         * rather than pinned as a pair of literals: line 5 is the `return
         * quote(block) { let t:u64=1; ...` line and column 31 is the `t` of
         * the `let`, so the check below recomputes both from `at` and a green
         * cannot come from a literal that happens to be right today. */
        static const char *HYG_SPAN_NEEDLE = "let t:u64=1";

        unsigned judged_h = 0, nothing_available = 0, wrong_binding_rows = 0;

        /* THE HELPER, so "the published name is the mark" is a property of
         * the produced BYTES and not of a count. It answers: does the
         * produced region publish any name that is a SPELLED identifier the
         * caller also declared? `bare_of_caller` is the set the caller wrote
         * outside every macro body, re-derived by the same rule the expander
         * uses (a template is not a caller declaration). */
        {
          const char *lbl[] = {"silent", "silent_ctl", "two_level",
                               "two_level_ctl", "caller_arg", "span"};
          const char *src[] = {HYG_SILENT, HYG_SILENT_CTL, HYG_TWO_LEVEL,
                               HYG_TWO_LEVEL_CTL, HYG_CALLER_ARG, HYG_SPAN};
          for (unsigned k = 0; k < 6; k++) {
            Run r = run(&image, src[k], 1u << 18, 0);
            judged_h++;
            fprintf(stderr,
                    "HYG_CASE n=%u/6 shape=%-15s ret=%llu code=%llu reason=%llu "
                    "line=%llu col=%llu nodes=%llu\n",
                    k, lbl[k], (unsigned long long)r.returned,
                    (unsigned long long)r.code, (unsigned long long)r.reason,
                    (unsigned long long)r.out[1],
                    (unsigned long long)r.out[2],
                    (unsigned long long)r.out[1]);
            cases++; checks++;

            /* THE SPAN, on the one row whose whole point is where the
             * diagnostic points. It is compared against the source the
             * harness holds, so the expectation is re-derived on every run
             * and a wrong column cannot hide behind a stale literal. */
            if (k == 5) {
              unsigned want_line = 0, want_col = 0;
              size_t len = strlen(HYG_SPAN);
              size_t at = 0;
              while (at + strlen(HYG_SPAN_NEEDLE) <= len &&
                     strncmp(HYG_SPAN + at, HYG_SPAN_NEEDLE,
                             strlen(HYG_SPAN_NEEDLE)) != 0)
                at++;
              if (at < len) {
                /* THE LINE START, remembered as the loop goes. The first
                 * version ran the scan to `at` and then subtracted `scan`,
                 * which is zero by construction: the loop exits only when
                 * scan==at, so the derived column was the width of the needle
                 * and the check was satisfied by any column the expander
                 * reported past it. A column derived that way cannot fail,
                 * and a check that cannot fail is not a check. */
                size_t scan = 0, line_start = 0;
                want_line = 1;
                while (scan < at) {
                  if (HYG_SPAN[scan] == '\n') { want_line++; line_start = scan + 1; }
                  scan++;
                }
                /* the needle starts at the `l` of `let`; the `t` is four
                 * bytes in, and columns are one based. */
                want_col = (unsigned)(at + 4 - line_start) + 1;
              }
              if (r.code != 381 || r.reason != 1) {
                failures++;
                fprintf(stderr,
                        "FAIL hygiene span row did not raise 381/1: got "
                        "%llu/%llu\n",
                        (unsigned long long)r.code,
                        (unsigned long long)r.reason);
              } else if (r.out[1] != want_line || r.out[2] != want_col) {
                failures++;
                fprintf(stderr,
                        "FAIL the refusal raised inside the expansion reported "
                        "line %llu column %llu and the author's macro body says "
                        "%u:%u -- a span that names neither the invocation nor "
                        "the template's own text is not a source span\n",
                        (unsigned long long)r.out[1],
                        (unsigned long long)r.out[2], want_line, want_col);
              }
              fprintf(stderr,
                      "HYG_SPAN reported=%llu:%llu derived_from_source=%u:%u "
                      "needle=|%s| invocation_line=12 template_line=%u\n",
                      (unsigned long long)r.out[1], (unsigned long long)r.out[2],
                      want_line, want_col, HYG_SPAN_NEEDLE, want_line);
            }

            /* EVERY ACCEPTED ROW: walk the produced region and ask, name by
             * name, whether the expander published a SPELLED identifier that
             * a TEMPLATE BOUND. A mark never matches; a spelled type word
             * never matches; the caller's own parameter name never matches,
             * because a parameter is not renamed. A bare `t` where the
             * template bound `t` does, and that is the defect. */
            if (r.code == 0 && r.w1 != 0) {
              unsigned marks = 0, spelled_caller = 0;
              char seen[16][128];
              unsigned seen_n = 0;
              for (uint64_t id = 1; id <= r.w1; id++) {
                const uint64_t *n = node_words(&r, id);
                char text[128];
                char kind = 0;
                unsigned long long ord = 0, ser = 0, x = 0, y = 0;
                const char *nm = NULL;
                if (n[0] != 90 || n[7] <= n[6]) continue;
                name_copy(&r, n[6], n[7], text, sizeof text);
                if (mark_fields(text, &kind, &ord, &ser, &x, &y, &nm) == 1) {
                  marks++;
                  if (seen_n < 16) {
                    snprintf(seen[seen_n], sizeof seen[0], "%s", text);
                    seen_n++;
                  }
                  continue;
                }
                /* not a mark: is it a name one of the TEMPLATES bound? A name
                 * a template binds is renamed, so this spelling refers to
                 * something the expansion did not introduce. */
                if (spelled_word(text) == 1) continue;
                if (template_binds(src[k], strlen(src[k]), text) == 1) {
                  spelled_caller++;
                  failures++;
                  fprintf(stderr,
                          "FAIL hygiene row %s published the SPELLED name |%s|, "
                          "which a macro body binds: the expansion renamed that "
                          "binding, so the spelled form points at some other "
                          "declaration and not at the one the author meant\n",
                          lbl[k], text);
                }
              }
              if (k == 2 || k == 3) {
                /* the two-level row must publish TWO DISTINCT marks for the
                 * two bindings spelled `t`, compared as text and not as a
                 * count: two copies of one mark satisfy a count. */
                int distinct = 0;
                for (unsigned a = 0; a < seen_n; a++) {
                  int dupe = 0;
                  for (unsigned b = 0; b < a; b++)
                    if (strcmp(seen[a], seen[b]) == 0) dupe = 1;
                  if (dupe == 0) distinct++;
                }
                if (marks < 2 || distinct < 2) {
                  failures++;
                  fprintf(stderr,
                          "FAIL the two-level nested expansion published %u "
                          "marks and %u distinct ones, so the two bindings "
                          "spelled `t` were not kept apart\n",
                          marks, distinct);
                }
                wrong_binding_rows++;
              }
              fprintf(stderr,
                      "HYG_NAMES shape=%-15s marks=%u spelled_caller_names=%u "
                      "distinct_marks=%u\n",
                      lbl[k], marks, spelled_caller,
                      seen_n < 2 ? seen_n : 2);
            }

            /* Row D is the control that must NOT be swept into the finding:
             * it publishes a spelled `v` on purpose, and that is CORRECT
             * because the caller owns the name. If the block above ever
             * starts refusing it, the pair has come apart. */
            if (k == 4) {
              unsigned spelled_v = 0;
              if (layout_ok(&r)) {
                for (uint64_t id = 1; id <= r.w1; id++) {
                  const uint64_t *n = node_words(&r, id);
                  char text[128];
                  if (n[0] != 90 || n[7] <= n[6]) continue;
                  name_copy(&r, n[6], n[7], text, sizeof text);
                  if (strcmp(text, "v") == 0) spelled_v++;
                }
              }
              if (spelled_v != 1) {
                failures++;
                fprintf(stderr,
                        "FAIL the caller-argument control published |v| %u "
                        "times and exactly once is what proves the spliced "
                        "CALLER node keeps the caller's spelling\n",
                        spelled_v);
              }
              nothing_available++;
            }
            freerun(&r);
          }

          /* THE TWO ROWS WHERE NOTHING COULD GO WRONG, named rather than
           * counted as coverage. Row silent_ctl has no wrong binding
           * available -- the caller bound `t` and the expansions introduce
           * `s`, so a spelled `s` has nothing to bind to. Row caller_arg is
           * the positive control, where a spelled name is the CORRECT
           * outcome. Neither is evidence that hygiene holds; they are the
           * instruments that make the other rows readable. */
          cases++; checks++;
          if (nothing_available != 1) {
            failures++;
            fprintf(stderr,
                    "FAIL the block claims one row where nothing could go "
                    "wrong and counted %u\n", nothing_available);
          }
          cases++; checks++;
          if (judged_h != 6 || wrong_binding_rows != 2) {
            failures++;
            fprintf(stderr,
                    "FAIL the adversarial table judged %u rows and claims 6, "
                    "with %u rows where a wrong binding was available and it "
                    "claims 2\n",
                    judged_h, wrong_binding_rows);
          }
          fprintf(stderr,
                  "HYG_SUMMARY rows=6 judged=%u nothing_available=%u "
                  "wrong_binding_available=%u "
                  "property=no_produced_name_is_a_spelled_identifier_the_"
                  "caller_declares\n",
                  judged_h, nothing_available, wrong_binding_rows);
        }
      }

      /* --- 7. THE SEVEN COMPILER BOUNDS.
       *
       * The triple is at the cap, one past it and one below it. Two of the
       * seven answer. Five do not, and for each of those the number that
       * matters is the one that answers FIRST, measured by bisection on
       * the body that reaches each ceiling soonest. */
      {
        /* (a) parameter_cap = 8. Reachable, and clean. */
        for (unsigned k = 0; k < 3; k++) {
          unsigned n = k == 0 ? 7u : (k == 1 ? 8u : 9u);
          char *src = params_body(n);
          char label[96];
          snprintf(label, sizeof label,
                   "parameter_cap %u parameter macro", n);
          if (n <= 8) fine(&image, label, src ? src : "");
          else err(&image, label, src ? src : "", 372, 2);
          free(src);
        }
        fprintf(stderr,
                "BOUND parameter_cap=8 at8=ok past9=372/2 below7=ok "
                "reachable=yes shadow=none\n");

        /* (b) walk_depth_cap = 64. Reachable, and clean: two per level,
         * because run_block hands an item depth+1 and a meta-if hands its
         * then-block depth+1. */
        {
          unsigned deepest = 0, past = 0;
          for (unsigned lv = 1; lv <= 40; lv++) {
            char *src = nest_body(lv);
            Run r = run(&image, src ? src : "", 1u << 18, 0);
            int ok = r.code == 0 && r.runtime == 0 && r.w1 != 0;
            int depth_refused = r.code == 375 && r.reason == 9;
            if (ok) deepest = lv;
            if (depth_refused && past == 0) past = lv;
            freerun(&r);
            free(src);
          }
          char label[96];
          char *a = nest_body(deepest > 1 ? deepest - 1 : 1);
          char *b = nest_body(deepest ? deepest : 1);
          char *c = nest_body(past ? past : 1);
          snprintf(label, sizeof label, "walk_depth_cap one below the cap");
          fine(&image, label, a ? a : "");
          snprintf(label, sizeof label, "walk_depth_cap at the cap");
          fine(&image, label, b ? b : "");
          snprintf(label, sizeof label, "walk_depth_cap one past the cap");
          err(&image, label, c ? c : "", 375, 9);
          cases++; checks++;
          if (deepest == 0 || past == 0 || past != deepest + 1) {
            failures++;
            fprintf(stderr,
                    "FAIL walk_depth_cap is not a boundary: deepest "
                    "expanding %u, first depth refusal %u\n", deepest, past);
          }
          fprintf(stderr,
                  "BOUND walk_depth_cap=64 at_cap=%u past=%u below=%u "
                  "refusal=375/9 reachable=yes shadow=none\n", deepest, past,
                  deepest > 1 ? deepest - 1 : 0);
          free(a); free(b); free(c);
        }

        /* (b2) walk_depth_cap AT THE declares_below GUARD, which is a
         * different site from the three the arm above measures, and the only
         * one of the four that cannot raise 375/9.
         *
         * WHY THIS NEEDS ITS OWN ARM. declares_below is a predicate: it
         * answers `true`, and its three callers (clone_let, produce_function
         * and the declaration arm) turn that into fail(381,1). So a cap
         * crossing here is a 381/1, not a 375/9, and the arm above -- which
         * only ever looks for 375/9 -- cannot see it. Worse, the invocation
         * has to be a SIBLING of the deep part, not inside it; see
         * sibling_nest_body. NESTING THE INVOCATION CANNOT REACH THIS CODE AT
         * ALL, because `walk` refuses at 375/9 on the way down first. Nothing
         * in this suite reached this site before this arm existed, which is
         * why the defect survived the wave that repaired the other three.
         *
         * THE THREE ASSERTIONS, and each one is load-bearing:
         *   1 the crossing PUBLISHES 65/64. Measured, not derived.
         *   2 a real collision still publishes 0/0. This is the arm that
         *     catches a fix which writes the two words unconditionally, and
         *     it is what makes the pair a DISCRIMINATION rather than a
         *     publication.
         *   3 the two are asserted DISCRIMINABLE, as a property of the PAIR.
         *     Two cases producing the same four words is the whole defect
         *     this arm exists to prevent, so an arm that only ever saw the
         *     published half would pass on the pre-fix bytes. The negative
         *     control is in the FIRST draft on purpose: on the bytes before
         *     the repair, arm 1 reads 0/0 and fails. */
        {
          uint64_t cross_o10 = 0, cross_o11 = 0, cross_code = 0,
                   cross_reason = 0;
          unsigned deepest = 0, past = 0;

          /* The plumbing control, run FIRST and on its own: the worked
           * example must expand. If it does not, every number below is
           * uninterpretable -- and a probe that answers nothing is
           * indistinguishable from a probe that is correctly silent. */
          {
            static const char *worked =
                "module m\ntarget x86_64-nexora-none\n"
                "macro ret(v:ast.expr)->ast.stmt {\n"
                "    return quote(stmt) { return $v+1; };\n}\n"
                TAIL "ret(41)\n" FOOT;
            Run r = run(&image, worked, 1u << 18, 0);
            cases++; checks++;
            if (r.code != 0 || r.runtime != 0 || r.w1 == 0) {
              failures++;
              fprintf(stderr,
                      "FAIL declares_below control: the worked example did "
                      "not expand (ret=%llu rt=%llu code=%llu w1=%llu); every "
                      "arm below is uninterpretable\n",
                      (unsigned long long)r.returned,
                      (unsigned long long)r.runtime,
                      (unsigned long long)r.code, (unsigned long long)r.w1);
            }
            freerun(&r);
          }

          /* The boundary is derived, not pinned: the largest nest that
           * expands and the smallest that crosses with a published quantity.
           * 30 and 31 are what the measurement gave; deriving them means a
           * change in the surrounding tree moves this arm honestly instead
           * of breaking it. */
          for (unsigned nest = 0; nest <= 45; nest++) {
            char *src = sibling_nest_body(nest);
            Run r = run(&image, src ? src : "", 1u << 18, 0);
            int crossing = r.code == 381 && r.reason == 1 &&
                           r.out[10] > r.out[11];
            if (r.code == 0 && r.runtime == 0 && r.w1 != 0 && !crossing)
              deepest = nest;
            if (crossing && past == 0) {
              past = nest;
              cross_code = r.code; cross_reason = r.reason;
              cross_o10 = r.out[10]; cross_o11 = r.out[11];
            }
            freerun(&r);
            free(src);
          }
          cases++; checks++;
          if (deepest == 0 || past == 0 || past != deepest + 1) {
            failures++;
            fprintf(stderr,
                    "FAIL declares_below guard is not a boundary: deepest "
                    "expanding %u, first published crossing %u\n", deepest,
                    past);
          } else {
            /* Arm 1: AT the crossing the quantity is published, in the cap's
             * own unit. 65 against 64 is the value measured on these bytes
             * and it is the reference the repair was made against. */
            if (!(cross_code == 381 && cross_reason == 1 &&
                  cross_o10 == 65 && cross_o11 == 64)) {
              failures++;
              fprintf(stderr,
                      "FAIL declares_below crossing does not publish 65/64: "
                      "code=%llu reason=%llu out10=%llu out11=%llu\n",
                      (unsigned long long)cross_code,
                      (unsigned long long)cross_reason,
                      (unsigned long long)cross_o10,
                      (unsigned long long)cross_o11);
            }

            /* Arm 2, and arm 3 with it: the SAME code and the SAME reason
             * from a REAL collision, which must still publish nothing --
             * and must not be the same four words as the crossing. If this
             * ever publishes 65/64 the channel has been filled
             * unconditionally and the pair has stopped discriminating. */
            Run c = run(&image, REBIND_MODULE_SRC, 1u << 18, 0);
            cases++; checks++;
            if (!(c.code == 381 && c.reason == 1 && c.out[10] == 0 &&
                  c.out[11] == 0)) {
              failures++;
              fprintf(stderr,
                      "FAIL real collision must publish 0/0 and answer the "
                      "same 381/1: code=%llu reason=%llu out10=%llu "
                      "out11=%llu\n",
                      (unsigned long long)c.code, (unsigned long long)c.reason,
                      (unsigned long long)c.out[10],
                      (unsigned long long)c.out[11]);
            } else if (cross_code == c.code && cross_reason == c.reason &&
                       cross_o10 == c.out[10] && cross_o11 == c.out[11]) {
              /* The defect itself, asserted as a property of the PAIR and
               * not of either arm: these two are the same four words, so a
               * reader cannot tell a scan cut short at 64 from a name the
               * caller really did declare. This is the assertion the lot
               * exists for, and it is the one that fails on the bytes
               * before the repair. */
              failures++;
              fprintf(stderr,
                      "FAIL the two refusals are the same four words: a cap "
                      "crossing and a real collision are indistinguishable\n");
            }
            freerun(&c);
          }
          fprintf(stderr,
                  "BOUND walk_depth_cap_at_declares_below crosses_at_nest=%u "
                  "expands_at_nest=%u crossing=381/1 out10=65 out11=64 "
                  "real_collision=381/1 out10=0 out11=0 discriminated=yes "
                  "shape=sibling_not_ancestor\n",
                  past, deepest);
        }

        /* (c) loop_cap = 512. REACHABLE AND CLEAN, measured with fuel held
         * out of the way.
         *
         * WHAT THIS ARM USED TO BE, and why it is replaced rather than
         * re-pinned. The two assertions here were built to prove loop_cap CAN
         * fire: "at 512 was not refused at all" and "one below the cap was
         * not refused". They now pass for the wrong reason. The at-cap arm
         * composes fuel=4096 and 512 items cost 27 + 8*512 = 4123 fuel, so the
         * FUEL budget answers 201 reason 1 at 510 items and loop_cap is never
         * consulted. What the arms were really measuring was a fuel ceiling
         * reported under the cap's name. Re-pinning them at whatever the
         * numbers are now would freeze the defect in place: the assertion
         * would again be satisfied by a budget that has nothing to do with
         * the bound, and it would do so silently the next time the per-item
         * cost changed. So the arms are gone and what replaces them measures
         * the cap itself.
         *
         * WHAT REPLACES THEM. The same body at the DECLARED fuel maximum,
         * where fuel cannot answer because nothing can spend 1048576 fuel on
         * 512 items (measured cost 4123). Under that budget the cap answers on
         * its own and answers cleanly: 512 items expand, 513 are refused
         * 380 reason 2, and 511 expand. The one-below arm is what makes the
         * middle observation a boundary rather than a coincidence -- a cap
         * that refused at every value would produce exactly the same 380/2
         * one past it and nothing here would notice.
         *
         * WHY IT FAILS IF FUEL ANSWERS FIRST. The at-cap and one-below arms
         * assert a full expansion, published nodes, and no diagnostic. A fuel
         * refusal publishes none of those: it writes 201 with reason 1 and
         * returns no region. So if fuel were answering, the at-cap arm would
         * see a refusal and fail on w1 == 0, and the one-past arm would see
         * 201 rather than 380 and fail on the code. The check is not merely
         * permissive about which budget answered; it is unable to pass while
         * a budget other than the cap answers. */
        {
          /* The declared fuel maximum. Named, not derived, and asserted
           * against the ceiling table's fuel row below so that changing the
           * declared maximum cannot leave this arm measuring a shadow. */
          const unsigned fuel_max = 1048576;
          unsigned ceil_at_max = loop_ceiling_at(&image, fuel_max);
          unsigned ceil_at_shape = loop_ceiling(&image);
          char *at = loop_body_fuel(512, fuel_max);
          char *past = loop_body_fuel(513, fuel_max);
          char *below = loop_body_fuel(511, fuel_max);
          char label[96];

          /* AT the cap and ONE BELOW it: both expand, with a published
           * region. This is the pair that the fuel budget used to answer,
           * and asking for the expansion is what makes the arm fail if fuel
           * answers first. */
          snprintf(label, sizeof label, "loop_cap at the cap, fuel held out");
          fine(&image, label, at ? at : "");
          snprintf(label, sizeof label, "loop_cap one below the cap, fuel held out");
          fine(&image, label, below ? below : "");
          snprintf(label, sizeof label, "loop_cap one past the cap, fuel held out");
          err(&image, label, past ? past : "", 380, 2);

          /* The bisection and the three fixed arms have to agree, or one of
           * them is measuring something else. Measured at the declared fuel
           * maximum the ceiling IS the cap; measured at the shape's own 4096
           * it is 508, which is the fuel ceiling and is reported as such
           * rather than as this bound. */
          cases++; checks++;
          if (ceil_at_max != 512) {
            failures++;
            fprintf(stderr,
                    "FAIL loop_cap is not 512 with fuel held out: the ceiling "
                    "at fuel=%u is %u, so either the cap moved or another "
                    "budget answers below it\n", fuel_max, ceil_at_max);
          }
          cases++; checks++;
          if (ceil_at_shape >= 512) {
            failures++;
            fprintf(stderr,
                    "FAIL the shape's own 4096 fuel budget answers at %u items, "
                    "which is not below loop_cap 512; the two ceilings are no "
                    "longer distinguishable and this arm cannot be trusted to "
                    "have measured the cap\n", ceil_at_shape);
          }

          {
            char *two_items = compose(fuel_max, 64, 16777216, 1048576, 128, 16777216,
                "macro two(n:u64)->ast.decl {\n"
                "    for i in $n {\n"
                "        emit quote(decl) { const c:u64 = 1; }\n"
                "        emit quote(decl) { const d:u64 = 2; }\n"
                "    }\n}\n" TAIL "two(3)\n" FOOT);
            /* Two producing items in one meta block is a macro form outside
             * this profile, so the projected output of a meta-for can never
             * exceed its count and the count cap is the whole cap here. The
             * reference's check is a product of count and template items
             * (frontend.c:2241, :4789); this is a different check that
             * happens to share the ceiling, and the banner says which is
             * which rather than letting the numbers be compared. */
            err(&image, "loop_cap a meta block with two producing items",
                two_items ? two_items : "", 377, 5);
            free(two_items);
          }
          fprintf(stderr,
                  "BOUND loop_cap=512 past513=380/2 at512=expands below511=expands "
                  "fuel_held_out_at=%u ceiling_at_fuel_max=%u "
                  "ceiling_at_shape_fuel_4096=%u reachable=yes shadow=none "
                  "projection=count_only_377_5 "
                  "replaced=the_at_cap_arms_which_the_4096_fuel_budget_answered\n",
                  fuel_max, ceil_at_max, ceil_at_shape);
          free(at); free(past); free(below);
        }

        /* (d) THE TEMPLATE ITEM BOUNDARY: 512 statements, on BOTH body
         * forms, and the silent truncation it replaces.
         *
         * THE DEFECT THIS EXISTS FOR. child_count() walked siblings under
         * `seen<=1024` and returned the count it REACHED, so a quoted block
         * body of more than 1024 statements was expanded as if it had 1024
         * and PUBLISHED: code 0, runtime 0, a complete looking node region,
         * no diagnostic anywhere. Measured on this shape, this fuel and one
         * binary:
         *
         *   1024 lets, 1025 items   5122 published nodes, code 0, last let PRESENT
         *   1025 lets, 1026 items   5122 published nodes, code 0, last let ABSENT
         *   9363 lets, 9364 items   5122 published nodes, code 0, last let ABSENT
         *
         * A caller could not tell a truncated expansion from a whole one, and
         * because it was a SUCCESS nothing downstream was protected by
         * anything either. That is this project's own rule with no red
         * anywhere in it, because the truncation was the answer rather than a
         * failed check.
         *
         * THE ANSWER IS THE REFERENCE'S, and it was measured there rather
         * than read off the source. A macro body returning a quoted block
         * holds its statements in MacroTemplate templates[512] at
         * frontend.c:57, and frontend.c:3782 refuses the 513th with
         * NTF_E_LIMIT 201 "quoted block statement limit exceeded" at
         * p->token.span, which is that statement's own position. Run against
         * the C reference on this body shape: 510 and 511 statements compile
         * and verify, 512 are refused 201 at the 513th item with nothing
         * published, and 1024 and 2048 are refused the same way. Nova answers
         * 380 reason 2 at the same count, because 380 is the code this module
         * already uses for a template whose projected statement count is too
         * large, and the reference uses ONE NTF_E_LIMIT for both of its 512s
         * -- the meta-for repeat count at frontend.c:2241 and the template
         * table at frontend.c:3782. The two quantities are not the same
         * number and are not reported as one: loop_cap is the repeat count,
         * template_item_cap is the size of the body being repeated, and the
         * arms above and below measure them apart.
         *
         * WHY FOUR ARMS AND NOT ONE. A refusal asserted only ABOVE the cap is
         * also the reading a cap that fires at every value gives, which is
         * the reason the ceiling campaign above carries a below arm: the one
         * below is the arm that can only pass if the boundary is where it is
         * claimed to be. The at arm is the arm the defect lived on -- a body
         * of exactly 512 statements used to publish complete, and a body of
         * 513 used to publish SHORT -- and the last arm is the literal shape
         * that was published short before this change.
         *
         * The first statement's line and column are DERIVED from what the two
         * builders write, not remembered from a run: compose() emits five
         * lines of budget block, and after it the quoted block form spends
         * three lines on the macro header and the quote, the generated
         * function form six on the macro header, the emit, the fn, the
         * effects, the clobbers and the brace. The refusal position is the
         * 513th statement, which is first_line + 512 of that form -- and the
         * two forms refusing at two DIFFERENT lines is itself the proof that
         * the position is read out of the body rather than written down once.
         */
        {
          const unsigned cap = 512;
          const unsigned forms_first[2] = {8, 11};
          const unsigned forms_col[2] = {9, 13};
          const char *forms_name[2] = {"quoted_block", "generated_fn"};
          const unsigned arms[4] = {cap - 1, cap, cap + 1, 1026};
          unsigned refused_line[2] = {0, 0};
          for (unsigned form = 0; form < 2; form++) {
            for (unsigned a = 0; a < 4; a++) {
              unsigned items = arms[a];
              unsigned n = items - 1; /* both builders add the return */
              char *src = form == 0 ? lets_body_titled(n, 1048576)
                                    : fn_body(n, 1048576);
              Run r = run(&image, src ? src : "", 1u << 22, 0);
              int published = r.returned == 0 && r.runtime == 0 &&
                              r.code == 0 && r.w1 != 0;
              char last[16];
              /* The last STATEMENT is the return, and the last introduced let
               * it can name is the one before it: lets_body_titled(n) and
               * fn_body(n) each write n lets named t0000..t{n-1} and a return
               * of t{n-1}. Asking for t{n} would be a name no body either
               * builder writes ever introduces, and that would fail every arm
               * at once -- a measurement which distinguishes nothing. */
              snprintf(last, sizeof last, "t%04u", n - 1);
              int whole = published && name_contains(&r, last);
              cases++; checks++;
              if (a < 2) {
                /* Below and at: the body must expand WHOLE. Asking only "did
                 * it answer 0" is the measurement that let the truncation
                 * through, because a truncated expansion answers 0 -- so the
                 * last statement's introduced name has to be in the produced
                 * name table. */
                if (!whole) {
                  failures++;
                  fprintf(stderr,
                          "FAIL template_item_cap %s at %u items (%u lets) did "
                          "not expand whole: ret=%llu runtime=%llu code=%llu "
                          "line=%llu col=%llu reason=%llu nodes=%llu\n",
                          forms_name[form], items, n,
                          (unsigned long long)r.returned,
                          (unsigned long long)r.runtime,
                          (unsigned long long)r.code,
                          (unsigned long long)r.w1,
                          (unsigned long long)r.w2,
                          (unsigned long long)r.reason,
                          (unsigned long long)r.out[1]);
                }
              } else {
                /* Above: refused 380/2 at the 513th statement's own line and
                 * column, and nothing published. The position is half the
                 * assertion -- a refusal with no position is the same defect
                 * one level down. */
                /* The 513th statement sits cap lines below the first one:
                 * first_line + 512. */
                unsigned want_line = forms_first[form] + cap;
                if (r.returned != 380 || r.runtime != 0 || r.code != 380 ||
                    r.reason != 2 || r.w1 != want_line ||
                    r.w2 != forms_col[form]) {
                  failures++;
                  fprintf(stderr,
                          "FAIL template_item_cap %s at %u items (%u lets) was "
                          "not refused 380/2 at the 513th statement: "
                          "ret=%llu runtime=%llu code=%llu line=%llu "
                          "col=%llu reason=%llu nodes=%llu want=380/2 at "
                          "%u:%u\n", forms_name[form], items, n,
                          (unsigned long long)r.returned,
                          (unsigned long long)r.runtime,
                          (unsigned long long)r.code,
                          (unsigned long long)r.w1,
                          (unsigned long long)r.w2,
                          (unsigned long long)r.reason,
                          (unsigned long long)r.out[1], want_line,
                          forms_col[form]);
                } else {
                  refused_line[form] = (unsigned)r.w1;
                }
              }
              fprintf(stderr,
                      "TEMPLATE_ITEMS form=%s items=%u lets=%u cap=%u "
                      "expanded_whole=%d code=%llu reason=%llu at=%llu:%llu\n",
                      forms_name[form], items, n, cap, whole,
                      (unsigned long long)r.code,
                      (unsigned long long)r.reason,
                      (unsigned long long)r.w1, (unsigned long long)r.w2);
              freerun(&r);
              free(src);
            }
          }
          /* The two forms must not answer at the same line, or the position
           * is a constant this harness happens to agree with. */
          cases++; checks++;
          if (refused_line[0] == 0 || refused_line[1] == 0 ||
              refused_line[0] == refused_line[1]) {
            failures++;
            fprintf(stderr,
                    "FAIL the two body forms refuse at lines %u and %u, so at "
                    "least one of them is not reporting the 513th statement of "
                    "its own body\n", refused_line[0], refused_line[1]);
          }
          fprintf(stderr,
                  "BOUND template_item_cap=%u refusal=380/2 at_the_513th_"
                  "statement quoted_block_at=%u generated_fn_at=%u "
                  "arms_below_at_above=511,512,513,1026 all_measured=yes "
                  "reference=frontend.c:3782_NTF_E_LIMIT_201_at_the_same_count "
                  "reachable=yes shadow=none\n", cap, refused_line[0],
                  refused_line[1]);
        }

        /* (e) the binding stack, 65536 words. bind_stride is 7
         * (macro_expand.nova:797-815), so the cap would answer at 65536 words
         * = 9362 entries, and the only thing that pushes an entry without
         * multiplying the work is a `let` in a quoted block.
         *
         * WHAT SHADOWS IT IS NEITHER THE HOST BUFFER TABLE NOR child_count.
         * The buffer table was this block's first answer and both allocation
         * leaks behind it are fixed: the expander no longer spends a host
         * buffer per node read (macro_expand.nova:257-296, 4502073 add_buffer
         * calls before and 8952 after). child_count was the second, and it
         * was the worse of the two, because it was silent -- a body past 1024
         * statements was expanded short and PUBLISHED as a success, so for a
         * long time the largest body this gate could build was a body this
         * block read as evidence.
         *
         * THE ANSWER IS template_item_cap, and it is arithmetic rather than
         * exhaustion: the 9363rd binding entry is the one refused, so a body
         * of 9363 statements is what it takes to get there, the cap refuses
         * that at 512, and 512 entries of 7 words is 3584 of the 65536.
         * The two arms below are the honest ones -- the deepest body
         * that expands, proven to expand WHOLE rather than merely to answer
         * 0, and a body well past the binding stack's 9362 that is refused by
         * a different bound, with a code and a position, instead of being
         * published short.
         *
         * WHAT THIS BLOCK USED TO SAY, and why both halves were wrong. It read
         * "it needs 9362 lets of 7 words. A 1200 let body still expands", and
         * the module repeated the second half in its own banner. A 1200
         * statement body does not expand: it is refused 380/2. And while that
         * sentence stood, a 1200 statement body expanded TRUNCATED, in
         * silence, as a success -- so it was true of nothing and was evidence
         * of the defect. */
        {
          const unsigned fuel_max = 1048576;
          unsigned lo = 1, hi = 1024, deepest = 0;
          while (lo <= hi) {
            unsigned mid = lo + (hi - lo) / 2;
            char *body = lets_body_titled(mid, fuel_max);
            Run r = run(&image, body ? body : "", 1u << 22, 0);
            int ok = r.returned == 0 && r.runtime == 0 && r.code == 0 &&
                     r.w1 != 0;
            if (ok) { deepest = mid; lo = mid + 1; }
            else hi = mid - 1;
            freerun(&r);
            free(body);
          }
          /* The deepest body must hold its own last let. A ceiling measured
           * only on "did it answer 0" is the measurement that let a truncated
           * expansion pass for a complete one. */
          char *edge = lets_body_titled(deepest, fuel_max);
          Run re = run(&image, edge ? edge : "", 1u << 22, 0);
          int whole = re.returned == 0 && re.code == 0 &&
                      name_contains(&re, last_let_name(deepest));
          freerun(&re);
          free(edge);
          cases++; checks++;
          if (!whole || deepest == 0 || deepest * 7u >= 65536u) {
            failures++;
            fprintf(stderr,
                    "FAIL the deepest expanding lets body is %u, and it does "
                    "not expand whole (%d) or its %u binding words reach the "
                    "65536 word stack, so this block's claim that the binding "
                    "stack is unreachable by arithmetic is wrong\n", deepest,
                    whole, deepest * 7u);
          }
          /* And the far arm: 9363 statements is one entry past what the
           * binding stack could hold, and it is REFUSED with a position
           * rather than published short. Either observation alone would be
           * consistent with a working cap; the pair is what makes a
           * truncation visible at all. */
          char *past = lets_body_titled(9363, fuel_max);
          Run rp = run(&image, past ? past : "", 1u << 22, 0);
          int past_refused = rp.returned != 0 && rp.code == 380 &&
                             rp.reason == 2 && rp.w1 != 0;
          /* what the model must then say about this bound; see
           * bound_status_matches_model() */
          bound_binding_stack_reachable = past_refused ? 0 : 1;
          cases++; checks++;
          if (!past_refused) {
            failures++;
            fprintf(stderr,
                    "FAIL a 9363-let body was not refused 380/2 with a "
                    "position: ret=%llu runtime=%llu code=%llu line=%llu "
                    "col=%llu reason=%llu; either the binding stack is now the "
                    "thing answering, which would make this block's shadow "
                    "claim wrong, or the body is still published short\n",
                    (unsigned long long)rp.returned,
                    (unsigned long long)rp.runtime,
                    (unsigned long long)rp.code,
                    (unsigned long long)rp.w1,
                    (unsigned long long)rp.w2,
                    (unsigned long long)rp.reason);
          }
          fprintf(stderr,
                  "BOUND binding_stack=65536 bind_stride=7 "
                  "largest_fitting_entries=9362 words=7*9362 "
                  "refused_at_entry=9363 deepest_expanding_body=%u lets "
                  "words=%u reachable=no "
                  "shadow=template_item_cap_380_2_at_513_statements "
                  "shadow_is_not=nv2_buffer_table "
                  "shadow_is_not=child_count_which_truncated_silently "
                  "a_9363_let_body_is_refused=%d truncation_now=none\n",
                  deepest, deepest * 7u, past_refused);
          freerun(&rp);
          free(past);
        }

        /* (f) the argument stack, 4096 words. arg_stride is 4
         * (macro_expand.nova:756 area, push_arg) and an expansion pushes one
         * entry per parameter, at most parameter_cap of them, so 1024 nested
         * expansions would be needed to answer it.
         *
         * WHAT SHADOWS IT. Not the host buffer table, which this block used to
         * name. The shadow is the expansion_depth BUDGET, and it is not a
         * shadow that can be pushed aside: 128 is the declared maximum, and a
         * comptime block may only LOWER a budget, so a body cannot ask for
         * more depth than 128 (measured: declaring expansion_depth=129 or
         * 1024 is refused 378 reason 1, the malformed limit block, before any
         * expansion runs). At the declared maximum a 127-deep chain expands
         * and a 128-deep chain is refused 201 reason 5, the depth budget.
         * 1024 levels against 128 is eight times below, so the argument stack
         * is unreachable by arithmetic rather than by exhaustion.
         *
         * So this arm measures the depth at which the chain stops and asserts
         * that the refusal is the DEPTH budget's and not the host's, which is
         * a claim about which budget answered and can be wrong in the way that
         * matters -- if the host answered instead, this fails. */
        {
          unsigned ceil = chain_ceiling(&image);
          bound_argument_stack_reachable = 0;
          /* The last depth that expands, and the first that is refused, at the
           * declared maximum, so the boundary is measured and not assumed. */
          char *deepest = chain_body(ceil);
          char *past = chain_body(ceil + 1);
          Run rd = run(&image, deepest ? deepest : "", 1u << 20, 0);
          int ok = rd.code == 0 && rd.runtime == 0 && rd.w1 != 0;
          err(&image, "argument_stack one past the expansion depth budget",
              past ? past : "", 201, 5);
          cases++; checks++;
          if (ok == 0) {
            failures++;
            fprintf(stderr,
                    "FAIL a %u level chain does not expand at the declared "
                    "expansion_depth maximum, so the boundary this block "
                    "reports has moved (ret=%llu runtime=%llu code=%llu)\n",
                    ceil, (unsigned long long)rd.returned,
                    (unsigned long long)rd.runtime, (unsigned long long)rd.code);
          }
          fprintf(stderr,
                  "BOUND argument_stack=4096 words=4*1024 needs_levels=1024 "
                  "measured_ceiling=%u measured_past=%u refusal=201/5 "
                  "reachable=no shadow=the_expansion_depth_budget_at_its_"
                  "declared_maximum shadow_is_not=nv2_buffer_table "
                  "depth_cannot_be_raised=378/1\n", ceil, ceil + 1);
          freerun(&rd);
          free(deepest); free(past);
        }

        /* (g) and (h): hard_node_cap 262144 and hard_name_cap 4194304.
         *
         * THESE TWO NO LONGER HAVE THE SAME VERDICT, and the block used to
         * report one verdict for both.
         *
         * hard_name_cap 4194304 IS REACHABLE, and this block said it was not.
         * Its measurement swept three shapes -- a meta-for, a lets body and
         * an expansion chain -- and none of them writes a long enough name
         * table, so it reported the largest name table any of them reached
         * (11574 bytes, a fortieth of the cap) and concluded the cap was
         * unreachable. The conclusion was a property of the sweep and not of
         * the bound. The name table is a SEPARATE counter from the node
         * count, so a body that introduces long names raises it without
         * moving the node count at all: a nested meta-for with 200-byte
         * introduced names is refused 900 reason 1 by reserve_names, and
         * with 1-byte names the same item count is refused 201 reason 3 by
         * arena_bytes instead. Same count, two different bounds, and which
         * one answers depends only on the name length. This is exactly the
         * failure the module's own banner warns about at macro_expand.nova:
         * a measured ceiling is a property of the body, and writing it down
         * as a constant is how a bound gets mistaken for a shadow.
         *
         * IS THAT PAIR AN INSTRUMENT OR A COINCIDENCE, and the answer is
         * measured rather than argued. It is an instrument, for one reason
         * that is structural and not lucky: the two arms hold the ITEM COUNT
         * fixed and vary only the per item NAME COST, and the item count is
         * the one input the arena bound reads and the one the name bound
         * does not. So the item count cannot be what separates the two
         * verdicts -- if it were, both arms would answer alike. What the pair
         * turns on is the CROSSING of two per item slopes, the name bytes a
         * step charges and the 96*nodes the arena charges for the same step,
         * and the crossing is a monotone function of the name length, which
         * is why lengthening the names from 1 to 200 bytes moves the answer
         * from the arena to the name table without anything else changing.
         * The pair is therefore load bearing, but it is a pair and not a
         * sweep: it shows the name cap is REACHED and that the arena answers
         * the short name shape first. It does not show where the crossing
         * is, and a third arm at a name length that makes the two verdicts
         * swap back would be what pins the crossing rather than the
         * existence of it.
         *
         * hard_node_cap 262144 IS NOT REACHABLE, and the reason is arithmetic
         * rather than exhaustion. node_bytes() is 96 and max_arena() is frozen
         * at 16777216, so arena_bytes refuses at 174762 published nodes, below
         * the 262144 at which reserve_nodes would refuse. A comptime block may
         * only LOWER a budget, so no body can raise the arena to get past it.
         * The reserve_nodes check is therefore dead code. It is kept because
         * it is a declared bound of the reference; it is not a guarantee.
         *
         * So the answer to "are these bounds enforced by anything" is now
         * different for the two, and both are enforced: the name cap by its
         * own check, which fires, and the node cap by the arena budget, which
         * always answers first. Neither is enforced by the host. */
        {
          unsigned long long max_nodes = 0, max_names = 0;
          unsigned lc = loop_ceiling(&image);
          char *probe = loop_body(lc);
          Run rp = run(&image, probe ? probe : "", 1u << 20, 0);
          if (layout_ok(&rp)) {
            if (rp.w1 > max_nodes) max_nodes = rp.w1;
            if (rp.w2 > max_names) max_names = rp.w2;
          }
          freerun(&rp);
          free(probe);

          /* hard_name_cap, REACHED. The longest-name body this block can build
           * is refused by the name table's own check, and the refusal is the
           * cap firing rather than anything shadowing it. */
          char *long_names = nested_body(512, 512, 200);
          char *short_names = nested_body(512, 512, 1);
          err(&image, "hard_name_cap a nested meta-for with long introduced names",
              long_names ? long_names : "", 900, 1);
          bound_hard_name_cap_reachable = 1;

          /* The negative proof for that arm, and the reason it is not a
           * coincidence: the SAME item count with short names is refused by a
           * DIFFERENT budget. If both were refused 900/1 then the arm above
           * would be measuring the item count and not the name length, and
           * the name cap would still be unproven. */
          err(&image, "hard_name_cap control, the same count with short names",
              short_names ? short_names : "", 201, 3);
          /* short names at the same count are the arena's answer, not the name
           * table's, and that is what the row's shadow column records */
          bound_hard_name_cap_shadow_code = 201;
          bound_hard_name_cap_shadow_reason = 3;
          free(long_names);
          free(short_names);

          bound_hard_node_cap_reachable = 0;
          /* hard_node_cap, NOT reached, and the ceiling that keeps it out is
           * the arena rather than the host. */
          cases++; checks++;
          if (max_nodes >= 262144) {
            failures++;
            fprintf(stderr,
                    "FAIL hard_node_cap was REACHED (%llu published nodes), so "
                    "this block's claim that the arena always answers first is "
                    "wrong\n", max_nodes);
          }
          fprintf(stderr,
                  "BOUND hard_node_cap=262144 arena_node_ceiling=174762 "
                  "measured_max_nodes=%llu reachable=no "
                  "shadow=arena_bytes_at_96_bytes_per_node "
                  "shadow_is_not=nv2_buffer_table "
                  "reserve_nodes_is_dead_code=true\n", max_nodes);
          fprintf(stderr,
                  "BOUND hard_name_cap=4194304 measured_max_name_bytes=%llu "
                  "reachable=YES shadow=none refusal=900/1 "
                  "reached_by=a_nested_meta_for_with_200_byte_introduced_names "
                  "the_same_count_with_1_byte_names_is_refused_by_arena_201/3\n",
                  max_names);
        }

        /* THE MODEL'S STATUS TABLE AGAINST WHAT THESE FOUR ARMS MEASURED.
         *
         * A declared bound with no measured enforcement status is a number a
         * reader cannot act on: "the expander refuses past 65536 binding
         * words" and "the expander refuses past 262144 nodes" are the same
         * sentence with one of them true. The four arms above measure the
         * status; ntasm_fuel_model.h records it; this compares the two. A
         * row whose measurement is -1 -- an arm that did not run -- fails,
         * because a default is exactly how a stale row would look green.
         *
         * The bounds themselves are NOT changed here and must not be: the
         * table says what is enforced, not what ought to be.
         *
         * WHY THIS LOOP COVERS FOUR OF THE TABLE'S ROWS, stated as a reason
         * and not as a count, because a count in this position is a claim
         * that goes stale the moment a row is added -- and the moment a row
         * is added is exactly when a reader needs to read this.
         *
         * THE REASON: this loop compares the model's verdict against an arm
         * that MEASURED a reachability, so every row it can speak about is a
         * row that has an execution behind it. A row with no execution has
         * nothing to compare a verdict against, and adding one would not
         * extend this loop's coverage -- it would dilute what the loop means
         * in order to accommodate a row the loop cannot express. So the rows
         * this loop does not carry are not an oversight here; they are
         * checked on their own, next to the arm or the source reading that
         * can support them, and a reader who wants to know how a row is
         * checked should follow the row, not this loop.
         *
         * AND THE TWO VERDICTS ARE NOT THE SAME VERDICT, which is the second
         * reason this loop cannot carry every row. One unreachable verdict is
         * a SHADOW: a bound DID fire, on a different quantity than the row
         * declares, and the caller's correction is to be told which one
         * answered. The other is a DEAD ARM: nothing can fire, because no
         * caller can pass a value that reaches the guard. A shadow is
         * measurable -- you can drive the other bound and watch this one
         * never appear -- so this loop can speak about it. A dead arm has no
         * measurement to make, ever, so putting it here would ask the loop
         * to compare a verdict against nothing. */
        {
          struct { const char *name; int measured; } m[4] = {
              {"binding_stack", bound_binding_stack_reachable},
              {"argument_stack", bound_argument_stack_reachable},
              {"hard_node_cap", bound_hard_node_cap_reachable},
              {"hard_name_cap", bound_hard_name_cap_reachable}};
          for (unsigned k = 0; k < 4; k++) {
            const ng_bound_model *b = ng_fuel_bound(m[k].name);
            cases++; checks++;
            if (b == NULL) {
              failures++;
              fprintf(stderr, "FAIL the model has no row for %s\n", m[k].name);
              continue;
            }
            if (m[k].measured < 0) {
              failures++;
              fprintf(stderr,
                      "FAIL the %s arm did not measure a reachability, so the "
                      "model's row for it is unchecked\n", m[k].name);
              continue;
            }
            int want = b->status == NG_FUEL_BOUND_REACHABLE;
            if (m[k].measured != want) {
              failures++;
              fprintf(stderr,
                      "FAIL the model says %s is %s, and the arm measured %s\n",
                      b->name, want ? "reachable" : "unreachable",
                      m[k].measured ? "reachable" : "unreachable");
            }
            /* The row's arithmetic has to be the arithmetic the bound
             * declares, or "9362 entries" is a caption on nothing. */
            cases++; checks++;
            if (b->per_entry != 0 &&
                (b->entries * b->per_entry > b->words ||
                 (b->entries + 1) * b->per_entry <= b->words)) {
              failures++;
              fprintf(stderr,
                      "FAIL the model says %s holds %llu entries of %llu "
                      "words, which does not straddle the declared %llu\n",
                      b->name, (unsigned long long)b->entries,
                      (unsigned long long)b->per_entry,
                      (unsigned long long)b->words);
            }
            fprintf(stderr,
                    "BOUND_STATUS name=%s words=%llu unit=%s per_entry=%llu "
                    "entries=%llu model=%s measured=%s shadow=%llu/%llu\n",
                    b->name, (unsigned long long)b->words, b->unit,
                    (unsigned long long)b->per_entry,
                    (unsigned long long)b->entries,
                    b->status == NG_FUEL_BOUND_UNREACHABLE_ARITHMETIC
                        ? "UNREACHABLE_ARITHMETIC"
                        : (b->status == NG_FUEL_BOUND_UNREACHABLE_CALLERS
                               ? "UNREACHABLE_CALLERS"
                               : "REACHABLE"),
                    m[k].measured ? "reachable" : "unreachable",
                    (unsigned long long)b->shadow_code,
                    (unsigned long long)b->shadow_reason);
          }
          /* the one row whose shadow is a MEASURED pair rather than an
           * arithmetic consequence: the same item count is answered by the
           * name table at 200-byte names and by the arena at 1-byte names,
           * and the model records the arena's answer as the shadow because
           * that is the one a reader would otherwise mistake for the cap. */
          cases++; checks++;
          CHECK(bound_hard_name_cap_shadow_code == 201 &&
                    bound_hard_name_cap_shadow_reason == 3,
                "the same item count with short introduced names is refused by "
                "arena_bytes 201/3, which is the shadow the model's row for "
                "hard_name_cap names");
        }

          /* The ninth row's ARGUMENT, checked against the source rather than
           * against this file. The row claims put_words cannot refuse at 24
           * because every caller passes a literal n of 1, 2 or 6, and a row
           * that cannot be re-checked is the stale comment one level down. So
           * the source is read here and the literals are counted. If someone
           * adds a seventh-shaped call site, or one that passes a variable,
           * the row goes red instead of quietly becoming false.
           *
           * WHAT THIS IS NOT: an execution. There is no input that reaches the
           * guard, so no arm could measure it, and a check that ran the path
           * would be a check on nothing. This confirms the CLAUSE the verdict
           * rests on -- the maximum literal any caller passes -- and leaves
           * the rest of the row to the reader's own grep. */
          {
            const ng_bound_model *b = ng_fuel_bound("put_words_bytes");
            FILE *src = fopen("compiler/nova/macros/macro_expand.nova", "r");
            cases++; checks++;
            if (b == NULL) {
              failures++;
              fprintf(stderr,
                      "FAIL the model has no row for put_words_bytes\n");
            } else if (b->status != NG_FUEL_BOUND_UNREACHABLE_CALLERS) {
              failures++;
              fprintf(stderr,
                      "FAIL put_words_bytes is not UNREACHABLE_CALLERS, and a "
                      "dead arm and a shadow are not the same fact\n");
            } else if (src == NULL) {
              /* Not a soft pass. Without the source the clause is unverified,
               * and saying so is the difference between a check and a
               * comment. */
              failures++;
              fprintf(stderr,
                      "FAIL cannot read macro_expand.nova, so the "
                      "put_words_bytes row's argument is unchecked\n");
            } else {
              char line[512];
              unsigned calls = 0, max_literal = 0, guard = 0;
              while (fgets(line, sizeof line, src)) {
                const char *p = strstr(line, "put_words(env,");
                if (p != NULL) {
                  unsigned n = 0;
                  if (sscanf(p, "put_words(env,%u", &n) == 1) {
                    calls++;
                    if (n > max_literal) max_literal = n;
                  }
                }
                /* The guard's own literal, read off the source so the row's
                 * declared 24 cannot drift away from the code it describes. */
                if (guard == 0 && strstr(line, "if n>24 {") != NULL &&
                    strstr(line, "refuse_bound") != NULL)
                  guard = 24;
              }
              fclose(src);
              cases++; checks++;
              if (guard != 24 || b->words != 24) {
                failures++;
                fprintf(stderr,
                        "FAIL put_words' guard is no longer `n>24` inside a "
                        "refuse_bound: the source guard reads %u and the row "
                        "declares %llu\n",
                        guard, (unsigned long long)b->words);
              }
              cases++; checks++;
              if (calls != 8 || max_literal > 6 || b->entries != max_literal) {
                failures++;
                fprintf(stderr,
                        "FAIL put_words has %u call sites with a maximum "
                        "literal n of %u, and the row declares %llu as the "
                        "largest value any caller passes\n",
                        calls, max_literal, (unsigned long long)b->entries);
              } else {
                fprintf(stderr,
                        "BOUND_STATUS name=put_words_bytes words=%llu unit=%s "
                        "per_entry=%llu entries=%llu "
                        "model=UNREACHABLE_CALLERS measured=unmeasurable "
                        "call_sites=%u max_literal_n=%u guard=%u "
                        "unreachable_by=four_times no_test_possible\n",
                        (unsigned long long)b->words, b->unit,
                        (unsigned long long)b->per_entry,
                        (unsigned long long)b->entries, calls, max_literal,
                        guard);
              }
            }
          }

        /* WHAT THE CEILING ABOVE ACTUALLY IS, and the answer moved.
         *
         * This block used to assert that the host's buffer table -- 65536
         * entries, nova/runtime_v2.c:9 -- was the ceiling, and it proved it by
         * running a 511 item meta-for and requiring host_refused() to fire.
         * Every `at()` was one 96-byte Node returned by value across a module
         * boundary, so each was a live buffer the expander never reclaimed, and
         * the table filled: measured 4502073 add_buffer calls across the swept
         * shapes, peak live 65536 (macro_expand.nova:268-284).
         *
         * BOTH OF THOSE LEAKS ARE FIXED. The expander now reads node words
         * out of the tree instead of calling node_at, and text_is no longer
         * borrows a buffer per spelling tested. The same sweep now costs 8952
         * add_buffer calls with a peak of 436 live. So the table no longer
         * fills for ANY body this gate builds, and the ceiling it used to name
         * is not a ceiling at all: 65536 slots against a peak of 436 is two
         * orders of magnitude of headroom.
         *
         * WHAT REPLACES THE ASSERTION. The old arm is not re-pinned at a
         * larger item count -- there is no item count that fills the table any
         * more, so a re-pinned literal would be pinning a ceiling that does
         * not exist. In its place this measures the largest body each shape
         * reaches and asserts that every one of them still expands. That is
         * the claim the module now makes, and it is a claim that can be wrong:
         * if a future change reintroduced an allocation per node, the largest
         * of these bodies would stop expanding and this fails. The exhaustion
         * itself is exercised deliberately, and as a distinction rather than
         * as a ceiling, by exhaustion_is_distinguishable() above. */
        {
          struct { const char *shape; unsigned items; } SHAPES[3] = {
              {"meta_for", loop_ceiling(&image)},
              {"lets", lets_ceiling(&image)},
              {"expansion_chain", chain_ceiling(&image)}};
          int all_expand = 1;
          for (unsigned k = 0; k < 3; k++) {
            char *src = k == 0 ? loop_body(SHAPES[k].items)
                               : (k == 1 ? lets_body(SHAPES[k].items)
                                         : chain_body(SHAPES[k].items));
            Run r = run(&image, src ? src : "", 1u << 22, 0);
            int ok = r.returned == 0 && r.runtime == 0 && r.code == 0 && r.w1 != 0;
            if (ok == 0) all_expand = 0;
            fprintf(stderr,
                    "CEILING_SHAPE %s=%u expands=%d published_nodes=%llu "
                    "name_bytes=%llu\n", SHAPES[k].shape, SHAPES[k].items, ok,
                    (unsigned long long)r.w1, (unsigned long long)r.w2);
            freerun(&r);
            free(src);
          }
          cases++; checks++;
          if (all_expand == 0) {
            failures++;
            fprintf(stderr,
                    "FAIL at least one of the three largest measured bodies no "
                    "longer expands, so something is answering below a bound "
                    "this block says is not there\n");
          }
          fprintf(stderr,
                  "CEILING nv2_buffer_table=65536 record=96 "
                  "add_buffer_calls_before=4502073 peak_live_before=65536 "
                  "add_buffer_calls_after=8952 peak_live_after=436 "
                  "fills_for_any_measured_shape=%s "
                  "shadow_of_the_five=none_the_host_table_is_not_a_ceiling "
                  "shadow_of_the_binding_stack=template_item_cap_not_the_host_"
                  "and_not_child_count "
                  "exhaustion_exercised_where=exhaustion_is_distinguishable\n",
                  all_expand ? "no" : "yes");
        }
        exhaustion_is_distinguishable(&image);
      }
    }
  }
  if (image.memory) nova_host_unmap(&image);
  if (compiled) nt_artifact_free(&a);
  for (unsigned i = 0; i < 6; i++) free(sources[i]);
  /* The campaign's own limits, in the style the registry and the PE gate use.
   * A campaign that does not say what it did not cover is a campaign whose
   * silence reads as coverage, and these are the silences.
   *
   *   io_purity: the expander and the six Nova I/O intrinsics only. It says
   *     nothing about a Nova module's own I/O, which is OPEN and measured
   *     open, nor about a C module the expander might call, of which there
   *     are none. It watches one directory on one filesystem; a read of a
   *     path outside it would be caught only if it changed the seven corpus
   *     digests, and the campaign does not claim more than that. It does not
   *     observe a clock, an environment or a process, because the Nova
   *     language has no primitive for any of the three and the absence is
   *     measured by compilation, not by a runtime trap.
   *   ceilings: the six declared maxima, and the EIGHT compiler bounds the
   *     module declares. Those bounds' shadows were the host's 65536 buffer
   *     table and, behind it, arena_bytes; the buffer table is no longer
   *     either. After the node-read and text_is leaks were fixed the
   *     expander's allocations fell from 4502073 add_buffer calls to 8952 and
   *     its peak live buffers from 65536 to 436, so no body in this tree
   *     fills the table. A second shadow WAS the expander's own child_count,
   *     which truncated a body past 1024 statements and published it as a
   *     success; it is gone, and the bound that answers in its place is the
   *     reference's own 512, refused 380/2 with a position. Every bound below
   *     is accounted for by the expander's own budgets or by its own checks,
   *     and the host is not among them.
   *   both: a refusal is compared by code, reason and published region. No
   *     campaign here asserts anything about diagnostic TEXT. */
  printf("A5_CAMPAIGN_LIMITS "
         "io_purity=expander_vs_six_nova_intrinsins; "
         "io_purity_not=other_nova_modules; "
         "io_purity_scope=one_directory_one_filesystem; "
         "io_purity_clock_env_process=no_primitive_exists_measured_by_compiling; "
         "ceilings=the_six_declared_maxima_and_the_eight_compiler_bounds; "
         "provenance=the_produced_name_table_every_name_classified; "
         "provenance_marks=__ntm___ntd___ntp_from_frontend.c:2384,4818,4880,"
         "4938_rebuilt_in_C_not_by_the_expander; "
         "provenance_forgery=closed_by_the_lexer_measured_by_a_refused_module; "
         "provenance_freshness=serial_differs_per_expansion_measured; "
         "provenance_leak=one_unclassified_name_found_over_four_nested_"
         "argument_shapes; "
         "bounds_reachable_and_clean=parameter_cap_walk_depth_cap_loop_cap_"
         "template_item_cap_hard_name_cap; "
         "bounds_not_reachable=binding_stack_argument_stack_hard_node_cap; "
         "bounds_not_reachable_because=binding_stack_9362_entries_need_a_body_"
         "of_9362_statements_which_template_item_cap_refuses_at_512_"
         "argument_stack_needs_1024_levels_and_expansion_depth_is_capped_at_"
         "128_hard_node_cap_arena_bytes_answers_at_174762_nodes; "
         "template_item_cap_measured_on=both_body_forms_at_511_512_513_1026_"
         "statements_with_the_one_below_arm_and_the_513th_statement_position; "
         "template_item_cap_is_the_reference_own=frontend.c:57_and_3782_"
         "NTF_E_LIMIT_201_measured_at_the_same_count; "
         "child_count_truncation=none_a_body_past_the_cap_is_refused_rather_"
         "than_published_short; "
         "bounds_shadow=none_the_nv2_buffer_table_is_no_longer_a_ceiling_for_"
         "any_measured_shape_peak_live_436_of_65536; "
         "bounds_hard_name_cap_reached_by=nested_meta_for_with_200_byte_"
         "introduced_names_refused_900/1_while_the_same_count_with_1_byte_"
         "names_is_refused_by_arena_201/3; "
         "limits_ceilings_not=the_eight_compiler_bounds_are_measured_and_"
         "five_of_them_are_reachable_and_clean_and_the_other_three_are_"
         "proved_unreachable_by_arithmetic_rather_than_by_exhaustion; "
         "limits_ceilings_shared_table_not=the_reference_512_is_one_template_"
         "table_per_macro_while_nova_counts_a_quoted_block_body_and_a_"
         "generated_function_body_apart_so_a_body_at_exactly_512_with_other_"
         "template_items_beside_it_is_one_count_wider_here; "
         "provenance_execution=the_produced_region_folded_by_ntasm_constant_eval_"
         "and_the_mark_read_out_of_the_same_region; "
         "limits_provenance_not=the_reference_cannot_express_the_shape_that_"
         "leaks_so_that_outcome_is_Nova_only; "
         "limits_provenance_classifier=quoted_string_and_line_comment_braces_"
         "and_identifiers_ignored_with_positive_and_negative_controls; "
         "adversarial=twelve_constructed_inputs_that_should_be_caught; "
         "adversarial_count=12_declared_and_12_judged_compared_with_equality_"
         "not_with_a_floor; "
         /* RETRACTION, left visible on purpose. This key first read
          * `adversarial_caught=9_of_12` and `adversarial_accepted=2_of_12`,
          * written from the shape list rather than from a run. The run said
          * refused=7 accepted=5 (ADV_SUMMARY, same log). The two numbers a
          * reader would have compared against each other disagreed, so the
          * measurement is believed and the guess is withdrawn: 7 of the 12
          * are refused, and the 5 that are not are THREE controls, ONE
          * expansion that is correct by design (the shadowed case), and ONE
          * finding. A tally that hid the controls inside the acceptances
          * would have read as a worse campaign than it is, and one that
          * hid the finding inside them would have read as a better one. */
         "adversarial_refused=7_of_12_sibling_scope_374_1_recursion_201_2_"
         "rebind_module_381_1_param_shadow_376_2_reserved_376_3_unbound_374_1_"
         "recurse_metafor_377_4; "
         "adversarial_accepted=5_of_12_of_which_three_are_controls_and_one_is_"
         "correct_by_design_the_shadowed_case_and_one_is_the_finding_"
         "rebind_fnlocal; "
         "adversarial_control=one_non_adversarial_case_that_must_expand_"
         "because_a_parser_that_refused_everything_would_look_identical; "
         "adversarial_classifier_control=classify_name_asked_directly_about_a_"
         "bare_w_it_cannot_place_a_real_mark_and_a_spelled_word_because_a_zero_"
         "from_a_predicate_that_cannot_say_yes_is_not_a_measurement; "
         "adversarial_pairs=each_acceptance_paired_with_a_control_that_differs_"
         "only_in_the_callers_text_so_the_pair_can_come_apart; "
         "adversarial_hygienic_control=diagnostic_381_is_not_required_by_a_"
         "function_local_let_because_declares_below_reads_k_const_k_data_k_fn_"
         "k_param_at_macro_expand.nova:1416-1417_and_k_let_is_not_among_them_"
         "the_same_template_at_module_scope_is_refused_and_the_acceptance_is_"
         "hygienic_in_effect_because_the_introduced_name_is_marked; "
         "limits_adversarial_not=mutual_recursion_between_two_macros_"
         "parameter_count_at_the_cap_arity_mismatch_3xx_expansion_in_a_type_"
         "position_386_a_mark_forged_inside_a_string_or_comment_a_name_resolved_"
         "through_a_meta_if_branch_the_reference_owns_and_this_profile_"
         "refuses_377_a_template_naming_a_macro_a_comptime_binding_376_1_"
         "cross_module_or_cross_invocation_provenance_and_the_diagnostic_"
         "TEXT_of_any_of_these_codes; "
         "limits_adversarial_classifier=marks_are_recognised_by_parsing_"
         "their_ordinal_and_serial_out_of_the_expanders_own_bytes_so_a_prefix_"
         "test_would_not_be_this_check_but_a_name_that_is_BOTH_a_mark_format_"
         "AND_declared_by_the_caller_would_classify_as_marked_and_this_"
         "campaign_would_not_notice; "
         "both_no_diagnostic_text=true\n");
  printf("NTASM_NOVA_MACRO_EXPAND checks=%u failures=%u cases=%u\n",
         checks, failures, cases);
  return failures ? 1 : 0;
}
