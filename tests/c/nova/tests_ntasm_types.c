/* NTASM v0 Nova gate: the type checker, compiler/nova/types.nova.
 *
 * The entry is types_entry.main(source,out). out[4] nonzero selects
 * types.macro_forms, which counts the three macro type forms one by one, and
 * out[5] nonzero selects the raw tree mode, where out[6] is a node count and the
 * twelve word node records follow at out[7]. The raw mode lets a case drive a
 * structural branch the parser cannot spell; the source stays the caller
 * string, so a name node still resolves against real bytes.
 *
 * types.check keeps its contract: out[0..3] are the scalar, pointer, array and
 * macro type form counts on success, 350 and 351 write the line and the column
 * of the first offending node, and a structural 800 leaves out untouched.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
static const uint64_t guard = UINT64_C(0xcccccccccccccccc);
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s\n", m); } } while (0)

static char *loadf(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) { free(b); fclose(f); return NULL; }
  fclose(f);
  b[z] = 0;
  *n = (size_t)z;
  return b;
}

typedef struct { uint64_t returned, runtime, out[4]; } Run;

static Run run(const NovaHostImage *i, const char *s, uint64_t words) {
  Run r = {.out = {guard, guard, guard, guard}};
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, words * 8, 1);
  uint64_t a[] = {sh, strlen(s), oh, words};
  r.returned = i->entry(&c, a, 4);
  r.runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return r;
}

static void ok(const NovaHostImage *i, const char *n, const char *s, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
  Run r = run(i, s, 4);
  cases++; checks++;
  if (r.returned || r.runtime || r.out[0] != a || r.out[1] != b || r.out[2] != c || r.out[3] != d) {
    failures++;
    fprintf(stderr, "FAIL ok %s ret=%llu out=%llu,%llu,%llu,%llu\n", n,
            (unsigned long long)r.returned, (unsigned long long)r.out[0],
            (unsigned long long)r.out[1], (unsigned long long)r.out[2],
            (unsigned long long)r.out[3]);
  }
}

static void err(const NovaHostImage *i, const char *n, const char *s, uint64_t code) {
  Run r = run(i, s, 4);
  cases++; checks++;
  if (r.returned != code || r.runtime || r.out[0] == guard || r.out[1] == guard) {
    failures++;
    fprintf(stderr, "FAIL err %s ret=%llu\n", n, (unsigned long long)r.returned);
  }
}

static void bad(const NovaHostImage *i, const char *n, const char *s, uint64_t words) {
  Run r = run(i, s, words);
  cases++; checks++;
  if (r.returned != 800 || r.runtime || r.out[0] != guard || r.out[1] != guard) {
    failures++;
    fprintf(stderr, "FAIL invalid %s\n", n);
  }
}

/* types.check over an eight word buffer, so the three macro type forms are
 * read one by one from out[4..6] instead of as the single lumped out[3]. */
static void forms(const NovaHostImage *i, const char *n, const char *s, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
  uint64_t out[8];
  for (unsigned k = 0; k < 8; k++) out[k] = guard;
  out[4] = 0; out[5] = 0;
  NovaContextV2 ctx = {0};
  CHECK(nova_context_init_v2(&ctx), "forms context init");
  uint64_t sh = nova_borrow_v2(&ctx, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&ctx, out, sizeof out, 1);
  uint64_t args[] = {sh, strlen(s), oh, 8};
  uint64_t ret = i->entry(&ctx, args, 4);
  uint64_t rerr = ctx.error;
  CHECK(nova_context_destroy_v2(&ctx), "forms context cleanup");
  cases++; checks++;
  if (ret || rerr || out[4] != a || out[5] != b || out[6] != c || out[7] != d) {
    failures++;
    fprintf(stderr, "FAIL forms %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu want=%llu,%llu,%llu,%llu\n",
            n, (unsigned long long)ret, (unsigned long long)rerr,
            (unsigned long long)out[4], (unsigned long long)out[5],
            (unsigned long long)out[6], (unsigned long long)out[7],
            (unsigned long long)a, (unsigned long long)b,
            (unsigned long long)c, (unsigned long long)d);
  }
}

/* The four word buffer still gets the original four counters and nothing more,
 * which is the contract the seven pipeline callers rely on. */
static void short_ok(const NovaHostImage *i, const char *n, const char *s, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
  uint64_t out[4] = {guard, guard, guard, guard};
  NovaContextV2 ctx = {0};
  CHECK(nova_context_init_v2(&ctx), "short_ok context init");
  uint64_t sh = nova_borrow_v2(&ctx, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&ctx, out, sizeof out, 1);
  uint64_t args[] = {sh, strlen(s), oh, 4};
  uint64_t ret = i->entry(&ctx, args, 4);
  uint64_t rerr = ctx.error;
  CHECK(nova_context_destroy_v2(&ctx), "short_ok context cleanup");
  cases++; checks++;
  if (ret || rerr || out[0] != a || out[1] != b || out[2] != c || out[3] != d) {
    failures++;
    fprintf(stderr, "FAIL short_ok %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu\n",
            n, (unsigned long long)ret, (unsigned long long)rerr,
            (unsigned long long)out[0], (unsigned long long)out[1],
            (unsigned long long)out[2], (unsigned long long)out[3]);
  }
}

/* types.check with an output buffer shorter than four words: a structural 800
 * with nothing written. */
static void forms_bad(const NovaHostImage *i, const char *n, uint64_t words) {
  uint64_t out[8];
  for (unsigned k = 0; k < 8; k++) out[k] = guard;
  const char *s = "module m\n";
  NovaContextV2 ctx = {0};
  CHECK(nova_context_init_v2(&ctx), "forms_bad context init");
  uint64_t sh = nova_borrow_v2(&ctx, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&ctx, out, words * 8, 1);
  uint64_t args[] = {sh, strlen(s), oh, words};
  uint64_t ret = i->entry(&ctx, args, 4);
  uint64_t rerr = ctx.error;
  CHECK(nova_context_destroy_v2(&ctx), "forms_bad context cleanup");
  cases++; checks++;
  if (ret != 800 || rerr || out[0] != guard) {
    failures++;
    fprintf(stderr, "FAIL forms_bad %s ret=%llu\n", n, (unsigned long long)ret);
  }
}

/* One raw node record, in the flat order of ast.nova: kind, token_begin,
 * token_end, source, line, column, start, end, first_child, last_child,
 * next_sibling, aux. The record index is the one based node id. */
static void node12(uint64_t *w, uint64_t id, uint64_t kind, uint64_t start, uint64_t end,
                   uint64_t fc, uint64_t lc, uint64_t ns, uint64_t aux) {
  uint64_t b = (id - 1) * 12;
  w[b] = kind; w[b + 1] = 0; w[b + 2] = 0; w[b + 3] = 0;
  w[b + 4] = 1; w[b + 5] = 1; w[b + 6] = start; w[b + 7] = end;
  w[b + 8] = fc; w[b + 9] = lc; w[b + 10] = ns; w[b + 11] = aux;
}

/* A raw tree case. out[4] selects the raw mode on input and comes back holding
 * the expand<..> count, out[5..6] the node count on input and the $T and ast.*
 * counts on return, and out[7] the ast.* count and the alien count. A nonzero
 * code additionally pins that out[0..3] still hold the guard, which is the no
 * write on refusal rule of the four word convention. */
static void raw_case(const NovaHostImage *i, const char *n, const char *s,
                     uint64_t count, const uint64_t *nodes, uint64_t code,
                     uint64_t e0, uint64_t e1, uint64_t e2, uint64_t e3,
                     uint64_t e4, uint64_t e5, uint64_t e6, uint64_t e7) {
  uint64_t words = 6 + count * 12;
  uint64_t out[6 + 8 * 12];
  if (words > 6 + 8 * 12) {
    failures++; cases++; checks++;
    fprintf(stderr, "FAIL raw %s too many nodes\n", n);
    return;
  }
  for (uint64_t k = 0; k < words; k++) out[k] = guard;
  out[4] = 1; out[5] = count;
  for (uint64_t k = 0; k < count * 12; k++) out[6 + k] = nodes[k];
  NovaContextV2 ctx = {0};
  CHECK(nova_context_init_v2(&ctx), "raw context init");
  uint64_t sh = nova_borrow_v2(&ctx, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&ctx, out, words * 8, 1);
  uint64_t args[] = {sh, strlen(s), oh, words};
  uint64_t ret = i->entry(&ctx, args, 4);
  uint64_t rerr = ctx.error;
  CHECK(nova_context_destroy_v2(&ctx), "raw context cleanup");
  cases++; checks++;
  int bad = (ret != code) || rerr;
  if (!bad && code == 0)
    bad = out[0] != e0 || out[1] != e1 || out[2] != e2 || out[3] != e3 ||
          out[4] != e4 || out[5] != e5 || out[6] != e6 || out[7] != e7;
  if (!bad && code != 0)
    bad = out[0] != guard || out[1] != guard || out[2] != guard || out[3] != guard;
  if (bad) {
    failures++;
    fprintf(stderr, "FAIL raw %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
            n, (unsigned long long)ret, (unsigned long long)rerr,
            (unsigned long long)out[0], (unsigned long long)out[1],
            (unsigned long long)out[2], (unsigned long long)out[3],
            (unsigned long long)out[4], (unsigned long long)out[5],
            (unsigned long long)out[6], (unsigned long long)out[7]);
  }
}

int main(void) {
  const char *paths[] = {"tests/nova/tests/types-entry.nova",
                         "compiler/nova/analysis/types/types.nova",
                         "compiler/nova/frontend/parser.nova",
                         "compiler/nova/frontend/ast.nova",
                         "compiler/nova/frontend/lexer.nova"};
  char *sources[5] = {0};
  NtFInput inputs[5];
  for (unsigned i = 0; i < 5; i++) {
    size_t n = 0;
    sources[i] = loadf(paths[i], &n);
    inputs[i] = (NtFInput){paths[i], sources[i], n};
  }
  int all = 1;
  for (unsigned i = 0; i < 5; i++) if (!sources[i]) all = 0;
  CHECK(all, "sources load");
  NtArtifact a = {0};
  int compiled = all && nova_compile_many_v2(inputs, 5, &a);
  CHECK(compiled, "modules compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line, a.error.column, a.error.message);
  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&a, &image), "image maps");
  if (image.memory) {
    const char *basic = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    ok(&image, "basic", basic, 1, 0, 0, 0);
    const char *scalars = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u8 @al,in b:u16 @cx,in c:u32 @edx,in d:u64 @rbx,in e:i8 @sil,in g:i16 @di,in h:i32 @r8d,in i:i64 @r9,in j:bool @r10b)->never\neffects {no_return}\nclobbers {} {\nud2\n}\n}\n";
    ok(&image, "scalars", scalars, 10, 0, 0, 0);
    const char *pointer = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u8> @rdi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    ok(&image, "pointer", pointer, 2, 1, 0, 0);
    const char *nested = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,ptr<kernel,u8>> @rdi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    ok(&image, "nested", nested, 2, 2, 0, 0);
    const char *array = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:array<u8,4> @rdi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    ok(&image, "array", array, 2, 0, 1, 0);
    const char *unknown = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:telepathy @rdi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    err(&image, "unknown", unknown, 350);
    const char *zero = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:array<u8,0> @rdi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    err(&image, "zero", zero, 351);
    const char *macro_type = "module m\ntarget x86_64-nexora-none\nmacro make(T:ast.type,v:ast.expr)->ast.decl {\nreturn quote(decl) { export data answer:$T=$v; };\n}\n";
    ok(&image, "macro type variable", macro_type, 0, 0, 0, 4);

    /* === the three macro type forms, split and validated ================ */
    /* The same source check already accepted: one $T splice and three ast.*
     * forms, now reported one by one instead of as the single total 4. */
    forms(&image, "split splice and ast", macro_type, 0, 1, 3, 0);
    short_ok(&image, "four word buffer", macro_type, 0, 0, 0, 4);
    /* An expand<..> form next to the ast.decl result kind. */
    const char *expand_type = "module m\ntarget x86_64-nexora-none\nmacro widen()->ast.decl {\nreturn quote(decl) { const wide : expand size(1) = 1; };\n}\n";
    forms(&image, "split expand", expand_type, 1, 0, 1, 0);
    /* An ast.* spelling outside the closed vocabulary is counted and reported,
     * not refused: ntasm_macro_expand rejects the module later as 372, so
     * types.check keeps the verdict it has always returned. */
    const char *alien_ast = "module m\ntarget x86_64-nexora-none\nmacro mk(t:ast.telepathy)->ast.decl {\nreturn quote(decl) { const c:u64 = 1; };\n}\n";
    forms(&image, "split alien ast", alien_ast, 0, 0, 2, 1);
    ok(&image, "alien ast still accepted", alien_ast, 1, 0, 0, 2);
    forms_bad(&image, "forms short", 3);
    forms_bad(&image, "forms empty", 0);

    /* The raw tree cases drive the shape branches the parser cannot spell.
     * The source is "$T u8 expr": a splice occupies [0,2) with its name at
     * [1,2), the name u8 at [3,5) and the name expr at [6,10). */
    const char *raw_src = "$T u8 expr";
    uint64_t n[4 * 12];
    /* a well formed expand<..> with one literal argument */
    node12(n, 1, 36, 0, 5, 2, 3, 0, 3); node12(n, 2, 90, 3, 5, 0, 0, 3, 0); node12(n, 3, 94, 0, 0, 0, 0, 0, 1);
    raw_case(&image, "raw expand ok", raw_src, 3, n, 0, 0, 0, 0, 1, 1, 0, 0, 0);
    /* a well formed $T splice */
    node12(n, 1, 36, 0, 2, 2, 2, 0, 4); node12(n, 2, 90, 1, 2, 0, 0, 0, 0);
    raw_case(&image, "raw splice ok", raw_src, 2, n, 0, 0, 0, 0, 1, 0, 1, 0, 0);
    /* a well formed ast.expr kind, and an ast.* spelling outside the closed
     * vocabulary of ntasm_macro_expand */
    node12(n, 1, 36, 5, 10, 2, 2, 0, 5); node12(n, 2, 90, 6, 10, 0, 0, 0, 0);
    raw_case(&image, "raw ast ok", raw_src, 2, n, 0, 0, 0, 0, 1, 0, 0, 1, 0);
    node12(n, 1, 36, 2, 5, 2, 2, 0, 5); node12(n, 2, 90, 3, 5, 0, 0, 0, 0);
    raw_case(&image, "raw ast alien", raw_src, 2, n, 0, 0, 0, 0, 1, 0, 0, 1, 1);
    /* refusals: an expand<..> with no child, with a literal instead of a name,
     * with an argument that is not a value, and with a name outside the source.
     * The rejected argument is a well formed u64 type node, so the refusal is
     * the argument rule and not the scalar catalog. */
    node12(n, 1, 36, 0, 5, 0, 0, 0, 3);
    raw_case(&image, "raw expand nameless", raw_src, 1, n, 800, 0, 0, 0, 0, 0, 0, 0, 0);
    node12(n, 1, 36, 0, 5, 2, 2, 0, 3); node12(n, 2, 94, 0, 0, 0, 0, 0, 1);
    raw_case(&image, "raw expand literal name", raw_src, 2, n, 800, 0, 0, 0, 0, 0, 0, 0, 0);
    node12(n, 1, 36, 0, 5, 2, 3, 0, 3); node12(n, 2, 90, 3, 5, 0, 0, 3, 0);
    node12(n, 3, 36, 3, 5, 4, 4, 0, 0); node12(n, 4, 90, 3, 5, 0, 0, 0, 0);
    raw_case(&image, "raw expand type argument", raw_src, 4, n, 800, 0, 0, 0, 0, 0, 0, 0, 0);
    node12(n, 1, 36, 0, 5, 2, 2, 0, 3); node12(n, 2, 90, 40, 42, 0, 0, 0, 0);
    raw_case(&image, "raw expand name outside source", raw_src, 2, n, 800, 0, 0, 0, 0, 0, 0, 0, 0);
    /* refusals: a $T splice with two children, with a literal child, with a
     * type child and with a name the sigil does not immediately precede */
    node12(n, 1, 36, 0, 2, 2, 3, 0, 4); node12(n, 2, 90, 1, 2, 0, 0, 3, 0); node12(n, 3, 90, 1, 2, 0, 0, 0, 0);
    raw_case(&image, "raw splice two children", raw_src, 3, n, 800, 0, 0, 0, 0, 0, 0, 0, 0);
    node12(n, 1, 36, 0, 2, 2, 2, 0, 4); node12(n, 2, 94, 0, 0, 0, 0, 0, 1);
    raw_case(&image, "raw splice literal", raw_src, 2, n, 800, 0, 0, 0, 0, 0, 0, 0, 0);
    node12(n, 1, 36, 0, 2, 2, 2, 0, 4); node12(n, 2, 36, 3, 5, 3, 3, 0, 0); node12(n, 3, 90, 3, 5, 0, 0, 0, 0);
    raw_case(&image, "raw splice type child", raw_src, 3, n, 800, 0, 0, 0, 0, 0, 0, 0, 0);
    node12(n, 1, 36, 1, 2, 2, 2, 0, 4); node12(n, 2, 90, 1, 2, 0, 0, 0, 0);
    raw_case(&image, "raw splice unspelled sigil", raw_src, 2, n, 800, 0, 0, 0, 0, 0, 0, 0, 0);
    /* refusals: an ast.* kind with a literal child, with no child at all and
     * with a child the tree does not carry */
    node12(n, 1, 36, 5, 10, 2, 2, 0, 5); node12(n, 2, 94, 0, 0, 0, 0, 0, 1);
    raw_case(&image, "raw ast literal", raw_src, 2, n, 800, 0, 0, 0, 0, 0, 0, 0, 0);
    node12(n, 1, 36, 5, 10, 0, 0, 0, 5);
    raw_case(&image, "raw ast nameless", raw_src, 1, n, 800, 0, 0, 0, 0, 0, 0, 0, 0);
    node12(n, 1, 36, 5, 10, 2, 2, 0, 5);
    raw_case(&image, "raw ast absent child", raw_src, 1, n, 800, 0, 0, 0, 0, 0, 0, 0, 0);
    /* a $T splice and an ast.* kind in one tree, so the split is a split */
    node12(n, 1, 36, 0, 2, 2, 2, 0, 4); node12(n, 2, 90, 1, 2, 0, 0, 0, 0);
    node12(n, 3, 36, 5, 10, 4, 4, 0, 5); node12(n, 4, 90, 6, 10, 0, 0, 0, 0);
    raw_case(&image, "raw splice and ast", raw_src, 4, n, 0, 0, 0, 0, 2, 0, 1, 1, 0);

    bad(&image, "short", basic, 3);
    bad(&image, "invalid", "target x86_64-nexora-none\n", 4);
  }
  if (image.memory) nova_host_unmap(&image);
  if (compiled) nt_artifact_free(&a);
  for (unsigned i = 0; i < 5; i++) free(sources[i]);
  printf("NTASM_NOVA_TYPES checks=%u failures=%u cases=%u\n", checks, failures, cases);
  return failures ? 1 : 0;
}
