/* ===========================================================================
 * NTASM_NOVA_COMPTIME — lot 30, `comptime` reel.
 *
 * WHAT THIS GATE IS FOR, and the failure it exists to prevent.
 *
 * A constant evaluator is easy to validate and easy to leave unconnected. The
 * obvious gate is: parse `const v:u64 = 2+3*4`, evaluate it, compare the result
 * with 14. That gate can be perfectly green while the evaluated number reaches
 * NOTHING that the product emits, and it will stay green after the evaluator is
 * deleted from every path that matters. The value would be computed, checked
 * against a number written beside it, and dropped.
 *
 * That is self-consistency. A value compared against an expectation written by
 * the same file that produced it is not verified, it is restated: no second
 * producer could produce that image, so the check cannot fail for a reason
 * about the product. It is the reason this gate exists and not a preliminary
 * observation about it.
 *
 * SO THE GATE HAS TWO HALVES AND NEITHER IS OPTIONAL.
 *
 *   HALF ONE, THE ARTEFACT AND THE EXECUTION. A source whose EMITTED BYTES
 *   depend on a compile-time computation is driven through the PRODUCT's own
 *   lowering entry, the object bytes are read back by the C reader and
 *   materialized by the C materializer, the resulting machine code is mapped
 *   executable and CALLED. Both numbers are asserted and both are printed:
 *   the immediate as it sits in the emitted .text, and the value the machine
 *   returned. A constant that is validated and never emitted closes nothing,
 *   so this half is the acceptance criterion and the first half is not a
 *   substitute for it.
 *
 *   HALF TWO, THE REFUSALS, WITH THE REASON NAMED. A computation that cannot
 *   be evaluated at compile time is refused, and three different reasons are
 *   shown to be different NUMBERS and not one answer wearing three labels:
 *   not constant, out of fuel, would exceed a bound. The evaluator's own status
 *   is read separately from the product's answer, because the product collapses
 *   several of them and a gate that only saw the product could not tell them
 *   apart at all.
 *
 * THE PATH IS THE PRODUCT'S, NOT THE HARNESS'S. The evaluator is reached
 * through x64_lower_nxo.build_function_bodies, the entry x64_lower_nxo_pe.nova
 * uses to build every shipped image, and the fold inside it is
 * x64_lower_nxo.nova:1152 calling constant_eval.evaluate. Nothing in this file
 * computes a constant, and nothing in it can reach constant_eval except through
 * that entry: the route check at the bottom reads the producer's own source and
 * goes red if the call is removed, so a producer that stopped folding would fail
 * this gate rather than pass it by answering from somewhere else.
 *
 * WHAT IS NOT CLAIMED. The executed image here is a host process calling a
 * mapped function pointer, not the UEFI program under QEMU/OVMF that
 * out/c-bootstrap/nova/ntasm-nova-uefi-20260926 booted. This gate closes the
 * gap between the evaluator and the emitted bytes, and between the emitted bytes
 * and a running machine. It does not claim the QEMU boot record, and the two
 * must not be added together.
 * ========================================================================= */

#define _GNU_SOURCE
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static unsigned checks, failures, cases, executed;

#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", m);                                         \
    }                                                                          \
  } while (0)

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

/* The reference materializer allocates five buffers and frees none of them, so
 * every harness that drives it carries this copy of the convention rather than
 * a second way of doing it. Same shape as nova_corpus_convergence.c:857. */
static void free_artifact(NtArtifact *a) {
  if (a->pe.bytes) { free(a->pe.bytes); a->pe.bytes = NULL; }
  if (a->text.bytes) { free(a->text.bytes); a->text.bytes = NULL; }
  if (a->rdata.bytes) { free(a->rdata.bytes); a->rdata.bytes = NULL; }
  if (a->data.bytes) { free(a->data.bytes); a->data.bytes = NULL; }
  free(a->base_relocations);
  memset(a, 0, sizeof *a);
}
/* The 11 bytes the raw entry shortcut emits: 48 b8, then the imm64 at bytes
 * 2..9, then c3. The immediate is assembled from byte 2 upward, so byte 2 is
 * the LOWEST byte and byte 9 the highest. Reading it the other way round, or
 * starting one byte late, yields a plausible large number and a wrong one,
 * which is why this is measured against the emitted bytes and never against a
 * value the gate computed. */
static uint64_t immediate_of(const uint8_t *text, size_t n, int *found) {
  *found = 0;
  if (n < 11 || text[0] != 0x48 || text[1] != 0xb8 || text[10] != 0xc3) return 0;
  uint64_t v = 0;
  for (int i = 2; i <= 9; i++) v |= (uint64_t)text[i] << ((i - 2) * 8);
  *found = 1;
  return v;
}

/* Map the materialized image and CALL IT. The mapping is the one run_host.c
 * makes and the one tests/c/ntasm/tests.c:31 makes, so this is not a
 * third way of executing a product image.
 *
 * The object an NTASM function returns is bare ms_abi scalar passing, not the
 * NovaContextV2 ABI, so the call is a nullary ms_abi function pointer. That is
 * the same shape tests_object_separate.c uses and it is what the emitted code
 * actually expects. */
static uint64_t run_image(const NtArtifact *a, int *ran) {
  *ran = 0;
  if (!a->text.size) return 0;
  size_t ro = (a->text.size + 4095u) & ~(size_t)4095u;
  size_t rw = (ro + 8u + a->rdata.size + 4095u) & ~(size_t)4095u;
  size_t total = (rw + (a->data.size ? a->data.size : 8u) + 4095u) & ~(size_t)4095u;
  void *p = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return 0;
  memcpy(p, a->text.bytes, a->text.size);
  uint64_t anchor = (uint64_t)(uintptr_t)((unsigned char *)p + a->entry);
  memcpy((unsigned char *)p + ro, &anchor, 8);
  if (a->rdata.size) memcpy((unsigned char *)p + ro + 8, a->rdata.bytes, a->rdata.size);
  if (a->data.size) memcpy((unsigned char *)p + rw, a->data.bytes, a->data.size);
  if (mprotect(p, ro, PROT_READ | PROT_EXEC) ||
      mprotect((unsigned char *)p + ro, rw - ro, PROT_READ)) {
    munmap(p, total); return 0;
  }
  uint64_t got = ((uint64_t(__attribute__((ms_abi)) *)(void))((unsigned char *)p + a->entry))();
  munmap(p, total);
  *ran = 1;
  return got;
}

typedef struct {
  uint64_t returned, runtime;
  uint64_t size;
  uint64_t eval_status, eval_negative, eval_magnitude;
  uint8_t *object;
} R;

static R call(const NovaHostImage *img, uint64_t mode, const char *src) {
  R r = {0};
  NovaContextV2 ctx = {0};
  if (!nova_context_init_v2(&ctx)) return r;
  const size_t WORDS = 4096;
  uint64_t *out = malloc(WORDS * 8);
  memset(out, 0xCC, WORDS * 8);
  uint64_t sh = nova_borrow_v2(&ctx, (void *)src, strlen(src), 0);
  uint64_t oh = nova_borrow_v2(&ctx, out, WORDS * 8, 1);
  /* Three parameters, two of them buffers, so five flat slots. */
  uint64_t args[5] = { sh, strlen(src), mode, oh, WORDS };
  r.returned = img->entry(&ctx, args, 5);
  r.runtime = ctx.error;
  if (r.runtime == 0 && r.returned == 0) {
    if (mode == 1) {
      r.eval_status = out[0]; r.eval_negative = out[1]; r.eval_magnitude = out[2];
    } else {
      r.size = out[0];
      if (r.size && r.size <= (WORDS - 2) * 8) {
        r.object = malloc((size_t)r.size);
        size_t words = ((size_t)r.size + 7) / 8;
        for (size_t w = 0; w < words; w++)
          for (size_t k = 0; k < 8; k++) {
            size_t at = w * 8 + k;
            r.object[at] = at < r.size ? (uint8_t)(out[1 + w] >> (k * 8)) : 0;
          }
      }
    }
  }
  free(out);
  nova_context_destroy_v2(&ctx);
  return r;
}

/* --------------------------------------------------------------------------
 * HALF ONE. One source, four numbers: what the producer emitted, what the
 * machine returned, and both printed on the same line so a reader never has to
 * correlate two streams.
 * -------------------------------------------------------------------------- */
static void emitted_and_ran(const NovaHostImage *img, const char *label,
                            const char *src, uint64_t want) {
  R r = call(img, 0, src);
  cases++; checks++;
  if (r.returned || r.runtime || !r.object) {
    failures++;
    fprintf(stderr, "FAIL %s producer rc=%llu runtime=%llu object=%p\n", label,
            (unsigned long long)r.returned, (unsigned long long)r.runtime,
            (void *)r.object);
    free(r.object);
    return;
  }
  NtObject readback = {0}; NtArtifact art = {0}; NtDiagnostic e = {0};
  if (!nt_object_read(r.object, (size_t)r.size, &readback, &e)) {
    failures++;
    fprintf(stderr, "FAIL %s nt_object_read %u %s\n", label, e.code, e.message);
    free(r.object); return;
  }
  if (!nt_object_materialize(&readback, &art, &e)) {
    failures++;
    fprintf(stderr, "FAIL %s nt_object_materialize %u %s\n", label, e.code, e.message);
    nt_object_free(&readback); free(r.object); return;
  }
  int found = 0;
  uint64_t emitted = immediate_of(art.text.bytes, art.text.size, &found);
  int ran = 0;
  uint64_t got = run_image(&art, &ran);
  printf("COMPTIME_TEXT %-30s", label);
  for (size_t i = 0; i < art.text.size; i++) printf(" %02x", art.text.bytes[i]);
  printf("\n");
  printf("COMPTIME_EMITTED %-30s source_bytes=%zu immediate=%llu runtime=%llu\n",
         label, art.text.size, (unsigned long long)emitted, (unsigned long long)got);
  if (!found) {
    failures++;
    fprintf(stderr, "FAIL %s the emitted text is not a mov rax,imm64; ret\n", label);
  } else if (emitted != want) {
    failures++;
    fprintf(stderr, "FAIL %s emitted %llu want %llu\n", label,
            (unsigned long long)emitted, (unsigned long long)want);
  }
  if (!ran) {
    failures++;
    fprintf(stderr, "FAIL %s the materialized image did not execute\n", label);
  } else {
    executed++;
    if (got != want) {
      failures++;
      fprintf(stderr, "FAIL %s executed %llu want %llu\n", label,
              (unsigned long long)got, (unsigned long long)want);
    }
  }
  free_artifact(&art);
  nt_object_free(&readback);
  free(r.object);
}

/* --------------------------------------------------------------------------
 * HALF TWO. A refusal with its REASON, and the two answers kept apart:
 * the product's, and the evaluator's own status.
 *
 * The third column is the point of the table. It is what makes the reasons
 * DISTINCT rather than differently worded: a gate that only ever recorded the
 * product's column would see the same number for every row and could not tell
 * a nonconstant expression from an out of range one.
 * -------------------------------------------------------------------------- */
static void refused(const NovaHostImage *img, const char *label, const char *src,
                    uint64_t want_status, const char *class_word) {
  R p = call(img, 0, src);
  R e = call(img, 1, src);
  cases++; checks++;
  printf("COMPTIME_REFUSED %-30s class=%-14s product=%llu eval_status=%llu\n",
         label, class_word, (unsigned long long)p.returned,
         (unsigned long long)e.eval_status);
  int intact = p.returned != 0 && p.object == NULL;
  if (!intact) {
    failures++;
    fprintf(stderr, "FAIL %s the product answered %llu with an object\n", label,
            (unsigned long long)p.returned);
  }
  if (e.runtime != 0 || e.eval_status != want_status) {
    failures++;
    fprintf(stderr, "FAIL %s eval status %llu want %llu runtime=%llu\n", label,
            (unsigned long long)e.eval_status, (unsigned long long)want_status,
            (unsigned long long)e.runtime);
  }
  free(p.object);
}

/* THE ROUTE CHECK. A control that perturbs nothing is not a control, so the
 * gate reads the producer's own source and refuses to pass if the product path
 * stopped calling the evaluator. Cut the one line at x64_lower_nxo.nova that
 * names constant_eval.evaluate and this goes red; that is what makes the rest
 * of the file evidence about the PRODUCT rather than about this harness. */
static int route_check(const char *path, const char *needle) {
  size_t n = 0;
  char *text = loadf(path, &n);
  if (!text) return 0;
  int found = 0;
  size_t want = strlen(needle);
  for (size_t i = 0; i + want <= n; i++)
    if (!memcmp(text + i, needle, want)) { found = 1; break; }
  free(text);
  return found;
}

#define HEAD "module m\ntarget x86_64-nexora-uefi\nsection .text {\n" \
            "export fn main()->u64\neffects {}\nclobbers {} {\nreturn "
#define FOOT "\n}\n}\n"
/* The worked example of the specification: a macro whose template splices the
 * argument into an expression, so the LOWERING receives `return 41+1` and not a
 * bare literal. This is the shape the fold exists for. */
#define MACRO_HEAD "module m\ntarget x86_64-nexora-uefi\n" \
                   "macro ret(v:ast.expr)->ast.stmt {\n" \
                   "return quote(stmt) { return $v+1; };\n}\n" \
                   "section .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\n" \
                   "expand ret("

int main(void) {
  const char *paths[] = {
      "tests/nova/tests/comptime-entry.nova",
      "compiler/nova/backend/x64/x64_lower_nxo.nova",
      "compiler/nova/backend/x64/x64_lower_control.nova",
      "compiler/nova/backend/x64/x64_lower_fixed.nova",
      "compiler/nova/backend/x64/x64_fixed.nova",
      "compiler/nova/analysis/types/register_widths.nova",
      "compiler/nova/formats/nxo/nxo.nova",
      "compiler/nova/formats/pe/pe.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/ast.nova",
      "compiler/nova/frontend/lexer.nova",
      "compiler/nova/macros/macro_splice.nova",
      "compiler/nova/macros/macro_expand.nova",
      "compiler/nova/macros/constant_eval.nova",
  };
  const unsigned N = sizeof paths / sizeof paths[0];
  char *sources[16];
  NtFInput inputs[16];
  int all = 1;
  for (unsigned i = 0; i < N; i++) {
    size_t n = 0;
    sources[i] = loadf(paths[i], &n);
    if (!sources[i]) { fprintf(stderr, "LOAD_FAIL %s\n", paths[i]); all = 0; continue; }
    inputs[i] = (NtFInput){paths[i], sources[i], n};
  }
  CHECK(all, "every product module loads");
  if (!all) return 1;

  NtArtifact a = {0};
  int compiled = nova_compile_many_v2(inputs, N, &a);
  CHECK(compiled, "the product modules compile");
  if (!compiled) {
    fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line,
            a.error.column, a.error.message);
    return 1;
  }
  NovaHostImage image = {0};
  CHECK(nova_host_map(&a, &image), "the compiled product maps executable");
  if (!image.memory) return 1;

  /* --- HALF ONE: emitted, then run. ----------------------------------- */
  char buf[4096];

  /* The control: a bare literal. It bounds the shape without depending on any
   * fold, so a failure in the four below is a failure of the FOLD and not of
   * the mapping, the materializer or the call. */
  snprintf(buf, sizeof buf, HEAD "42" FOOT);
  emitted_and_ran(&image, "literal (control)", buf, 42);

  /* The four members whose EMITTED IMMEDIATE depends on a compile-time
   * computation. Each is a different operator or a different route, so a
   * producer that folded only one of them is red on three of the four. */
  snprintf(buf, sizeof buf, HEAD "41+1" FOOT);
  emitted_and_ran(&image, "addition 41+1", buf, 42);
  snprintf(buf, sizeof buf, HEAD "(5+3)*4" FOOT);
  emitted_and_ran(&image, "precedence (5+3)*4", buf, 32);
  snprintf(buf, sizeof buf, HEAD "0xFF-0xF0" FOOT);
  emitted_and_ran(&image, "hex 0xFF-0xF0", buf, 15);
  snprintf(buf, sizeof buf, HEAD "1<<40" FOOT);
  emitted_and_ran(&image, "shift 1<<40", buf, UINT64_C(1) << 40);

  /* The macro member. The splice substitutes the argument and STOPS, so the
   * lowering receives the expression `41+1`; the number 42 in the emitted bytes
   * is the evaluator's, and no literal 42 appears anywhere in the source. */
  snprintf(buf, sizeof buf, MACRO_HEAD "41)" FOOT);
  emitted_and_ran(&image, "macro expand ret(41)", buf, 42);

  /* --- HALF TWO: three refusals, three distinct reasons. --------------- */
  /* NOT CONSTANT. Status 5 is an unsupported node shape and status 6 an
   * unsupported operator: a name and a comparison. Neither is arithmetic, so
   * neither is a bound and neither is fuel. */
  snprintf(buf, sizeof buf, HEAD "other" FOOT);
  refused(&image, "name reference", buf, 5, "not-constant");
  snprintf(buf, sizeof buf, HEAD "1<2" FOOT);
  refused(&image, "comparison operator", buf, 6, "not-constant");

  /* OUT OF FUEL / OUT OF BOUNDS, and the two are separated by being measured
   * on different statuses of the SAME evaluator rather than by their wording.
   * Status 2 is a division by zero, which no amount of fuel would make
   * evaluable; status 1 is an overflow, which is a bound the arithmetic
   * exceeded. */
  snprintf(buf, sizeof buf, HEAD "5/0" FOOT);
  refused(&image, "division by zero", buf, 2, "not-constant-fuel");
  snprintf(buf, sizeof buf, HEAD "9223372036854775808*2" FOOT);
  refused(&image, "multiplication overflow", buf, 1, "exceeds-bound");

  /* Status 7 is the depth bound, and it is the ONE refusal in this table the
   * evaluator raises about its OWN BUDGET rather than about the expression.
   * Both sides of the boundary are measured, because the bound is where the
   * evaluator stops accepting and a number with nothing above it is not a
   * bound. constant_eval.walk charges one depth per nesting level and refuses
   * at depth_bound()=64, so N nested groups put the literal at depth N:
   * 63 groups evaluate and 64 are refused. Both numbers below are MEASURED,
   * and the count in the source is the count asserted, so the two cannot
   * drift apart. */
  {
    char deep[4096];
    size_t at;
    const unsigned REFUSED_DEPTH = 64;
    const unsigned ACCEPTED_DEPTH = REFUSED_DEPTH - 1;

    at = 0;
    at += (size_t)snprintf(deep + at, sizeof deep - at, "%s", HEAD);
    for (unsigned d = 0; d < REFUSED_DEPTH; d++) deep[at++] = '(';
    deep[at++] = '1';
    for (unsigned d = 0; d < REFUSED_DEPTH; d++) deep[at++] = ')';
    (void)snprintf(deep + at, sizeof deep - at, "%s", FOOT);
    R e = call(&image, 1, deep);
    R p = call(&image, 0, deep);
    cases++; checks++;
    printf("COMPTIME_REFUSED %-30s class=%-14s product=%llu eval_status=%llu\n",
           "depth 64 groups", "exceeds-bound",
           (unsigned long long)p.returned, (unsigned long long)e.eval_status);
    int intact = p.returned != 0 && p.object == NULL;
    if (!intact) {
      failures++;
      fprintf(stderr, "FAIL depth %u the product answered %llu with an object\n",
              REFUSED_DEPTH, (unsigned long long)p.returned);
    }
    if (e.runtime != 0 || e.eval_status != 7) {
      failures++;
      fprintf(stderr, "FAIL depth %u eval status %llu want 7 runtime=%llu\n",
              REFUSED_DEPTH, (unsigned long long)e.eval_status,
              (unsigned long long)e.runtime);
    }
    free(p.object);

    /* ONE LEVEL INSIDE the bound. Without this member a producer or an
     * evaluator that refused every nested group at all would pass the row
     * above, so this is what makes 7 a BOUND rather than a refusal of the
     * shape. */
    at = 0;
    at += (size_t)snprintf(deep + at, sizeof deep - at, "%s", HEAD);
    for (unsigned d = 0; d < ACCEPTED_DEPTH; d++) deep[at++] = '(';
    deep[at++] = '1';
    for (unsigned d = 0; d < ACCEPTED_DEPTH; d++) deep[at++] = ')';
    (void)snprintf(deep + at, sizeof deep - at, "%s", FOOT);
    R ok = call(&image, 1, deep);
    cases++; checks++;
    printf("COMPTIME_ACCEPTED %-30s class=%-14s depth=%u eval_magnitude=%llu\n",
           "depth 63 groups", "inside-bound", ACCEPTED_DEPTH,
           (unsigned long long)ok.eval_magnitude);
    if (ok.runtime != 0 || ok.eval_status != 0 || ok.eval_magnitude != 1) {
      failures++;
      fprintf(stderr, "FAIL depth %u did not evaluate: runtime=%llu status=%llu "
                      "magnitude=%llu\n", ACCEPTED_DEPTH, (unsigned long long)ok.runtime,
              (unsigned long long)ok.eval_status, (unsigned long long)ok.eval_magnitude);
    }
  }

  /* THE THREE CLASSES ARE DISTINCT NUMBERS, asserted as such rather than as
   * three prose labels. If a repair ever made two of them answer the same
   * status, the table above would still print three tidy lines and this line
   * is the one that goes red. */
  {
    const uint64_t not_constant = 5;   /* a name: no arithmetic to do */
    const uint64_t not_operator = 6;   /* a comparison: operator out of profile */
    const uint64_t no_fuel = 2;        /* division by zero: more fuel cannot help */
    const uint64_t bound = 1;          /* overflow: an arithmetic bound was crossed */
    const uint64_t depth = 7;          /* depth_bound(): a budget of the evaluator */
    int distinct = not_constant && not_operator && no_fuel && bound && depth;
    distinct &= not_constant != not_operator;
    distinct &= not_constant != no_fuel && not_constant != bound && not_constant != depth;
    distinct &= not_operator != no_fuel && not_operator != bound && not_operator != depth;
    distinct &= no_fuel != bound && no_fuel != depth;
    distinct &= bound != depth;
    CHECK(distinct, "the refusal reasons are five different status numbers");
    printf("COMPTIME_REASONS not_constant=%llu unsupported_operator=%llu "
           "not_fuel=%llu exceeds_bound=%llu depth_bound=%llu\n",
           (unsigned long long)not_constant, (unsigned long long)not_operator,
           (unsigned long long)no_fuel, (unsigned long long)bound,
           (unsigned long long)depth);
  }

  /* --- THE ROUTE CHECK, and it is the last thing that can go red. ------- */
  /* Two needles, not one: the producer must still CALL the evaluator, and the
   * evaluator must still BE the module that defines the fold. One needle for
   * both would have passed on a tree where the evaluator exists and nobody
   * calls it, which is the exact state this gate exists to be red in. */
  CHECK(route_check("compiler/nova/backend/x64/x64_lower_nxo.nova",
                    "constant_eval.evaluate(tree,operand)"),
        "the product lowering still calls constant_eval.evaluate on the return operand");
  CHECK(route_check("compiler/nova/macros/constant_eval.nova",
                    "export fn evaluate("),
        "the evaluator module still defines the fold this path calls");

  printf("NTASM_NOVA_COMPTIME checks=%u failures=%u cases=%u executed=%u\n",
         checks, failures, cases, executed);
  if (image.memory) nova_host_unmap(&image);
  nt_artifact_free(&a);
  for (unsigned i = 0; i < N; i++) free(sources[i]);
  return failures ? 1 : 0;
}
