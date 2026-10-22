#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntasm_pipeline_parity.h"

/* ====================== pipeline parity ==============================
   This gate compiles a SUB-CHAIN of the 34 stage pipeline of validate.nova
   and its module list carries exactly one of them: semantics.nova, which is
   stage index (2).  The rest -- decls-entry, decls, parser, ast, lexer -- are
   this gate's own entry and the front end it needs, not stages.

   CLAIMS=1, and the helper is what proved it.  This gate was wired with
   claims=0 on the standing claim that its only non zero code of its own is
   812, the "borrowed out buffer is too narrow" verdict, which no stage of the
   34 emits.  The helper's claims=0 assertion fired on the `duplicate` case:
   300 is emitted by semantics.nova:87 and is therefore the verdict of stage
   index, a stage THIS entry runs.  So this gate does assert a pipeline
   verdict, on a real fixture, and the honest declaration is claims=1.  The
   812 case is still counted as unattributed rather than compared, because
   812 genuinely is not a verdict of this pipeline; claims=1 does not stop
   that count, it only stops the helper from reading a pipeline verdict here
   as a category error.  The 800 structural refusals are counted and never
   compared, so the width cases are outside the comparison by construction. */
// (812 -> 0)  The `short` case. 812 is this gate's OWN "the borrowed out buffer
// is narrower than 1+count*6 words" verdict (decls.nova:104, `if len(out)<needed
// { return 812; }`), raised because the case lends 18 words where the three
// declarations of the `valid` fixture need 19. No stage of the 34 emits 812 --
// the helper counts it as unattributed -- and the pipeline cannot reach it,
// because validate's entry always lends four words and never builds this
// gate's per-declaration table, so for the same source the pipeline answers 0
// (accepted). The pair is declared rather than fixed because both answers are
// correct for the width each side was actually lent: the gate is measuring a
// buffer contract the pipeline does not have.
static const NgParityPair ng_parity_pairs[]={{812,0}};
static NgParitySpec ng_parity={
  "decls",
  {"index"},1,
  1,
  ng_parity_pairs,(unsigned)(sizeof ng_parity_pairs/sizeof ng_parity_pairs[0]),
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];

static unsigned checks, failures, cases;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s\n", m); } } while (0)
static const uint64_t guard = UINT64_C(0xcccccccccccccccc);

static char *load(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb"); if (!f) return NULL;
  fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
  char *p = n >= 0 ? malloc((size_t)n + 1) : NULL;
  if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) { free(p); fclose(f); return NULL; }
  fclose(f); p[n] = 0; *length = (size_t)n; return p;
}

typedef struct { uint64_t returned, runtime_error, out[64]; } Run;
static Run run(const NovaHostImage *image, const char *name, const char *source, uint64_t words) {
  Run r = {0}; for (unsigned i = 0; i < 64; i++) r.out[i] = guard;
  NovaContextV2 c = {0}; CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)source, strlen(source), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, words * sizeof(uint64_t), 1);
  uint64_t args[] = {sh, strlen(source), oh, words};
  r.returned = image->entry(&c, args, 4); r.runtime_error = c.error;
  ng_parity_check(&checks, &failures, &ng_parity, name, source, r.returned);
  CHECK(nova_context_destroy_v2(&c), "context cleanup"); return r;
}
static void expect_code(const NovaHostImage *image, const char *name,
                        const char *source, uint64_t words, uint64_t code,
                        int untouched) {
  Run r = run(image, name, source, words); cases++; checks++;
  if (r.returned != code || r.runtime_error ||
      (untouched && (r.out[0] != guard || r.out[1] != guard))) {
    failures++; fprintf(stderr, "FAIL %s ret=%llu runtime=%llu out=%llu,%llu\n",
      name, (unsigned long long)r.returned, (unsigned long long)r.runtime_error,
      (unsigned long long)r.out[0], (unsigned long long)r.out[1]);
  }
}

int main(void) {
  const char *paths[] = {"tests/nova/tests/decls-entry.nova",
    "compiler/nova/frontend/decls.nova",
    "compiler/nova/analysis/semantics.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova"};
  char *sources[6] = {0}; NtFInput inputs[6];
  for (unsigned i = 0; i < 6; i++) { size_t n = 0; sources[i] = load(paths[i], &n); inputs[i] = (NtFInput){paths[i], sources[i], n}; }
  CHECK(sources[0] && sources[1] && sources[2] && sources[3] && sources[4] && sources[5], "sources load");
  NtArtifact artifact = {0}; int compiled = sources[0] && sources[1] && sources[2] && sources[3] && sources[4] && sources[5] && nova_compile_many_v2(inputs, 6, &artifact);
  CHECK(compiled, "Nova modules compile");
  if (!compiled) fprintf(stderr, "E%u %zu:%zu %s\n", artifact.error.code, artifact.error.line, artifact.error.column, artifact.error.message);
  NovaHostImage image = {0}; CHECK(compiled && nova_host_map(&artifact, &image), "image maps");
  int parity = ng_parity_begin(&ng_parity, &failures, ng_parity_err, sizeof ng_parity_err);
  if (image.memory && parity == 0) {
    const char *valid = "module m\ntarget x86_64-nexora-none\nimport math.add as add: fn(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {}\nsection .rdata {\ndata answer:u64=42\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    Run r = run(&image, "valid", valid, 19); cases++; checks++;
    if (r.returned || r.runtime_error || r.out[0] != 3 || r.out[1] != 9 ||
        r.out[2] != 0 || r.out[5] != 2 || r.out[7] != 24 || r.out[8] == 0 ||
        r.out[11] != 0 || r.out[13] != 18 || r.out[14] == 0 || r.out[17] != 0) {
      failures++; fprintf(stderr, "FAIL valid declaration table\n");
    }
    const char *params = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";
    r = run(&image, "params", params, 7); cases++; checks++;
    if (r.returned || r.runtime_error || r.out[0] != 1 || r.out[1] != 18 || r.out[5] != 2) { failures++; fprintf(stderr, "FAIL function arity\n"); }
    const char *two_sections = "module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata same:u64=1\n}\nsection .text {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    r = run(&image, "two_sections", two_sections, 13); cases++; checks++;
    if (r.returned || r.runtime_error || r.out[0] != 2 || r.out[1] != 24 || r.out[7] != 18 || r.out[2] == r.out[8]) { failures++; fprintf(stderr, "FAIL section tracking\n"); }
    const char *duplicate = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    expect_code(&image, "duplicate", duplicate, 19, 300, 0);
    expect_code(&image, "short", valid, 18, 812, 1);
    expect_code(&image, "invalid", "target x86_64-nexora-none\n", 19, 800, 1);
  }
  if (image.memory) { ng_parity_finish(&ng_parity, &failures); nova_host_unmap(&image); }
  if (compiled)
    nt_artifact_free(&artifact);
  for (unsigned i = 0; i < 6; i++) free(sources[i]);
  printf("NTASM_NOVA_DECLS checks=%u failures=%u cases=%u\n", checks, failures, cases);
  return failures ? 1 : 0;
}
