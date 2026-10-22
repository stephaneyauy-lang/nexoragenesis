#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntasm_pipeline_parity.h"

/* ====================== pipeline parity ==============================
   Every non zero code this gate asserts is a CLAIM ABOUT the 34 stage
   pipeline of validate.nova, and this entry compiles a SUB-CHAIN of it:
   index, refs, calls.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source of this file through the
   41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment. */
static const NgParityPair ng_parity_pairs[]={{0,0}};
static NgParitySpec ng_parity={
  "calls",
  {"index","refs","calls"},3,
  1,
  ng_parity_pairs,0,
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];

static unsigned checks, failures, cases;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s\n", m); } } while (0)
static const uint64_t guard = UINT64_C(0xcccccccccccccccc);

static char *load(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END); long size = ftell(f); fseek(f, 0, SEEK_SET);
  char *data = size >= 0 ? malloc((size_t)size + 1) : NULL;
  if (!data || fread(data, 1, (size_t)size, f) != (size_t)size) {
    free(data); fclose(f); return NULL;
  }
  fclose(f); data[size] = 0; *length = (size_t)size; return data;
}

typedef struct { uint64_t returned, runtime_error, out[6]; } Run;
static Run run(const NovaHostImage *image, const char *name, const char *source, uint64_t words) {
  Run r = {.out = {guard, guard, guard, guard, guard, guard}};
  NovaContextV2 context;
  if (!nova_context_init_v2(&context)) { r.runtime_error = UINT64_MAX; return r; }
  uint64_t sh = nova_borrow_v2(&context, (void *)source, strlen(source), 0);
  uint64_t oh = nova_borrow_v2(&context, r.out, words * sizeof(uint64_t), 1);
  uint64_t args[] = {sh, strlen(source), oh, words};
  r.returned = image->entry(&context, args, 4); r.runtime_error = context.error;
  CHECK(nova_context_destroy_v2(&context), "calls context cleanup");
  ng_parity_check(&checks, &failures, &ng_parity, name, source, r.returned);
  return r;
}

static void expect_ok(const NovaHostImage *image, const char *name,
                      const char *source, uint64_t decls, uint64_t calls) {
  Run r = run(image, name, source, 4); cases++; checks++;
  if (r.returned || r.runtime_error || r.out[0] != decls ||
      r.out[1] != calls || r.out[2] != calls) {
    failures++; fprintf(stderr, "FAIL ok %s ret=%llu runtime=%llu out=%llu,%llu,%llu\n",
      name, (unsigned long long)r.returned, (unsigned long long)r.runtime_error,
      (unsigned long long)r.out[0], (unsigned long long)r.out[1],
      (unsigned long long)r.out[2]);
  }
}

static void expect_code(const NovaHostImage *image, const char *name,
                        const char *source, uint64_t code) {
  Run r = run(image, name, source, 4); cases++; checks++;
  if (r.returned != code || r.runtime_error || r.out[0] == guard) {
    failures++; fprintf(stderr, "FAIL code %s ret=%llu runtime=%llu out=%llu,%llu\n",
      name, (unsigned long long)r.returned, (unsigned long long)r.runtime_error,
      (unsigned long long)r.out[0], (unsigned long long)r.out[1]);
  }
}

// Arity mismatch verdict. 311 keeps its four-word contract: out[0..1] the
// callee name position, out[2] the expected arity, out[3] the received
// arity. The too-many/too-few verdict is the optional extension, so this
// case borrows six words: out[4] is the reason (4 too many arguments,
// 5 too few, the reason numbers of call_types 354) and out[5] the
// zero-based index of the first surplus argument (reason 4) or of the
// first unsatisfied parameter (reason 5).
static void expect_arity(const NovaHostImage *image, const char *name,
                         const char *source, uint64_t line, uint64_t column,
                         uint64_t expected, uint64_t received,
                         uint64_t reason, uint64_t index) {
  Run r = run(image, name, source, 6); cases++; checks++;
  if (r.returned != 311 || r.runtime_error || r.out[0] != line ||
      r.out[1] != column || r.out[2] != expected || r.out[3] != received ||
      r.out[4] != reason || r.out[5] != index) {
    failures++;
    fprintf(stderr, "FAIL arity %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu,%llu,%llu"
      " want 311 at %llu,%llu expected=%llu received=%llu reason=%llu index=%llu\n", name,
      (unsigned long long)r.returned, (unsigned long long)r.runtime_error,
      (unsigned long long)r.out[0], (unsigned long long)r.out[1],
      (unsigned long long)r.out[2], (unsigned long long)r.out[3],
      (unsigned long long)r.out[4], (unsigned long long)r.out[5],
      (unsigned long long)line, (unsigned long long)column,
      (unsigned long long)expected, (unsigned long long)received,
      (unsigned long long)reason, (unsigned long long)index);
  }
}

static void expect_untouched(const NovaHostImage *image, const char *name,
                             const char *source, uint64_t words) {
  Run r = run(image, name, source, words); cases++; checks++;
  if (r.returned != 800 || r.runtime_error || r.out[0] != guard || r.out[1] != guard) {
    failures++; fprintf(stderr, "FAIL untouched %s ret=%llu runtime=%llu\n", name,
      (unsigned long long)r.returned, (unsigned long long)r.runtime_error);
  }
}

int main(void) {
  const char *paths[] = {"tests/nova/tests/calls-entry.nova",
    "compiler/nova/analysis/calls/calls.nova", "compiler/nova/analysis/semantics.nova",
    "compiler/nova/frontend/refs.nova",
    "compiler/nova/frontend/parser.nova", "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova"};
  char *sources[7] = {0}; NtFInput inputs[7];
  for (size_t i = 0; i < 7; i++) { size_t n = 0; sources[i] = load(paths[i], &n); inputs[i] = (NtFInput){paths[i], sources[i], n}; }
  CHECK(sources[0] && sources[1] && sources[2] && sources[3] && sources[4] && sources[5] && sources[6], "calls sources load");
  NtArtifact artifact = {0};
  int compiled = sources[0] && sources[1] && sources[2] && sources[3] && sources[4] && sources[5] && sources[6] && nova_compile_many_v2(inputs, 7, &artifact);
  CHECK(compiled, "calls Nova modules compile");
  if (!compiled) fprintf(stderr, "Nova compile E%u %zu:%zu %s\n", artifact.error.code, artifact.error.line, artifact.error.column, artifact.error.message);
  NovaHostImage image = {0}; CHECK(compiled && nova_host_map(&artifact, &image), "calls image maps");
  int parity = ng_parity_begin(&ng_parity, &failures, ng_parity_err, sizeof ng_parity_err);
  if (image.memory && parity == 0) {
    const char *zero_arg = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_ok(&image, "zero_arg", zero_arg, 2, 1);
    const char *many_args = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in x:u64 @rcx,in y:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1,2)\nreturn 0\n}\n}\n";
    expect_ok(&image, "many_args", many_args, 2, 1);
    const char *import_alias = "module m\ntarget x86_64-nexora-none\nimport math.add as add: fn(in x:u64 @rcx,in y:u64 @rdx)->u64\neffects {}\nclobbers {}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall add(1,2)\nreturn 0\n}\n}\n";
    expect_ok(&image, "import_alias", import_alias, 2, 1);
    const char *expr_call = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {} {\nreturn helper()\n}\n}\n";
    expect_ok(&image, "expr_call", expr_call, 2, 1);
    const char *too_few = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_code(&image, "too_few", too_few, 311);
    const char *too_many = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1,2)\nreturn 0\n}\n}\n";
    expect_code(&image, "too_many", too_many, 311);
    const char *absent = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall absent()\nreturn 0\n}\n}\n";
    expect_code(&image, "absent", absent, 310);
    const char *out_only = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(out x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_ok(&image, "out_only", out_only, 2, 1);
    const char *inout_missing = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(inout x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_code(&image, "inout_missing", inout_missing, 311);
    const char *mixed = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in a:u64 @rcx,out b:u64 @rdx,inout c:u64 @r8)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1,2)\nreturn 0\n}\n}\n";
    expect_ok(&image, "mixed directions", mixed, 2, 1);
    // An explicit abi clause is also a kind 28 node whose first child is a
    // dashed name (kind 92), not a qualified name (kind 91). It is not a call.
    const char *explicit_abi = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_ok(&image, "explicit_abi", explicit_abi, 2, 1);
    const char *explicit_abi_arity = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in x:u64 @rcx)->u64\nabi nx64-abi-v0\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_code(&image, "explicit_abi_arity", explicit_abi_arity, 311);
    // ---- Arity family: exact, one too few, many too few, one too many,
    // ---- many too many, surplus on a consuming callee, surplus on an
    // ---- imported callee, surplus on a callee whose slot is `out`,
    // ---- nested calls, and the position plus index of both directions.
    const char *exact_one = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n";
    expect_ok(&image, "exact_one", exact_one, 2, 1);
    const char *exact_four = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in a:u64 @rcx,in b:u64 @rdx,in c:u64 @r8,in d:u64 @r9)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1,2,3,4)\nreturn 0\n}\n}\n";
    expect_ok(&image, "exact_four", exact_four, 2, 1);
    const char *one_too_few = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n";
    expect_arity(&image, "one_too_few", one_too_few, 12, 6, 2, 1, 5, 1);
    const char *many_too_few = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in a:u64 @rcx,in b:u64 @rdx,in c:u64 @r8,in d:u64 @r9)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1,2)\nreturn 0\n}\n}\n";
    expect_arity(&image, "many_too_few", many_too_few, 12, 6, 4, 2, 5, 2);
    const char *none_two_params = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_arity(&image, "none_two_params", none_two_params, 12, 6, 2, 0, 5, 0);
    const char *one_too_many = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in a:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1,2)\nreturn 0\n}\n}\n";
    expect_arity(&image, "one_too_many", one_too_many, 12, 6, 1, 2, 4, 1);
    const char *many_too_many = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1,2,3,4,5)\nreturn 0\n}\n}\n";
    expect_arity(&image, "many_too_many", many_too_many, 12, 6, 2, 5, 4, 2);
    const char *too_many_import = "module m\ntarget x86_64-nexora-none\nimport math.add as add: fn()->u64\neffects {}\nclobbers {}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall add(1)\nreturn 0\n}\n}\n";
    expect_arity(&image, "too_many_import", too_many_import, 10, 6, 0, 1, 4, 0);
    // An `out` parameter consumes no argument, so the surplus argument
    // handed to a (in, out) signature is a real too-many, not a legal write.
    const char *out_surplus = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in a:u64 @rcx,out b:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1,2)\nreturn 0\n}\n}\n";
    expect_arity(&image, "out_surplus", out_surplus, 12, 6, 1, 2, 4, 1);
    const char *out_only_arg = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(out b:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n";
    expect_arity(&image, "out_only_arg", out_only_arg, 12, 6, 0, 1, 4, 0);
    // The same `out` in the middle of a signature consumes nothing: two
    // arguments still satisfy (in, out, inout).
    const char *out_middle_exact = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in a:u64 @rcx,out b:u64 @rdx,inout c:u64 @r8)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1,2)\nreturn 0\n}\n}\n";
    expect_ok(&image, "out_middle_exact", out_middle_exact, 2, 1);
    const char *early_out_too_few = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(out b:u64 @rcx,in a:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_arity(&image, "early_out_too_few", early_out_too_few, 12, 6, 1, 0, 5, 0);
    const char *nested_stmt_too_few = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn inner(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn outer(in a:u64 @rcx)->u64\neffects {}\nclobbers {} {\ncall inner(a)\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall outer(1)\nreturn 0\n}\n}\n";
    expect_arity(&image, "nested_stmt_too_few", nested_stmt_too_few, 12, 6, 2, 1, 5, 1);
    const char *nested_expr_too_many = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn inner(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn outer(in a:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn main()->u64\neffects {}\nclobbers {} {\nreturn inner(outer(1),2,3)\n}\n}\n";
    expect_arity(&image, "nested_expr_too_many", nested_expr_too_many, 17, 8, 2, 3, 4, 2);
    // ---- Direction anchor. parser.nova builds the parameter node before it
    // ---- steps over the direction keyword, so parameter.start opens on
    // ---- `in`/`out`/`inout` and never on the name. A name that begins with
    // ---- a direction word must not change the verdict: `in outbound`
    // ---- consumes one argument, `out outbound` consumes none. Each pair
    // ---- below is one exact-arity case (verdict only) and one mismatch case
    // ---- (verdict plus reason and index).
    const char *in_outbound_ok = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in outbound:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn outbound\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n";
    expect_ok(&image, "in_outbound_ok", in_outbound_ok, 2, 1);
    const char *in_outbound_missing = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in outbound:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn outbound\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_arity(&image, "in_outbound_missing", in_outbound_missing, 12, 6, 1, 0, 5, 0);
    const char *out_input_ok = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(out input:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_ok(&image, "out_input_ok", out_input_ok, 2, 1);
    const char *out_input_arg = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(out input:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n";
    expect_arity(&image, "out_input_arg", out_input_arg, 12, 6, 0, 1, 4, 0);
    const char *inout_outer_ok = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(inout outer:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn outer\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n";
    expect_ok(&image, "inout_outer_ok", inout_outer_ok, 2, 1);
    const char *inout_outer_missing = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(inout outer:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn outer\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_arity(&image, "inout_outer_missing", inout_outer_missing, 12, 6, 1, 0, 5, 0);
    const char *in_inoutbox_ok = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in inoutbox:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn inoutbox\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n";
    expect_ok(&image, "in_inoutbox_ok", in_inoutbox_ok, 2, 1);
    const char *in_inoutbox_missing = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in inoutbox:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn inoutbox\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_arity(&image, "in_inoutbox_missing", in_inoutbox_missing, 12, 6, 1, 0, 5, 0);
    const char *out_outbound_arg = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(out outbound:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n";
    expect_arity(&image, "out_outbound_arg", out_outbound_arg, 12, 6, 0, 1, 4, 0);
    expect_untouched(&image, "short", zero_arg, 2);
    expect_untouched(&image, "short", zero_arg, 2);
  }
  if (image.memory) { ng_parity_finish(&ng_parity, &failures); nova_host_unmap(&image); }
  if (compiled) nt_artifact_free(&artifact);
  for (size_t i = 0; i < 7; i++) free(sources[i]);
  printf("NTASM_NOVA_CALLS checks=%u failures=%u cases=%u\n", checks, failures, cases);
  return failures ? 1 : 0;
}
