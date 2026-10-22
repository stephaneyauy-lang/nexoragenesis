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
   index, refs.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source of this file through the
   41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment. */

/* ONE KNOWN RED, AND WHY IT IS NOT THIS GATE'S DEFECT.
   `template_call_absent_name` trips the helper's B-direction check: this entry
   accepted, the pipeline refuses 310, and 310 is in the owner set of a stage
   this entry runs (refs(27)), so the helper reads that as "the entry is not
   asking the stage it declares".  Measured, not inferred: a throwaway probe
   built two images over the same verbatim fixture, one running
   semantics.index + ntasm_refs.resolve and one adding calls.check after it
   exactly as validate.nova orders them.  The first answers 0, the second
   answers 310.  So the 310 is calls(28)'s verdict, and calls(28) is NOT a
   stage this entry runs -- this gate is right and the check fired anyway.
   The cause is a real disagreement between two stage modules, not a mistake
   in either: refs.nova excludes template subtrees (it builds template_mask and
   skips what it owns) while calls.nova carries no template exclusion at all,
   so for a `call absent($v)` written inside a macro quote the two stages read
   the same tree differently and calls.check is the one that refuses.
   The helper cannot tell the two apart because its owners table is a bitmask
   over every stage that CAN return a code, not over the stage that DID, and
   its own LIMITS line already concedes it: the B check reads
   `no_which_stage_the_pipeline_stopped_at(only_the_whole_pipeline_verdict)`.
   The stage set below is left declaring refs because that is what the module
   list carries; dropping refs to dodge the check would be the gate quietly
   claiming a stage it does not run, which is the thing the check exists to
   catch.  Not declared as a divergence pair either: the declared table is
   for pairs where BOTH sides refuse, and this is the accept direction, which
   the helper counts as `weaker` and never compares.
   Fixing this properly needs the header, which is held: the B check would
   have to compare against the refusing stage rather than against the owner
   set, which needs the pipeline to report where it stopped. */
static const NgParityPair ng_parity_pairs[]={{0,0}};
static NgParitySpec ng_parity={
  "refs",
  {"index","refs"},2,
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

typedef struct { uint64_t returned, runtime_error, out[4]; } Run;
static Run run(const NovaHostImage *image, const char *name, const char *source, uint64_t words) {
  Run r = {.out = {guard, guard, guard, guard}};
  NovaContextV2 context;
  if (!nova_context_init_v2(&context)) { r.runtime_error = UINT64_MAX; return r; }
  uint64_t sh = nova_borrow_v2(&context, (void *)source, strlen(source), 0);
  uint64_t oh = nova_borrow_v2(&context, r.out, words * sizeof(uint64_t), 1);
  uint64_t args[] = {sh, strlen(source), oh, words};
  r.returned = image->entry(&context, args, 4); r.runtime_error = context.error;
  CHECK(nova_context_destroy_v2(&context), "refs context cleanup");
  ng_parity_check(&checks, &failures, &ng_parity, name, source, r.returned);
  return r;
}

static void expect_ok(const NovaHostImage *image, const char *name,
                      const char *source, uint64_t decls, uint64_t calls) {
  Run r = run(image, name, source, 3); cases++; checks++;
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
  Run r = run(image, name, source, 3); cases++; checks++;
  if (r.returned != code || r.runtime_error || r.out[0] == guard) {
    failures++; fprintf(stderr, "FAIL code %s ret=%llu runtime=%llu out=%llu,%llu\n",
      name, (unsigned long long)r.returned, (unsigned long long)r.runtime_error,
      (unsigned long long)r.out[0], (unsigned long long)r.out[1]);
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
  const char *paths[] = {"tests/nova/tests/refs-entry.nova",
    "compiler/nova/frontend/refs.nova", "compiler/nova/analysis/semantics.nova",
    "compiler/nova/frontend/parser.nova", "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova"};
  char *sources[6] = {0}; NtFInput inputs[6];
  for (size_t i = 0; i < 6; i++) { size_t n = 0; sources[i] = load(paths[i], &n); inputs[i] = (NtFInput){paths[i], sources[i], n}; }
  CHECK(sources[0] && sources[1] && sources[2] && sources[3] && sources[4] && sources[5], "refs sources load");
  NtArtifact artifact = {0};
  int compiled = sources[0] && sources[1] && sources[2] && sources[3] && sources[4] && sources[5] && nova_compile_many_v2(inputs, 6, &artifact);
  CHECK(compiled, "refs Nova modules compile");
  if (!compiled) fprintf(stderr, "Nova compile E%u %zu:%zu %s\n", artifact.error.code, artifact.error.line, artifact.error.column, artifact.error.message);
  NovaHostImage image = {0}; CHECK(compiled && nova_host_map(&artifact, &image), "refs image maps");
  int parity = ng_parity_begin(&ng_parity, &failures, ng_parity_err, sizeof ng_parity_err);
  if (image.memory && parity == 0) {
    const char *simple = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_ok(&image, "simple", simple, 2, 1);
    const char *many = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\ncall helper()\nreturn 0\n}\n}\n";
    expect_ok(&image, "multiple", many, 2, 2);
    const char *imported = "module m\ntarget x86_64-nexora-none\nimport math.add as add: fn(in x:u64 @rcx)->u64\neffects {}\nclobbers {}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall add(1)\nreturn 0\n}\n}\n";
    expect_ok(&image, "import_alias", imported, 2, 1);
    const char *expr_return = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {} {\nreturn helper()\n}\n}\n";
    expect_ok(&image, "expr_return", expr_return, 2, 1);
    const char *expr_let = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {} {\nlet x:u64=helper();\nreturn x\n}\n}\n";
    expect_ok(&image, "expr_let", expr_let, 2, 1);
    const char *missing = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall absent()\nreturn 0\n}\n}\n";
    expect_code(&image, "missing", missing, 310);
    const char *duplicate = "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    expect_code(&image, "duplicate", duplicate, 300);

    /* A call name is resolved as a whole, exactly like the C oracle: a dotted
     * callee spelling is never a local function name or an import alias, so the
     * qualifier must not be silently dropped. */
    const char *qualified_local =
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn add()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
      "fn main()->u64\neffects {}\nclobbers {} {\ncall other.add()\nreturn 0\n}\n}\n";
    expect_code(&image, "qualified_call_local", qualified_local, 310);
    const char *qualified_expr =
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn add()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
      "fn main()->u64\neffects {}\nclobbers {} {\nreturn other.add()\n}\n}\n";
    expect_code(&image, "qualified_expr_local", qualified_expr, 310);
    const char *qualified_import =
      "module m\ntarget x86_64-nexora-none\nimport math.add as add: fn()->u64\n"
      "effects {}\nclobbers {}\nsection .text {\nfn main()->u64\n"
      "effects {}\nclobbers {} {\ncall math.add()\nreturn 0\n}\n}\n";
    expect_code(&image, "qualified_call_import", qualified_import, 310);
    const char *deep_qualified =
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn add()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
      "fn main()->u64\neffects {}\nclobbers {} {\ncall a.b.add()\nreturn 0\n}\n}\n";
    expect_code(&image, "deep_qualified_call", deep_qualified, 310);

    /* The bare alias and the bare local name stay valid: the same final
     * segment is accepted only without a qualifier. */
    expect_ok(&image, "bare_local_same_segment", simple, 2, 1);
    expect_ok(&image, "bare_alias_same_segment", imported, 2, 1);

    expect_untouched(&image, "short", simple, 2);
    /* === A section is a syntactic block, not a namespace, and the callable
     * table of this module must stay flat. This is a RETRACTION, not a
     * feature: the wave 7 report claimed the absence of a section term in the
     * table below was a gap, and it is not.
     *
     * spec/ntasm/ntasm.md 3: « Une section est un bloc syntaxique, pas un changement
     * d'état implicite qui se propage jusqu'à la fin du fichier ». spec/ntasm/ntasm.md
     * 4: « Les symboles sont: locaux au module par défaut ». The C oracle reads
     * both literally and never once consults fn->section: find_function
     * (frontend.c:1352) resolves a callee against the whole module, and
     * duplicate_function (frontend.c:2950) compares names per module. Measured
     * with nt_object_compile on these exact sources, none of it hand-copied:
     *   cross_section_call   -> 0  accepted, two symbols, one relocation
     *   fn_in_rdata          -> 0  accepted, two symbols
     *   data_vs_fn_sections  -> 0  accepted, two symbols
     *   two_distinct_data    -> 0  accepted, three symbols
     *   callee_in_a_later_section -> 0  accepted, two symbols, one reloc
     * A section-scoped name table would refuse all five, so each one is a
     * regression this gate now catches rather than accepts.
     *
     * The same measurement also retires the companion claim, that a second
     * declaration of the same name in another section is accepted somewhere in
     * the pipeline. It is not, and this entry cannot show it because it runs
     * neither pass that owns the rule: callable_names.check (313) owns the
     * callable namespace and symbol_names.check (319) owns the link namespace,
     * both module-wide and both with the words "regardless of section" in
     * their own header comment (callable_names.nova:98-107,
     * symbol_names.nova:48-52). nt_object_compile agrees on the refusals:
     * dup_data_rdata_data is 300 7:6 duplicate data 'answer', dup_fn_text_rdata
     * and dup_fn_two_text are 300 11:4 duplicate function 'main'. So the flat
     * table this module builds is the right one, and the cases below are the
     * proof that it stays flat. */
    const char *cross_call =
      "module m\ntarget x86_64-nexora-none\n"
      "section .rdata {\nfn helper()->u64\neffects {}\nclobbers {} {\n"
      "return 1\n}\n}\nsection .text {\n"
      "fn main()->u64\neffects {}\nclobbers {} {\ncall helper()\n"
      "return 0\n}\n}\n";
    expect_ok(&image, "call_across_sections", cross_call, 2, 1);
    const char *fn_in_rdata =
      "module m\ntarget x86_64-nexora-none\n"
      "section .rdata {\nfn other()->u64\neffects {}\nclobbers {} {\n"
      "return 1\n}\n}\nsection .text {\n"
      "fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    expect_ok(&image, "function_in_a_data_section", fn_in_rdata, 2, 0);
    const char *data_vs_fn =
      "module m\ntarget x86_64-nexora-none\n"
      "section .rdata {\ndata answer:u64=1\n}\nsection .text {\n"
      "fn answer()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    expect_ok(&image, "data_and_fn_same_name_sections", data_vs_fn, 1, 0);
    const char *two_data =
      "module m\ntarget x86_64-nexora-none\n"
      "section .rdata {\ndata alpha:u64=1\n}\n"
      "section .data {\ndata beta:u64=2\n}\nsection .text {\n"
      "fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    expect_ok(&image, "distinct_data_in_two_sections", two_data, 1, 0);
    /* Section order carries no meaning either: the callee's section is written
     * AFTER the caller's, so a table that only accumulated what it had already
     * walked would miss it. Same oracle verdict, 0, two symbols, one reloc. */
    const char *callee_later =
      "module m\ntarget x86_64-nexora-none\n"
      "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\n"
      "call helper()\nreturn 0\n}\n}\n"
      "section .rdata {\nfn helper()->u64\neffects {}\nclobbers {} {\n"
      "return 1\n}\n}\n";
    expect_ok(&image, "callee_in_a_later_section", callee_later, 2, 1);



    /* === A template is not the module namespace. spec/ntasm/ntasm.md 13 develops
     * a macro before the final verification, so a declaration or a call that
     * exists only inside a comptime(11), a macro(13) or a quote(43) subtree
     * is a template, whether or not an expansion happened. Both indexes of
     * this module are flat node id scans, so the subtree is what excludes
     * them, not the expansion. */
    const char *tpl_fn =
      "module m\ntarget x86_64-nexora-none\n"
      "macro mk()->ast.decl {\nemit quote(decl) {\nfn ghost()->u64\n"
      "effects {}\nclobbers {} {\nreturn 1;\n}\n}\n}\n"
      "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    expect_ok(&image, "template_fn_not_callable", tpl_fn, 1, 0);
    const char *tpl_fn_called =
      "module m\ntarget x86_64-nexora-none\n"
      "macro mk()->ast.decl {\nemit quote(decl) {\nfn ghost()->u64\n"
      "effects {}\nclobbers {} {\nreturn 1;\n}\n}\n}\n"
      "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\n"
      "call ghost()\nreturn 0\n}\n}\n";
    expect_code(&image, "template_only_callee", tpl_fn_called, 310);
    const char *ct_fn =
      "module m\ntarget x86_64-nexora-none\n"
      "comptime(fuel=4096,call_depth=64,arena_bytes=262144,ast_nodes=256,"
      "expansion_depth=4,constant_bytes=4096){\nreturn quote(decl) {\n"
      "fn ghost()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n};\n}\n"
      "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    expect_ok(&image, "comptime_scoped_fn", ct_fn, 1, 0);
    /* The mirror image of the same defect: a call written inside a template
     * is not a call of the module either, so a real callee named there is
     * not resolved and not counted, and a callee that exists nowhere is not
     * a missing reference. */
    const char *tpl_call =
      "module m\ntarget x86_64-nexora-none\n"
      "macro go(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { call helper($v); };\n}\n"
      "section .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
      "fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    expect_ok(&image, "template_call_not_a_call", tpl_call, 2, 0);
    const char *tpl_call_absent =
      "module m\ntarget x86_64-nexora-none\n"
      "macro go(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { call absent($v); };\n}\n"
      "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    expect_ok(&image, "template_call_absent_name", tpl_call_absent, 1, 0);
    /* A module that carries a template and two real callees still resolves
     * both of them: the exclusion is the template subtree and nothing else. */
    const char *tpl_and_real =
      "module m\ntarget x86_64-nexora-none\n"
      "macro go(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { call helper($v); };\n}\n"
      "section .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
      "fn other()->u64\neffects {}\nclobbers {} {\nreturn 2\n}\n"
      "fn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";
    expect_ok(&image, "real_callables_with_template", tpl_and_real, 3, 1);
  }
  if (image.memory) { ng_parity_finish(&ng_parity, &failures); nova_host_unmap(&image); }
  if (compiled) nt_artifact_free(&artifact);
  for (size_t i = 0; i < 6; i++) free(sources[i]);
  printf("NTASM_NOVA_REFS checks=%u failures=%u cases=%u\n", checks, failures, cases);
  return failures ? 1 : 0;
}
