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
   index (semantics), callable_names, types, refs, calls,
   initializer_types.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source this file asserts through
   the 41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment.

     {359,352}  one case, "nested shadow two levels": the fixture nests two
                `let x` of u32 and u8 inside a `let x:u64`, and reads the
                innermost one in `let y:u64=x`.  359 belongs to stage 30,
                initializer_types, which is the LAST stage this entry links
                and which answers a let initializer that does not match the
                type its own position ordered resolution gives the name --
                the right answer to the question stage 30 asks.  The
                pipeline instead stops at stage 24, return_types, which runs
                six stages earlier and never asks about let initializers at
                all: it walks the RETURN nodes, reads the declared type of
                the name each returns, and compares it to the function's
                declared return type.  The middle `return x` names the
                `let x:u32`, so 352 is that stage's answer to a different
                line of a different construct.  Same source, two refusals,
                neither one wrong for the stage that made it.

     {360,375}  one case, "initializer bool proof depth 65": the fixture is
                64 `!` operators over a `bool` parameter.  360 belongs to
                stage 30, initializer_types, and names the unproved name the
                prover could not discharge before its own budget ran out.
                The pipeline stops at stage 1, expand, because
                macro_expand.nova walks the whole tree with
                `walk_depth_cap()` = 64 and answers 375 reason 9 -- a
                template walk past its nesting bound -- long before any of
                stages 8..30 is reached.  375 is outside the 300..365
                attribution table the helper prints messages from, so the
                FAIL line says "unattributed" for it; the code and the
                reason were read out of macro_expand.nova, not guessed.

   The stage set of this entry is a link set -- semantics.index, then
   callable_names, then types, then refs, then calls, then
   initializer_types -- and not a prefix of the 34 stage order (expand,
   targets, versions and features are all missing ahead of it), so the two
   sides are being asked different questions and equality of verdicts is not
   available here.  The helper says so in its own banner on every run
   (prefix=no) rather than leaving it to this comment. */
static const NgParityPair ng_parity_pairs[]={{359,352},{360,375}};
static NgParitySpec ng_parity={
  "initializer_types",
  {"index","callable_names","types","refs","calls","initializer_types"},6,
  1,
  ng_parity_pairs,
  (unsigned)(sizeof ng_parity_pairs / sizeof ng_parity_pairs[0]),
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[7];}Run;static Run run(const NovaHostImage*i,const char*name,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");ng_parity_check(&checks,&failures,&ng_parity,name,s,r.returned);return r;}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t locals,uint64_t names,uint64_t calls,uint64_t literals){Run r=run(i,n,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=locals||r.out[1]!=names||r.out[2]!=calls||r.out[3]!=literals){failures++;fprintf(stderr,"FAIL ok %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.runtime,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* A refusal must publish the exact line and column of the offending
   initializer together with its reason. */
static void err_at(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t reason,uint64_t line,uint64_t column){Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=reason||r.out[3]!=0){failures++;fprintf(stderr,"FAIL err %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu want %llu reason %llu at %llu:%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.runtime,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3],(unsigned long long)code,(unsigned long long)reason,(unsigned long long)line,(unsigned long long)column);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,n,s,words);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL bad %s ret=%llu runtime=%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.runtime);}}
/* === U13: the operand-form axis, one question asked of BOTH sides ========
 *
 * spec/ntasm/ntasm.md 6.1 froze the closed set of operand forms of a machine
 * instruction, and the reference applies it in frontend.c:5427-5450: the
 * `mov` case is a MNEMONIC special case with a shape guard, evaluated
 * before the general operand path. Until now nothing in the tree asked the
 * product and the reference the same question on that axis, so a rule could
 * move on one side alone and no gate would see it. This block is that
 * question, at run time, on both sides, compared only afterwards.
 *
 * The two measurements are deliberately of DIFFERENT kinds, because the
 * axis is a boolean and the two sides do not share a code space:
 *
 *  - the product's answer is the return code of the REAL 34 stage pipeline,
 *    validate.validate, over the whole module. Not a table of literals and
 *    not a single stage: the shapes below are decided by different stages
 *    (a name in a destination is 336 from body_clobbers, a name as an
 *    arithmetic source is accepted by all 34, a width mismatch is accepted
 *    by all 34), so asking one stage would answer a different question.
 *  - the reference's answer is NtFProgram.verified out of nt_frontend_compile.
 *    The RETURN VALUE IS NOT THE VERDICT and the trap is measured: it is 1
 *    on a verified program and 0 on a refused one, so `rc == 0` as
 *    "accepted" inverts every row here. `verified` is read because it is
 *    the documented field.
 *
 *    The first draft of this comment claimed rc and verified COINCIDE on
 *    this corpus, on the grounds that the validate gate's corpus cannot
 *    tell them apart. That was carried over without being measured HERE,
 *    and it is FALSE for this corpus: instrumenting the two side by side
 *    over all 65 rows prints a difference on 2 of them. rc and verified are
 *    therefore NOT interchangeable here, which is a stronger reason to
 *    read `verified` than the documented-field argument alone. The claim
 *    is stated as a measurement and not as a general truth about the two
 *    fields: which rows differ is a property of this corpus.
 *
 * WHERE THE CHECK HAS TO LIVE, and why not here in the product. The rule
 * needs three things at once: the MNEMONIC, the OPERAND ORDINAL, and the
 * name RESOLVED to a binding of the current function at a known width.
 * Measured, the three live in three different modules and no single Nova
 * pass holds all three today:
 *
 *  - the name resolver is initializer_types.named_type_at, and it is the
 *    only resolver in the tree. It is called from five sites (the let
 *    initializer, the return, the call argument, the condition, and the
 *    arithmetic/bool walks) and every one of them is an EXPRESSION
 *    context: none is reached from a machine instruction, so the resolver
 *    is never handed a mnemonic or an operand ordinal and cannot see
 *    either. It knows neither. That is the shape answer: the check cannot
 *    live at the resolver.
 *  - the mnemonic and the operand ordinal live in body_clobbers, which is
 *    the one pass that reads child 0 as the mnemonic and child 1/child 2 as
 *    the operands of a kind 32 statement. It is already where a name in a
 *    DESTINATION is refused, with 336. It has the shape and not the
 *    resolution.
 *  - the register table (register_widths) is what tells a GPR operand from
 *    a NAME operand, and it is a third module again.
 *
 * WAVE 11: the check now EXISTS, in body_clobbers, and this lot measured
 * where it could and could not go before writing it. Two of the three
 * premises above turned out to be about a placement that was never the only
 * one, and both are corrected here because the next reader needs them.
 *
 * FIRST, the three-module problem is not a problem in body_clobbers, and the
 * E302 blocker quoted below does not apply to it. body_clobbers ALREADY
 * IMPORTS register_widths -- `import ntasm_ast;import clobbers;
 * import register_widths;` on its line 2 -- and every harness module list
 * that compiles body_clobbers.nova already carries register_widths.nova, so
 * hosting the check there needed no new import and no module-list change at
 * all. E302 fires only on an `import` line (nova.c:614-627 checks the import
 * tokens against the compiled module names); a qualified call to a module
 * that is among the compiler inputs resolves without being imported. So the
 * constraint is real but it binds on DECLARATION, and the pass that already
 * declares what it needs was the one to use.
 *
 * SECOND, and this is the measurement that decided the design: the general
 * branch needs NO NAME RESOLVER AT ALL. A name operand and a register
 * operand are the SAME node shape in this AST -- simple_name_id returns a
 * name node for both -- and the only thing that tells `rax` from `answer` is
 * register_widths. The reference's frontend_x64_operand (frontend.c:5272)
 * accepts a register, a memory operand, a `crN` name and a constant
 * expression, and refuses everything else WHETHER OR NOT ANYTHING DECLARES
 * IT. An undeclared name, a function name and a data symbol are all refused
 * for the same reason and with the same code, so refusing them needs no
 * resolution. Only the `mov` special case has to know that its source is a
 * VARIABLE rather than a data symbol, a function or a sibling-block let,
 * and that is twenty lines reading the same node kinds initializer_types
 * reads. It is a copy for the same reason scalar_width above is a copy of
 * register_widths' private byte test: a qualified call needs its module
 * among the compiler inputs, and three of the six harness module lists that
 * compile this pass do not carry initializer_types.
 *
 * A NEW PASS MODULE WAS NOT AN OPTION, which is why the choice was binary.
 * Adding one needs an import in validate.nova AND a row in the pipe_paths
 * list below, and that list is in this file.
 *
 * ONE KIND OF ROW, and the reason the count changed. Every row is an
 * agreement row now. The thirty-nine that were pinned as divergences are
 * re-scoped rather than deleted, and each asserts the common answer on BOTH
 * sides plus the product code 400 -- a comparison alone is satisfied by two
 * modules that refuse everything, a shape both sides ACCEPT must stay
 * accepted, and a product code that changed from 400 to some other refusal
 * would still read as agreement unless the code itself is pinned.
 *
 * The counters in the banner are the anti-vacuity guard and are computed
 * from the two sides' OWN verdicts, so a corpus that had degenerated to all
 * refusals would print accepted_by_both=0 and the checks below the loop
 * would fail on it. `diverged` is counted live from the same verdicts and is
 * asserted zero: it is what says the re-scope did not buy agreement by
 * recoding a row. */
// R545 INSTRUMENT, TEMPORAIRE. `place` in machine_ir.nova already writes the refusing
// NODE into out[0] and the line into out[1]; the gate was carrying only the code, so
// the site of a refusal could not be seen from the gate at all. Carrying the four
// words through is the smallest instrument that exists and it touches the TEST, not
// the product. Removed once 2&1 has a site -- an instrument that outlives its
// question becomes a claim about the gate.
typedef struct{int product_accept,reference_accept;uint64_t product_code;uint64_t out[7];}Operand;
static unsigned operand_rows,operand_agreed,operand_accepted_by_both,
    operand_refused_by_both,operand_diverged;
/* The reference's own answer to "does this module verify?". */
static int reference_operand(const char*s){
  NtFInput input={"operand-agreement.ntasm",s,strlen(s)};
  NtFProgram program={0};
  nt_frontend_compile(&input,1,&program);
  int verified=program.verified;
  nt_frontend_free(&program);
  return verified;
}
/* ONE question, asked of both sides, compared only afterwards. Both
 * measurements happen here; every check that consumes them is below. */
static Operand ask_operand(const NovaHostImage*i,const char*label,const char*s){
  Run r=run(i,label,s,7);   /* R545: five words, not four -- out[4] is the refusing node */
  Operand o;
  o.product_code=r.returned;
  o.product_accept=(r.returned==0&&!r.runtime)?1:0;
  o.reference_accept=reference_operand(s);
  for(int k=0;k<7;k++) o.out[k]=r.out[k];   /* R545 INSTRUMENT */
  return o;
}
/* The two sides agree, and the common answer is `want` on BOTH. Asserting
 * the common answer on each side separately is what makes the accept rows
 * load bearing: a comparison alone cannot tell "both accept" from "both
 * refuse", and only the first is correct for these shapes.
 *
 * `product_code` is the code the product answered WHEN THE COMMON ANSWER WAS
 * MEASURED, and it is asserted here so the verdict cannot move silently.
 * The verdict alone cannot see a substitution: a row the product refuses
 * with 400 today would still be a refusal if it were refused with 336
 * instead, and the comparison would call that agreement. The three codes in
 * this corpus are 0 on the seventeen accept rows, 336 on the nine
 * destination rows body_clobbers has always answered, and 400 on the
 * thirty-nine operand-form rows. Pinning all three is what makes a change of
 * CODE a red rather than a line in a diff nobody reads. */
static void agree_operand(const NovaHostImage*i,const char*label,const char*s,int want,uint64_t product_code){
  Operand o=ask_operand(i,label,s);
  operand_rows++;cases++;
  if(o.product_accept==o.reference_accept) operand_agreed++;
  else operand_diverged++;
  if(o.product_accept&&o.reference_accept) operand_accepted_by_both++;
  if(!o.product_accept&&!o.reference_accept) operand_refused_by_both++;
  checks++;
  if(o.product_accept!=o.reference_accept){
    failures++;
    fprintf(stderr,"FAIL operand agreement %s: the product %s (code %llu) and the reference %s the same source\n",
            label,o.product_accept?"accepts":"refuses",(unsigned long long)o.product_code,
            o.reference_accept?"accepts":"refuses");
    fprintf(stderr,"      R563SITE line=%llu col=%llu code=%llu node=%llu stamp=%llu stamp_line=%llu\n",
            (unsigned long long)o.out[0],(unsigned long long)o.out[1],
            (unsigned long long)o.out[2],(unsigned long long)o.out[3],
            (unsigned long long)o.out[4],(unsigned long long)o.out[5]);
  }
  checks++;
  if(o.product_accept!=want){
    failures++;
    fprintf(stderr,"FAIL operand acceptance %s: the product %s it (code %llu), the common answer is %s\n",
            label,o.product_accept?"accepts":"refuses",(unsigned long long)o.product_code,
            want?"accept":"refuse");
  }
  checks++;
  if(o.reference_accept!=want){
    failures++;
    fprintf(stderr,"FAIL operand acceptance %s: the reference %s it, wanted %d\n",
            label,o.reference_accept?"accepts":"refuses",want);
  }
  checks++;
  if(o.product_code!=product_code){
    failures++;
    fprintf(stderr,"FAIL operand product code %s: the product answered %llu, the recorded code is %llu\n",
            label,(unsigned long long)o.product_code,(unsigned long long)product_code);
    /* R549/R563. The refusal's six published fields, named. Two of the three failing
     * rows are a constant expression that this same gate asks about elsewhere and that
     * the reference accepts, so the fields are printed for EVERY disagreement and not
     * only for the code mismatch -- a row can agree with the reference and still be
     * refused for a reason the code does not name. */
    fprintf(stderr,"      R563SITE line=%llu col=%llu code=%llu node=%llu stamp=%llu stamp_line=%llu\n",
            (unsigned long long)o.out[0],(unsigned long long)o.out[1],
            (unsigned long long)o.out[2],(unsigned long long)o.out[3],
            (unsigned long long)o.out[4],(unsigned long long)o.out[5]);
  }
}
/* The operand axis is decided by DIFFERENT stages of the 34, so the product
 * answer has to come from the whole pipeline and not from the stage subset
 * the image above runs. This second image is validate.validate over the
 * complete module list, compiled here so the comparison is the real one. */
static const char*const pipe_paths[]={
"tests/nova/tests/validate-entry.nova",
"compiler/nova/analysis/validate.nova","compiler/nova/macros/macro_splice.nova",
"compiler/nova/formats/ntir/ntir.nova",
"compiler/nova/macros/macro_expand.nova",
"compiler/nova/analysis/types/constant_types.nova",
"compiler/nova/macros/constant_eval.nova",
"compiler/nova/analysis/types/initializer_types.nova",
"compiler/nova/analysis/types/condition_types.nova",
"compiler/nova/analysis/types/literal_initializers.nova",
"compiler/nova/frontend/targets.nova",
"compiler/nova/frontend/versions.nova",
"compiler/nova/analysis/abi/feature_requirements.nova",
"compiler/nova/analysis/abi/features.nova",
"compiler/nova/analysis/types/pointer_spaces.nova",
"compiler/nova/analysis/control_flow.nova",
"compiler/nova/analysis/types/return_types.nova",
"compiler/nova/analysis/abi/body_clobbers.nova",
"compiler/nova/analysis/abi/body_intrinsics.nova",
"compiler/nova/analysis/abi/body_effects.nova",
"compiler/nova/analysis/calls/call_contracts.nova",
"compiler/nova/analysis/abi/abi.nova",
"compiler/nova/analysis/calls/call_clobbers.nova",
"compiler/nova/analysis/calls/call_effects.nova",
"compiler/nova/analysis/calls/call_types.nova",
"compiler/nova/analysis/calls/calls.nova",
"compiler/nova/frontend/refs.nova",
"compiler/nova/analysis/abi/clobbers.nova",
"compiler/nova/analysis/abi/contracts.nova",
"compiler/nova/analysis/abi/effects.nova",
"compiler/nova/analysis/types/register_widths.nova",
"compiler/nova/frontend/register_bindings.nova",
"compiler/nova/frontend/bindings.nova",
"compiler/nova/frontend/locals.nova",
"compiler/nova/frontend/parameters.nova",
"compiler/nova/analysis/types/types.nova",
"compiler/nova/frontend/symbol_names.nova",
"compiler/nova/analysis/calls/callable_names.nova",
"compiler/nova/analysis/semantics.nova",
"compiler/nova/frontend/parser.nova",
"compiler/nova/frontend/ast.nova",
"compiler/nova/frontend/lexer.nova",
/* machine_ir.nova, because validate.nova IMPORTS it (toolchain/
 * ntasm-nova/validate.nova:43) and calls machine_ir.lower and
 * machine_ir.verify at stage 35.  A list that does not carry it compiles
 * nothing: the product refuses with `E302 <line>:<col> Nova imported module
 * is not among compiler inputs', and the refusal is CORRECT -- it is a fact
 * about this list, not about the compiler.  ng_parity_paths in
 * ntasm_pipeline_parity.h carries the same row for the same reason. */
"compiler/nova/ir/machine_ir.nova"};
enum{PIPE_N=(int)(sizeof pipe_paths/sizeof pipe_paths[0])};
/* Every operand row is a COMPLETE module: the reference reads clobbers and
 * effects itself, so a fixture whose only defect were an undeclared clobber
 * would be refused by BOTH sides for a reason that has nothing to do with
 * the operand form, and the row would measure nothing. Each source below
 * therefore declares the clobbers and effects its own instruction needs. */
static const char*operand_sources[]={
/* A, the four accepted operand forms. Both sides must accept each. */
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,rcx\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,7\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmov rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(inout answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmov rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u32 @ebx)->u64\neffects {}\nclobbers {rax} {\nmov eax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u8 @bl)->u64\neffects {}\nclobbers {rax} {\nmov al,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nlet t:u64=1\nmov rax,t\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nif true {\nlet t:u64=1\nmov rax,t\n}\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nconst limit:u64=99\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,limit\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nconst limit:u32=99\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov eax,limit\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata seed:u64=42\n}\nsection .text {\nfn f()->u64\neffects {reads_mem}\nclobbers {rax} {\nmov rax,[seed]:ptr<user,u64>\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,1+1\nreturn 0\n}\n}\n",
/* A2, THE CONSTANT EXPRESSION OPERAND, spelled thirteen more ways. The row
 * above ("A constant expression", `mov rax,1+1`) was already an ACCEPT row
 * here, and the product CRASHED on it: rc=139, SEGV, on the binary built by
 * scripts/ntbuild.sh. Every form in this block reached the same place --
 * frontend.c's `frontend_x64_operand` folded the expression with
 * `constant_value` and answered NT_X64_IMM without recording the fold, so
 * codegen.c's `evaluate_constant` read a node that carried no record, the
 * mixed-`mov` arm fired on a node `infer` had never typed, and
 * `normalize_type(g, 0, span)` read `types[-1]`.
 *
 * So this block is not a new rule and these are not new forms: it is ONE row
 * that already existed, measured thirteen more times. The population is not
 * sampled, it is derived -- `constant_value` folds exactly these binary
 * operators (ADD SUB MUL DIV MOD AND OR XOR SHL SHR EQ NE LT LE GT GE) and
 * these three unary ones (POS NEG NOT), so a row per family is a partition of
 * the foldable set rather than four data points with a mechanism attached.
 * The parenthesised and the left-associated rows are here because parsing is
 * a separate question from folding: `(1+2)` and `1+2+3` build different
 * trees and a fix that only handled a flat left/right pair would pass the
 * other eleven. The const row is here because `limit` is an NTF_X_NAME leaf
 * under the arithmetic, not a literal, and the 5544 inference arm that types
 * a bare `mov rax,limit` does not reach it. `1 + 2` is a row of its own and
 * not a duplicate of `1+2` because the two spellings reach the lexer
 * differently and only one of them was named in the defect report. */
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,1+2\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,1 + 2\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,3*4\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,-1\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,!0\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,~0\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,7-2\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,8/2\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,6&3\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,1<2\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,(1+2)\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,1+2+3\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nconst limit:u64=99\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,limit+1\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nadd rax,rbx\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nadd rax,7\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {rax} {\nmov rax,p\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in c:u16 @cx)->u64\neffects {}\nclobbers {rax} {\nmov ax,c\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in c:i32 @ecx)->u64\neffects {}\nclobbers {rax} {\nmov eax,c\nreturn 0\n}\n}\n",
/* B, a name as the SOURCE of a mnemonic other than mov. The reference
 * refuses each in 400, and wave 11 measured the product refusing each in
 * 400 too, after it accepted every one of them through all 34 stages. One
 * row per mnemonic, so a single mnemonic regaining the name form is a red
 * on its own row and not a change in a total. */
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nadd rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nsub rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\ncmp rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nand rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nor rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nxor rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nadc rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nsbb rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\ntest rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nimul rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nshl rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nshr rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nsar rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nrol rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nror rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nlea rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmovzx eax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmovsx eax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmovsxd rax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nlet t:u64=1\nadd rax,t\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nlet t:u64=1\nmovzx eax,t\nreturn 0\n}\n}\n",
/* C, a name in the DESTINATION. Here the two sides already REFUSE, and they
 * refuse for the same reason: the product with 336 from body_clobbers,
 * which is the one pass that reads a kind 32 statement's mnemonic and its
 * ordinal operands. These rows are the negative direction of the axis and
 * they are what the B rows are measured against: the destination is
 * already closed, the source is not. */
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nadd answer,rbx\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmov answer,rax\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\ninc answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\ndec answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nnot answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nneg answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax} {\npop answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmov answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nxchg rax,answer\nreturn 0\n}\n}\n",
/* D, width. The reference refuses each in 400 with its own message, "mov
 * variable width does not match destination", and wave 11 measured the
 * product refusing each in 400 too. This is the one block that needed the
 * binding lookup: the destination register width has to be compared with
 * the DECLARED width of a variable, which is the only place on this axis
 * where a name has to be resolved rather than merely recognised. */
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmov eax,answer\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in c:u32 @ecx)->u64\neffects {}\nclobbers {rax} {\nmov rax,c\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in c:u8 @cl)->u64\neffects {}\nclobbers {rax} {\nmov rax,c\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in r:bool @al)->u64\neffects {}\nclobbers {rax} {\nmov al,r\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nlet t:u32=1\nmov rax,t\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {rax} {\nmov ax,p\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nconst limit:u32=9\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,limit\nreturn 0\n}\n}\n",
/* E, arity. Three operands to a two-operand mov, in the one case the
 * reference reaches its own count check -- which is the ENCODER's arity
 * answer, x64.c:756-757 NT_X64_COUNT, republished as 400 -- and in the
 * other it falls through to the general operand path, where the name
 * cannot lower. The two rows are refused for two different reasons and
 * the product now answers 400 on both. */
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmov rax,answer,rcx\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,rcx,rdx\nreturn 0\n}\n}\n",
/* F, a general expression as the source. The reference resolves a constant
 * expression to an immediate and refuses one that names a binding, which
 * is why the const_expr row above is an accept and these two are not. */
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nadd rax,answer+1\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmov rax,answer+1\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {reads_mem,writes_mem}\nclobbers {rax} {\nmov [rbx]:ptr<user,u64>,answer\nreturn 0\n}\n}\n",
/* G, a name that resolves to nothing the mixed lowering can read. The data
 * symbol is the defect the previous lot narrowed: it IS a name, resolved,
 * and the reference refuses it because a data symbol is a link and not a
 * binding. These five rows needed no resolver either -- a name that
 * resolves to nothing is refused for the same reason as one that resolves
 * to something, which is what frontend_x64_operand does. */
"module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata seed:u64=42\n}\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,seed\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata seed:u64=42\n}\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nadd rax,seed\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,nosuch\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov rax,helper\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in answer:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmov rax,other.x\nreturn 0\n}\n}\n",
"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nif true {\nlet t:u64=1\n}\nmov rax,t\nreturn 0\n}\n}\n"};
enum{OPERAND_N=(int)(sizeof operand_sources/sizeof operand_sources[0])};
/* The split is by INDEX, and the boundaries are asserted below rather than
 * trusted: A_ACCEPT rows first, then the B/C/D/E/F/G blocks. A count that
 * does not match the labels below is a gate bug, so the loop checks it. */
/* A_ACCEPT was 17 and is 30: the thirteen rows added to group A are the same
 * accept with the constant expression spelled thirteen more ways, and a count
 * left at 17 would drive them into the B block, which asserts 400 and would
 * have turned thirteen accepts into thirteen reds. The other six boundaries
 * are untouched, and `CHECK(at==OPERAND_N, ...)` in operand_block below is
 * what says the split still adds up rather than trusting these literals. */
enum{A_ACCEPT=30,B_SOURCE=21,C_DESTINATION=9,D_WIDTH=7,E_ARITY=2,F_EXPRESSION=3,G_UNRESOLVED=6};
static const char*const operand_label[OPERAND_N]={
"A gpr source","A immediate source","A parameter in","A parameter inout",
"A parameter u32 into eax","A parameter u8 into al","A let local",
"A let local in a nested block","A const u64","A const u32 into eax",
"A typed data memory","A constant expression",
"A2 constant expression, no space","A2 constant expression, spaces",
"A2 constant expression, multiply","A2 unary negative","A2 unary not",
"A2 unary bitnot","A2 constant expression, subtract",
"A2 constant expression, divide","A2 constant expression, and",
"A2 constant expression, less than","A2 constant expression, parenthesised",
"A2 constant expression, left associative",
"A2 const name plus literal","A arithmetic gpr source",
"A arithmetic immediate source","A pointer parameter","A parameter u16 into ax",
"A parameter i32 into eax",
"B add source","B sub source","B cmp source","B and source","B or source",
"B xor source","B adc source","B sbb source","B test source","B imul source",
"B shl source","B shr source","B sar source","B rol source","B ror source",
"B lea source","B movzx source","B movsx source","B movsxd source",
"B let as arithmetic source","B let as movzx source",
"C add destination","C mov destination","C inc destination","C dec destination",
"C not destination","C neg destination","C pop destination","C mov sole operand",
"C xchg second operand",
"D u64 into eax","D u32 into rax","D u8 into rax","D bool into al",
"D let u32 into rax","D pointer into ax","D const u32 into rax",
"E mov three operands with a name","E mov three register operands",
"F arithmetic expression source","F mov expression source","F memory destination",
"G data symbol as mov source","G data symbol as arithmetic source",
"G undeclared name","G function name","G qualified name","G sibling block name"};
/* Every row asks the same question and asserts a COMMON answer, on both
 * sides separately, together with the code the product answered when that
 * common answer was measured. Nothing here compares a product answer to a
 * literal copied out of the other side: the reference verdict is
 * re-measured on every run by nt_frontend_compile.
 *
 * WAVE 11 RE-SCOPE. Thirty-nine of these rows were pinned as DIVERGENCES:
 * the reference refused, the product accepted, and the recorded product code
 * was 0. The product now refuses all thirty-nine with 400, so the two sides
 * agree and the pinning did what it was built to do -- it refused to let the
 * number change without a human decision. The rows were RE-SCOPED, not
 * deleted: each is now an agreement row asserting `refuse` on BOTH sides and
 * the product code 400, which is the only shape that still fails if either
 * side drifts back. Deleting them would have put the axis back to measuring
 * nothing for those thirty-nine forms.
 *
 * The three codes in the corpus are therefore 0 on the seventeen accept
 * rows, 336 on the nine destination rows, and 400 on the thirty-nine
 * operand-form rows, and each is recorded per row rather than per block,
 * because the destination rows are 336 for a different reason than the
 * operand-form rows are 400: 336 is body_clobbers refusing a name in a
 * DESTINATION, and it was there before this axis had any source-side rule. */
static void operand_block(const NovaHostImage*i){
  int at=0;
  /* A: the negative direction. Both sides must ACCEPT, and the accept is
   * asserted on each side separately, so a corpus that had degenerated to
   * all refusals would go red here rather than pass the comparison. */
  for(int k=0;k<A_ACCEPT;k++,at++)
    agree_operand(i,operand_label[at],operand_sources[at],1,0);
  /* B: a name as the source of a mnemonic the reference does not extend the
   * mov case to. Closed in wave 11; both sides refuse with 400. */
  for(int k=0;k<B_SOURCE;k++,at++)
    agree_operand(i,operand_label[at],operand_sources[at],0,400);
  /* C: the destination half of the same axis, closed before wave 11 and
   * still 336, from the arm that reads a destination as a register family.
   * It is here so that the B block is measured against a closed half of the
   * same rule and not against a vacuous one, and so that a change of its
   * code from 336 to 400 is a red rather than a silent substitution. */
  for(int k=0;k<C_DESTINATION;k++,at++)
    agree_operand(i,operand_label[at],operand_sources[at],0,336);
  /* D, E, F, G: the width comparison, the arity, the expression source and
   * the names that resolve to nothing, all closed in wave 11 at 400. */
  for(int k=0;k<D_WIDTH;k++,at++)
    agree_operand(i,operand_label[at],operand_sources[at],0,400);
  for(int k=0;k<E_ARITY;k++,at++)
    agree_operand(i,operand_label[at],operand_sources[at],0,400);
  for(int k=0;k<F_EXPRESSION;k++,at++)
    agree_operand(i,operand_label[at],operand_sources[at],0,400);
  for(int k=0;k<G_UNRESOLVED;k++,at++)
    agree_operand(i,operand_label[at],operand_sources[at],0,400);
  CHECK(at==OPERAND_N,"every operand row is driven by exactly one block");
  /* The anti-vacuity guard, computed from the counters the rows above filled
   * from the two sides' OWN verdicts. A gate whose corpus had collapsed to
   * all refusals would satisfy every comparison and still be worthless;
   * these two numbers are what say it is not. */
  CHECK(operand_accepted_by_both==A_ACCEPT,"the operand corpus accepts on both sides");
  CHECK(operand_refused_by_both==OPERAND_N-A_ACCEPT,"the operand corpus refuses every other row on both sides");
  CHECK(operand_agreed==OPERAND_N,"every row on this axis is an agreement row");
  /* Zero, and counted LIVE: agree_operand increments this from the two
   * sides' own verdicts, so it is a measurement and not a literal. It is
   * what says the wave 11 re-scope did not quietly reintroduce a
   * disagreement by recoding a row as an agreement row. */
  CHECK(operand_diverged==0,"no row on the operand axis is a recorded divergence");
  printf("NTASM_NOVA_OPERAND_FORM rows=%u agreed=%u accepted_by_both=%u refused_by_both=%u diverged=%u\n",
         operand_rows,operand_agreed,operand_accepted_by_both,
         operand_refused_by_both,operand_diverged);
}
int main(void){const char*paths[]={"tests/nova/tests/initializer-types-entry.nova","compiler/nova/analysis/types/initializer_types.nova","compiler/nova/analysis/calls/calls.nova","compiler/nova/frontend/refs.nova","compiler/nova/analysis/types/types.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova","compiler/nova/analysis/types/register_widths.nova"};char*sources[11]={0};NtFInput inputs[11];for(unsigned i=0;i<11;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<11;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,11,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");int parity=ng_parity_begin(&ng_parity,&failures,ng_parity_err,sizeof ng_parity_err);if(image.memory&&parity==0){
 const char*name_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {} {\nlet x:u64=p\nreturn x\n}\n}\n";ok(&image,"name",name_ok,1,1,0,0);
 const char*name_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u32 @ecx)->u64\neffects {}\nclobbers {} {\nlet x:u64=p\nreturn x\n}\n}\n";err_at(&image,"name mismatch",name_bad,359,1,7,11);
 const char*call_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn value()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=value()\nreturn x\n}\n}\n";ok(&image,"call",call_ok,1,0,1,0);
 const char*call_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn value()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=value()\nreturn x\n}\n}\n";err_at(&image,"call mismatch",call_bad,359,1,12,11);
 const char*literals="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nlet ready:bool=true\nreturn x\n}\n}\n";ok(&image,"literals delegated",literals,2,0,0,2);
 const char*arithmetic="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nlet x:u64=p+1\nreturn x\n}\n}\n";ok(&image,"one-level arithmetic",arithmetic,1,0,0,1);
 const char*arithmetic_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u32 @ecx)->u64\neffects {changes_flags}\nclobbers {} {\nlet x:u64=p+1\nreturn x\n}\n}\n";err_at(&image,"arithmetic mismatch",arithmetic_bad,359,2,7,11);
 const char*nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nlet x:u64=p+(1+2)\nreturn x\n}\n}\n";ok(&image,"nested grouped arithmetic",nested,1,0,0,1);
 const char*precedence="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nlet x:u64=p+1*2\nreturn x\n}\n}\n";ok(&image,"nested precedence",precedence,1,0,0,1);
 const char*nested_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx,in q:u32 @edx)->u64\neffects {changes_flags}\nclobbers {} {\nlet x:u64=p+(q+1)\nreturn x\n}\n}\n";err_at(&image,"nested mismatch",nested_bad,359,2,7,11);
 const char*range_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u8 @cl)->u8\neffects {changes_flags}\nclobbers {} {\nlet x:u8=p+(1+256)\nreturn x\n}\n}\n";err_at(&image,"nested literal range",range_bad,359,2,7,10);
 const char*sibling="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true {\nlet x:u64=1\n}\nlet y:u64=x\nreturn y\n}\n}\n";err_at(&image,"sibling local not visible",sibling,360,1,10,11);
 const char*self_ref="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=x\nreturn x\n}\n}\n";err_at(&image,"self reference not visible",self_ref,360,1,7,11);
 const char*future="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet y:u64=x\nlet x:u64=1\nreturn y\n}\n}\n";err_at(&image,"future declaration not visible",future,360,1,7,11);
 const char*simple_local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nlet y:u64=x\nreturn y\n}\n}\n";ok(&image,"simple local name",simple_local,1,1,0,0);
 const char*qualified_local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nlet y:u64=bogus.x\nreturn y\n}\n}\n";err_at(&image,"qualified local rejected",qualified_local,360,3,7,11);
 /* A parameter is the fallback of the resolver only when no enclosing block
    declares the name, because bindings refuses a let that takes the name of
    a parameter. The inner let and the parameter therefore keep distinct
    names here, and both resolutions are still exercised. */
 const char*fallback="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif true {\nlet q:u32=1\nlet r:u32=q\n}\nlet z:u64=p\nreturn z\n}\n}\n";ok(&image,"inner local then parameter fallback",fallback,3,2,0,1);
 /* A nested let shadows an outer let of the same function: the innermost
    enclosing block answers for the name, and the type it declares is the
    one the prover uses. */
 const char*after_use="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nif true {\nlet y:u64=x\nlet x:u32=2\nreturn y\n}\nreturn x\n}\n}\n";ok(&image,"inner declaration after the use",after_use,3,1,0,2);
 const char*same_type="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nif true {\nlet x:u64=2\nlet y:u64=x\nreturn y\n}\nreturn x\n}\n}\n";ok(&image,"nested shadow of the same type",same_type,3,1,0,2);
 const char*other_type="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nif true {\nlet x:u32=2\nlet y:u64=x\nreturn y\n}\nreturn x\n}\n}\n";err_at(&image,"nested shadow of another type",other_type,359,1,10,11);
 const char*two_levels="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nif true {\nlet x:u32=2\nif true {\nlet x:u8=3\nlet y:u64=x\nreturn y\n}\nreturn x\n}\nreturn x\n}\n}\n";err_at(&image,"nested shadow two levels",two_levels,359,1,12,11);
 const char*after_block="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nif true {\nlet x:u32=2\nreturn x\n}\nlet z:u64=x\nreturn z\n}\n}\n";ok(&image,"outer name after a nested shadow",after_block,3,1,0,2);
 const char*unary_positive="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {} {\nlet x:u64=+p\nreturn x\n}\n}\n";ok(&image,"unary plus name",unary_positive,1,0,0,1);
 const char*unary_bitnot="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {} {\nlet x:u64=~p\nreturn x\n}\n}\n";ok(&image,"unary bitnot name",unary_bitnot,1,0,0,1);
 const char*unary_negative="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:i8 @cl)->i8\neffects {}\nclobbers {} {\nlet x:i8=-p\nreturn x\n}\n}\n";ok(&image,"unary negative signed name",unary_negative,1,0,0,1);
 const char*negative_min="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->i8\neffects {}\nclobbers {} {\nlet x:i8=-128\nreturn x\n}\n}\n";ok(&image,"negative signed minimum",negative_min,1,0,0,1);
 const char*negative_i16_min="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->i16\neffects {}\nclobbers {} {\nlet x:i16=-32768\nreturn x\n}\n}\n";ok(&image,"negative i16 minimum",negative_i16_min,1,0,0,1);
 const char*negative_i32_min="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->i32\neffects {}\nclobbers {} {\nlet x:i32=-2147483648\nreturn x\n}\n}\n";ok(&image,"negative i32 minimum",negative_i32_min,1,0,0,1);
 const char*negative_i64_min="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->i64\neffects {}\nclobbers {} {\nlet x:i64=-9223372036854775808\nreturn x\n}\n}\n";ok(&image,"negative i64 minimum",negative_i64_min,1,0,0,1);
 const char*negative_i64_range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->i64\neffects {}\nclobbers {} {\nlet x:i64=-9223372036854775809\nreturn x\n}\n}\n";err_at(&image,"negative i64 range",negative_i64_range,359,2,7,11);
 const char*negative_range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->i8\neffects {}\nclobbers {} {\nlet x:i8=-129\nreturn x\n}\n}\n";err_at(&image,"negative signed range",negative_range,359,2,7,10);
 const char*negative_unsigned="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u8\neffects {}\nclobbers {} {\nlet x:u8=-1\nreturn x\n}\n}\n";err_at(&image,"negative unsigned mismatch",negative_unsigned,359,2,7,10);
 const char*unary_bool="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=~true\nreturn x\n}\n}\n";err_at(&image,"unary bool rejected",unary_bool,359,2,7,11);
 const char*unary_nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:i8 @cl)->i8\neffects {}\nclobbers {} {\nlet x:i8=--p\nreturn x\n}\n}\n";ok(&image,"nested unary cardinality",unary_nested,1,0,0,1);
 const char*bool_mixed="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f(in ready:bool @al,in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nlet a:bool=!(ready) && (pred() || (x<5))\nreturn 0\n}\n}\n";ok(&image,"bool valued let mixed expression",bool_mixed,1,0,0,1);
 const char*bool_comparison="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nlet a:bool=x<5\nreturn 0\n}\n}\n";ok(&image,"bool valued let comparison",bool_comparison,1,0,0,1);
 const char*bool_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nlet a:bool=ready && !pred()\nreturn 0\n}\n}\n";ok(&image,"bool valued let with bool call",bool_call,1,0,0,1);
 const char*bool_nonbool="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al,in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nlet a:bool=ready && x\nreturn 0\n}\n}\n";err_at(&image,"bool valued let with integer operand",bool_nonbool,359,1,7,12);
 const char*bool_unproved="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nlet a:bool=ready && bogus.x\nreturn 0\n}\n}\n";err_at(&image,"bool valued let with unproved operand",bool_unproved,360,3,7,12);
 char deep_not_ok[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nlet a:bool=";for(unsigned i=0;i<63;i++)strcat(deep_not_ok,"!");strcat(deep_not_ok,"ready\nreturn 0\n}\n}\n");ok(&image,"initializer bool proof depth 64",deep_not_ok,1,0,0,1);
 char deep_not_bad[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nlet a:bool=";for(unsigned i=0;i<64;i++)strcat(deep_not_bad,"!");strcat(deep_not_bad,"ready\nreturn 0\n}\n}\n");err_at(&image,"initializer bool proof depth 65",deep_not_bad,360,3,7,12);
 /* === A5 residual: a name read UNDER AN OPERATOR. The produced let of the
    macro column is a bare `return t`; the same name one operator down was
    resolved by the position ordered search alone and answered "name not
    visible", so a produced let was visible to a produced return that read it
    directly and invisible to the same return that read it through `+`. The
    structural search now backs the position one, and it is the structural
    search that has to be told the third clause of the rule: a let is a
    parent of its own initializer, so a self reference is inside the
    declaration and is not in scope at its own use. These are the clear
    column of that walk, one case per nesting level, and the negative
    direction at each: a name that is genuinely not in scope at the use
    stays invisible, and the search that now answers must not reach a name
    the oracle does not resolve. */
 const char*op1="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet t:u64=1\nlet u:u64=t+1\nreturn u\n}\n}\n";ok(&image,"name under one operator",op1,2,0,0,2);
 const char*op2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet t:u64=1\nlet u:u64=(t+1)+1\nreturn u\n}\n}\n";ok(&image,"name under two operators",op2,2,0,0,2);
 const char*op3="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet t:u64=1\nlet u:u64=((t+1)+1)+1\nreturn u\n}\n}\n";ok(&image,"name under three operators",op3,2,0,0,2);
 /* The shadowing declaration is AFTER the use, so the use resolves against
    the outer let and the initializer is exact. A search that answered with
    the innermost declaration whatever its order would answer u32 here and
    refuse, which is what makes this the positive half of the pair below. */
 const char*op_after="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet x:u64=1\nif true {\nlet y:u64=x+1\nlet x:u32=2\nreturn y\n}\nreturn x\n}\n}\n";ok(&image,"shadow declared after the use",op_after,3,0,0,3);
 /* The shadowing declaration is BEFORE the use, so the innermost enclosing
    block answers and the type it declares is the one the prover uses: u32
    against a u64 initializer, a proved mismatch and not an unproved name.
    The bare form of this is the "nested shadow of another type" case above;
    this is the same question asked of the walk that changed. */
 const char*op_shadow="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet x:u64=1\nif true {\nlet x:u32=2\nlet y:u64=x+1\nreturn y\n}\nreturn x\n}\n}\n";err_at(&image,"shadowed name under an operator",op_shadow,359,2,10,11);
 /* Negative, self reference: `t` is declared by the very let that reads it,
    and the use is inside that declaration. */
 const char*op_self="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet t:u64=t+1\nreturn 0\n}\n}\n";err_at(&image,"self reference under an operator",op_self,360,3,7,11);
 /* Negative, later declaration: the let that binds the name has not ended
    at the use. */
 const char*op_future="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet u:u64=t+1\nlet t:u64=1\nreturn u\n}\n}\n";err_at(&image,"later declaration under an operator",op_future,360,3,7,11);
 /* Negative, sibling block: the let is in a block that does not enclose the
    use. */
 const char*op_sibling="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nif true {\nlet t:u64=1\n}\nlet u:u64=t+1\nreturn u\n}\n}\n";err_at(&image,"sibling local under an operator",op_sibling,360,3,10,11);
 /* A name that IS in scope and has the wrong type is a proved mismatch and
    not an unproved name, so the answer moves 360 to 359 the moment the
    search resolves it. The oracle refuses this source too. */
 const char*op_wrong="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet t:u32=1\nlet u:u64=t+1\nreturn u\n}\n}\n";err_at(&image,"wrong type under an operator",op_wrong,359,2,8,11);
 bad(&image,"short",name_ok,3);bad(&image,"short bool expression",bool_mixed,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);
}
if(image.memory)nova_host_unmap(&image);
if(compiled)nt_artifact_free(&a);
for(unsigned i=0;i<11;i++)free(sources[i]);
/* The operand block needs the FULL 34 stage pipeline, not the stage subset
 * the image above runs, so it gets its own image built from the complete
 * module list. Compiled here, from the tree, on every run: the comparison is
 * only worth anything if the product side is the real product. */
/* THE CONTROL THIS LIST NEVER HAD.  pipe_paths is this gate's own compiler
 * input list, so it is a hand-maintained copy of an image the tree derives,
 * and until now nothing asked whether it still IS that image.  On 2026-10-02
 * machine_ir.nova became stage 35 of validate.nova and this list did not
 * carry it, so the compile failed with E302 and the gate reported
 * `checks=218 failures=2` -- a count measured on three assertions, because
 * the refusal cut the image off before the operand block could run at all.
 * The control is asked BEFORE the compile, so a list that is short is named
 * as a list, not as a product refusal two stages downstream. */
{char why[160];
 int closed=ng_parity_closure_is(pipe_paths[0],pipe_paths,(size_t)PIPE_N,why,sizeof why);
 CHECK(closed,closed?"the operand pipeline module list is the closure of its entry":why);
 fprintf(stderr,"%s the operand pipeline module list is the closure of %s: %s\n",
         closed?"CLOSE-OK":"CLOSE-NO",pipe_paths[0],closed?"yes":why);}
{static char*psrc[PIPE_N];NtFInput pin[PIPE_N];int pall=1;
 for(int k=0;k<PIPE_N;k++){size_t n=0;psrc[k]=loadf(pipe_paths[k],&n);
   if(!psrc[k])pall=0;else pin[k]=(NtFInput){pipe_paths[k],psrc[k],n};}
 CHECK(pall,"operand pipeline sources load");
 NtArtifact pa={0};
 int pcompiled=pall&&nova_compile_many_v2(pin,PIPE_N,&pa);
 CHECK(pcompiled,"operand pipeline compiles");
 if(!pcompiled)fprintf(stderr,"E%u %zu:%zu %s\n",pa.error.code,pa.error.line,pa.error.column,pa.error.message);
 NovaHostImage pimage={0};
 CHECK(pcompiled&&nova_host_map(&pa,&pimage),"operand pipeline maps");
 if(pimage.memory){operand_block(&pimage);
const char*const_param_shadow="module m\ntarget x86_64-nexora-none\nconst limit:u64=99\nsection .text {\nfn f(in limit:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmov rax,limit+1\nreturn 0\n}\n}\n";
const char*const_let_shadow="module m\ntarget x86_64-nexora-none\nconst limit:u64=99\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nlet limit:u64=1\nmov rax,limit+1\nreturn 0\n}\n}\n";
agree_operand(&pimage,"module constant shadowed by runtime parameter",const_param_shadow,0,400);
agree_operand(&pimage,"module constant shadowed by runtime local",const_let_shadow,0,400);
 }

 if(pimage.memory)nova_host_unmap(&pimage);
 if(pcompiled)nt_artifact_free(&pa);
 for(int k=0;k<PIPE_N;k++)free(psrc[k]);}
/* The parity image the helper built is released here, after the operand block
 * has run its own pipeline image through the same run() and been compared by
 * the same call, and before main returns. */
ng_parity_finish(&ng_parity,&failures);
printf("NTASM_NOVA_INITIALIZER_TYPES checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
